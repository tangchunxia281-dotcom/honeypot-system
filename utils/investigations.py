"""Shared, versioned investigation notebook; source evidence and AI views stay separate."""
import ipaddress
import json
import secrets
import time
from contextlib import closing
from utils.ai_store import ensure_schema

STATES={'open','investigating','resolved'}
RISKS={'unknown','low','medium','high','critical'}


class Conflict(ValueError):
    pass


class InvestigationStore:
    def __init__(self,analyst):
        self.analyst=analyst

    def connect(self):
        c=self.analyst.connect()
        try:
            ensure_schema(c,self.analyst.path,'investigations-v1',self._schema)
            return c
        except Exception:c.close();raise

    @staticmethod
    def _schema(c):
        c.executescript('''
          CREATE TABLE IF NOT EXISTS investigations(id TEXT PRIMARY KEY,title TEXT,src_ip TEXT,
            state TEXT,human_risk TEXT,revision INTEGER,created_at REAL,updated_at REAL);
          CREATE INDEX IF NOT EXISTS investigations_list ON investigations(updated_at DESC,id);
          CREATE TABLE IF NOT EXISTS investigation_reports(case_id TEXT,report_id TEXT,snapshot TEXT,
            created_at REAL,PRIMARY KEY(case_id,report_id));
          CREATE TABLE IF NOT EXISTS investigation_audit(id INTEGER PRIMARY KEY,case_id TEXT,
            actor TEXT,action TEXT,note TEXT,created_at REAL,revision INTEGER);
          CREATE INDEX IF NOT EXISTS investigation_audit_case ON investigation_audit(case_id,id);
        ''')

    @staticmethod
    def clean(text,limit):
        from utils.ai_analyst import _clean
        if not isinstance(text,str) or len(text)>limit:raise ValueError('文字长度或类型无效')
        return _clean(text,limit).strip()

    @staticmethod
    def ip(value):
        if not isinstance(value,str):raise ValueError('来源地址无效')
        return str(ipaddress.ip_address(value)) if value else ''

    def _report(self,identifier):
        row=self.analyst.get(identifier)
        if not row or row['task']!='report' or row['status']!='completed':raise ValueError('请选择已完成的 AI 报告')
        return {'id':row['id'],'result':row['result'],'records':row['context'].get('records',[])[:24],'call_id':row['call_id'],'captured_at':time.time()}

    def _audit(self,c,identifier,actor,action,note,revision):
        c.execute('INSERT INTO investigation_audit(case_id,actor,action,note,created_at,revision) VALUES(?,?,?,?,?,?)',
                  (identifier,actor,action,note,time.time(),revision))
        # Metadata only; evidence and reviewer notes remain in the protected DB.

    def create(self,title,src_ip,actor,report_id=''):
        title=self.clean(title,80);src_ip=self.ip(src_ip)
        if not title:raise ValueError('请填写调查标题')
        snapshot=self._report(report_id) if report_id else None
        identifier=secrets.token_hex(12);now=time.time()
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE')
            if c.execute('SELECT COUNT(*) FROM investigations').fetchone()[0]>=2000:raise ValueError('调查数量已达到 2000，请导出并整理')
            if c.execute('SELECT COUNT(*) FROM investigations WHERE created_at>?',(now-3600,)).fetchone()[0]>=100:raise ValueError('本小时调查创建额度已满')
            c.execute('INSERT INTO investigations VALUES(?,?,?,?,?,?,?,?)',(identifier,title,src_ip,'open','unknown',1,now,now))
            if snapshot:c.execute('INSERT INTO investigation_reports VALUES(?,?,?,?)',(identifier,report_id,json.dumps(snapshot,ensure_ascii=False),now))
            self._audit(c,identifier,actor,'created','创建调查；来源关联不等同身份确认。',1)
        self._log(identifier,'created',1)
        return self.get(identifier)

    def get(self,identifier):
        with closing(self.connect()) as c:
            row=c.execute('SELECT * FROM investigations WHERE id=?',(identifier,)).fetchone()
            if not row:return None
            out=dict(row)
            out['reports']=[json.loads(r[0]) for r in c.execute('SELECT snapshot FROM investigation_reports WHERE case_id=? ORDER BY created_at,report_id',(identifier,))]
            out['audit']=[dict(r) for r in c.execute('SELECT * FROM investigation_audit WHERE case_id=? ORDER BY id DESC LIMIT 100',(identifier,))]
        return out

    def listing(self,state='',src_ip='',limit=30,before=None,term=''):
        if state and state not in STATES:raise ValueError('调查状态无效')
        src_ip=self.ip(src_ip);where=[];args=[]
        if state:where.append('state=?');args.append(state)
        if src_ip:where.append('src_ip=?');args.append(src_ip)
        term=self.clean(term,80)
        if term:where.append("title LIKE ? ESCAPE '\\'");args.append('%'+term.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%')
        total_where=list(where);total_args=list(args)
        if before:where.append('(updated_at<? OR (updated_at=? AND id<?))');args.extend((before[0],before[0],before[1]))
        limit=min(100,max(1,limit))
        with closing(self.connect()) as c:
            rows=[dict(r) for r in c.execute('SELECT *, (SELECT COUNT(*) FROM investigation_reports r WHERE r.case_id=investigations.id) AS report_count FROM investigations'+(' WHERE '+' AND '.join(where) if where else '')+' ORDER BY updated_at DESC,id DESC LIMIT ?',(*args,limit+1))]
            total=c.execute('SELECT COUNT(*) FROM investigations'+(' WHERE '+' AND '.join(total_where) if total_where else ''),total_args).fetchone()[0]
        more=len(rows)>limit;rows=rows[:limit]
        return {'items':rows,'total':total,'limit':limit,'next_before':str(rows[-1]['updated_at'])+':'+rows[-1]['id'] if more else ''}

    def update(self,identifier,revision,actor,state='',risk='',note='',report_id=''):
        if type(revision) is not int or revision<1:raise ValueError('调查版本无效')
        if state and state not in STATES or risk and risk not in RISKS:raise ValueError('状态或风险无效')
        note=self.clean(note,1000);snapshot=self._report(report_id) if report_id else None
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE')
            row=c.execute('SELECT * FROM investigations WHERE id=?',(identifier,)).fetchone()
            if not row:raise ValueError('调查不存在')
            if row['revision']!=revision:raise Conflict('其他操作已更新这份调查，请刷新后再提交')
            if c.execute('SELECT COUNT(*) FROM investigation_audit WHERE case_id=?',(identifier,)).fetchone()[0]>=2000:raise ValueError('此调查历史已达到 2000 条，请导出后建立新调查')
            if snapshot:
                if c.execute('SELECT 1 FROM investigation_reports WHERE case_id=? AND report_id=?',(identifier,report_id)).fetchone():return self.get(identifier)
                if c.execute('SELECT COUNT(*) FROM investigation_reports WHERE case_id=?',(identifier,)).fetchone()[0]>=10:raise ValueError('单份调查最多关联 10 份报告')
                c.execute('INSERT INTO investigation_reports VALUES(?,?,?,?)',(identifier,report_id,json.dumps(snapshot,ensure_ascii=False),time.time()))
            if not (state or risk or note or snapshot):raise ValueError('没有填写变更内容')
            revision+=1;c.execute('UPDATE investigations SET state=?,human_risk=?,revision=?,updated_at=? WHERE id=?',(state or row['state'],risk or row['human_risk'],revision,time.time(),identifier))
            action='report_added' if snapshot else 'updated'
            self._audit(c,identifier,actor,action,note or ('添加报告 '+report_id if snapshot else '状态／人工风险更新'),revision)
        self._log(identifier,action,revision)
        return self.get(identifier)

    @staticmethod
    def _log(identifier,action,revision):
        try:
            from utils.logger import get_logger
            get_logger('investigation').info('[调查审计] case=%s action=%s revision=%s',identifier,action,revision)
        except Exception:
            # The committed database audit remains authoritative; a console or
            # file logger outage must not turn a committed edit into HTTP 503.
            import logging
            logging.getLogger(__name__).warning('Investigation audit file unavailable; committed revision=%s',revision)

    def context(self,identifier):
        case=self.get(identifier)
        if not case:raise ValueError('调查不存在')
        records={}
        for report in case['reports']:
            for r in report['records']:records.setdefault(r['id'],r)
        if not records and case['src_ip']:
            records={r['id']:r for r in self.analyst.search(case['src_ip'],'',24)['records']}
        # Keep the maximum model-facing context bounded and choose high-signal
        # distinct entries before oldest normal requests can crowd them out.
        rows=sorted(records.values(),key=lambda r:(r['rule_level'] not in ('critical','high','medium'),r['timestamp']))
        unique=[];seen=set()
        for r in rows:
            signature=(r['channel'],r['kind'],r['excerpt'])
            if signature not in seen:seen.add(signature);unique.append(r)
        chosen=unique[:24]
        return {'records':chosen,'selected':len(chosen),'total_matching':len(records),'mode':'logs','case_id':identifier,
                'scope':'调查证据快照，最多24条输入、6条模型代表样本；人工笔记不是攻击证据。'}

    def profile(self,src_ip):
        src_ip=self.ip(src_ip)
        if not src_ip:raise ValueError('请填写来源 IP')
        with closing(self.analyst.connect()) as c:
            aggregate=dict(c.execute('SELECT COUNT(*) AS indexed_records,MIN(timestamp) AS first_seen,MAX(timestamp) AS last_seen,COUNT(DISTINCT NULLIF(session_id,\'\')) AS observed_sessions FROM analyst_evidence WHERE src_ip=?',(src_ip,)).fetchone())
            rows=[dict(r) for r in c.execute('SELECT * FROM analyst_evidence WHERE src_ip=? ORDER BY timestamp DESC,id DESC LIMIT 500',(src_ip,))]
        channels={};rules={};kinds={}
        for row in rows:
            for mapping,key in ((channels,'channel'),(rules,'rule_level'),(kinds,'kind')):mapping[row[key]]=mapping.get(row[key],0)+1
        reports=self.analyst.related_reports([r['id'] for r in rows])
        return dict(aggregate,src_ip=src_ip,sampled_records=len(rows),channels=channels,rule_levels=rules,kinds=kinds,
                    reports=reports[:20],records=rows[:20],scope='统计针对当前索引；类别统计最多最近500条，不包含未索引或已归档证据。同IP不等于同一人。')

    def export(self,identifier):
        row=self.get(identifier)
        if not row:raise ValueError('调查不存在')
        from utils.markdown_export import literal
        clean=literal
        lines=['# '+clean(row['title']),'','调查编号：'+identifier,'状态：'+row['state'],'人工风险：'+row['human_risk'],'版本：'+str(row['revision']),
               '','来源关联不等于身份确认；AI 结论、原规则和人工意见独立保留。','']
        for report in row['reports']:
            lines+=['## AI 报告 '+report['id'],clean(report['result'].get('title','')),clean(report['result'].get('summary','')),'AI风险：'+clean(report['result'].get('risk','unknown')),'']
            for r in report['records']:lines+=['原记录：'+clean(r['locator']),clean(r['timestamp'])+' · '+clean(r['src_ip']),'> '+clean(r['excerpt']).replace('\n','\n> '),'']
        lines+=['## 操作历史','']
        with closing(self.connect()) as c:
            audit=c.execute('SELECT * FROM investigation_audit WHERE case_id=? ORDER BY id LIMIT 2000',(identifier,)).fetchall()
        for entry in audit:lines+=[f"- 版本 {entry['revision']} · {entry['action']} · {clean(entry['note'])}"]
        return '\n'.join(lines)
