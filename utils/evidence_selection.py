"""Deterministic retrieval hints and diversity, never an AI verdict."""
import hashlib
import html
import re
from urllib.parse import unquote

PATTERNS={
 'xss':r'<\s*(?:script|svg|img|iframe)\b|on(?:error|load|click)\s*=|javascript:',
 'sqli':r'\bunion\s+(?:all\s+)?select\b|\bor\s+[\'\"]?1[\'\"]?\s*=|sleep\s*\(|information_schema',
 'path_traversal':r'\.\.[/\\]|/etc/(?:passwd|shadow)|win\.ini',
 'command_injection':r'(?:;|\||&&|\$\().{0,40}(?:whoami|cat|curl|wget|id\b)|cmd=',
 'ssrf':r'169\.254\.169\.254|https?://(?:127\.|localhost|10\.|192\.168\.)|file://',
 'ssti':r'\{\{.{0,80}\}\}|\$\{.{0,80}\}',
 'xxe':r'<!DOCTYPE|<!ENTITY|\bSYSTEM\s+[\'\"]',
 'scanner':r'sqlmap|nikto|gobuster|/\.env|/\.git|/actuator|/admin',
}
COMPILED={k:re.compile(v,re.I) for k,v in PATTERNS.items()}
LABELS={'xss':'浏览器脚本输入','sqli':'数据库输入','path_traversal':'文件访问输入','command_injection':'命令输入','ssrf':'远程资源输入','ssti':'模板输入','xxe':'XML实体输入','scanner':'入口探测','ssh':'SSH行为','normal':'未见明确特征'}


def hints(record):
    text=html.unescape(unquote(str(record.get('excerpt',''))))
    found=[k for k,p in COMPILED.items() if p.search(text)]
    if record.get('channel')=='ssh':found.append('ssh')
    return found or ['normal']


def clip(text,limit=1000):
    """Preserve rare tail features instead of losing everything after the head."""
    text=str(text)
    if len(text)<=limit:return text
    regions=[(0,180),(max(0,len(text)-160),len(text))]
    for pattern in COMPILED.values():
        match=pattern.search(text)
        if match:regions.append((max(0,match.start()-55),min(len(text),match.end()+75)))
    merged=[]
    for a,b in sorted(regions):
        if merged and a<=merged[-1][1]:merged[-1]=(merged[-1][0],max(b,merged[-1][1]))
        else:merged.append((a,b))
    # Feature windows get priority over a long normal prefix. Every retained
    # region is literal sanitized text; omitted ranges are explicitly marked.
    if sum(b-a for a,b in merged)>limit-100:
        middle=[text[a:b] for a,b in merged if a>0 and b<len(text)]
        return (text[:100]+'\n[中间省略]\n'+'\n[中间省略]\n'.join(middle)+ '\n[中间省略]\n'+text[-100:])[:limit]
    return '\n[中间省略]\n'.join(text[a:b] for a,b in merged)[:limit]


def signature(r):
    return re.sub(r'(?:demo_run|nonce|timestamp)=[^\s&]*','',r.get('excerpt','')).strip().lower()


def select(records,limit=6,question=''):
    categories={r['id']:hints(r) for r in records};terms=set(re.findall(r'[a-z][a-z_]{2,}|[\u4e00-\u9fff]{2,}',question.lower()))
    wanted=set()
    for kind,aliases in {'xss':['xss','脚本'],'sqli':['sql','数据库'],'path_traversal':['文件','路径'],'ssrf':['ssrf','内网'],'ssh':['ssh','登录'],'xxe':['xxe','xml'],'ssti':['ssti','模板'],'command_injection':['命令']}.items():
        if any(a in question.lower() for a in aliases):wanted.add(kind)
    unique=[];seen=set()
    for r in records:
        s=signature(r)
        if s not in seen:unique.append(r);seen.add(s)
    selected=[];covered=set()
    while unique and len(selected)<limit:
        def rank(r):
            cats=set(categories[r['id']]);novel=cats-covered-{'normal'}
            matches=sum(t in r['excerpt'].lower() for t in terms)
            return (len(cats&wanted)*15+len(novel)*8+(4 if r.get('rule_level') in ('critical','high') else 2 if r.get('rule_level')=='medium' else 0)+min(matches,5),r.get('timestamp',''),r['id'])
        chosen=max(unique,key=rank);unique.remove(chosen);selected.append(chosen);covered.update(categories[chosen['id']])
    all_types=set().union(*(set(v) for v in categories.values())) if records else set()
    return {'records':sorted(selected,key=lambda r:(r.get('timestamp',''),r['id'])),'matched':len(records),'selected':len(selected),
            'distinct':len(seen),'covered_hints':sorted(covered),'omitted_hints':sorted(all_types-covered),'method':'关键词、规则等级与类型多样性；类型仅为程序线索'}


def partitions(records,limit=6):
    # Every distinct behavior gets a bounded model batch; duplicates remain in
    # the corresponding snapshot and are marked as represented, not reread.
    remaining=list(records);parts=[]
    while remaining:
        choice=select(remaining,limit);keys={signature(r) for r in choice['records']}
        subset=[r for r in remaining if signature(r) in keys];parts.append(subset);remaining=[r for r in remaining if signature(r) not in keys]
    return parts


def graph(records,reports=None):
    ordered=sorted(records,key=lambda r:(r['timestamp'],r['id']))[:80];nodes=[];edges=[]
    for r in ordered:nodes.append({**r,'hints':hints(r),'label':' / '.join(LABELS.get(k,k) for k in hints(r)),
                                  'report_ids':[p['id'] for p in reports or [] if r['id'] in p.get('record_ids',[])]})
    from datetime import datetime
    for i,node in enumerate(nodes):
        for prev in reversed(nodes[:i]):
            same_session=bool(node['session_id'] and node['session_id']==prev['session_id'] and node['src_ip']==prev['src_ip'])
            same_source=node['src_ip']==prev['src_ip']
            try:gap=(datetime.fromisoformat(node['timestamp'])-datetime.fromisoformat(prev['timestamp'])).total_seconds()
            except ValueError:continue
            if (same_session or same_source and 0<=gap<=900):
                edges.append({'from':prev['id'],'to':node['id'],'type':'same_session' if same_session else 'same_source_window',
                    'ordered':gap>0,'reason':'同会话ID与来源' if same_session else '同来源且相差不超过15分钟；不是身份或攻击成功证明'})
                break
    return {'nodes':nodes,'edges':edges,'provided':len(records),'shown':len(nodes),'scope':'程序构建关联线索；同时刻不认定先后，同来源不确认身份。'}
