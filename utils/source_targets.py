"""Analyst-owned source labels. A label never changes firewall policy."""
import ipaddress
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from investigation_core.store import clean

class Targets:
    def __init__(self,path):
        self.path=Path(path);self.path.parent.mkdir(parents=True,exist_ok=True)
        with closing(self.connect()) as c,c:
            c.execute('CREATE TABLE IF NOT EXISTS source_targets(ip TEXT PRIMARY KEY,level TEXT,status TEXT,note TEXT,tags TEXT,revision INTEGER,updated REAL)')
    def connect(self):
        c=sqlite3.connect(self.path,timeout=2);c.row_factory=sqlite3.Row;return c
    def listing(self,term=''):
        with closing(self.connect()) as c:
            rows=c.execute('SELECT * FROM source_targets ORDER BY updated DESC LIMIT 200').fetchall()
        result=[]
        for r in rows:
            row=dict(r);row['tags']=json.loads(row['tags'])
            if not term or term.casefold() in json.dumps(row,ensure_ascii=False).casefold():result.append(row)
        return result
    def save(self,data):
        if not isinstance(data,dict) or set(data)-{'ip','level','status','note','tags','revision'}:raise ValueError('unknown_fields')
        ip=str(ipaddress.ip_address(data.get('ip','')))
        level=data.get('level','medium');status=data.get('status','watching');tags=data.get('tags',[])
        if level not in ('low','medium','high','critical') or status not in ('watching','reviewing','handled'):raise ValueError('target_value_invalid')
        if not isinstance(tags,list) or len(tags)>12 or any(not isinstance(t,str)for t in tags):raise ValueError('tags_invalid')
        note=clean(data.get('note',''),2000);tags=list(dict.fromkeys(clean(t,30)for t in tags))
        if type(data.get('revision'))is not int:raise ValueError('revision_required')
        with closing(self.connect()) as c,c:
            c.execute('BEGIN IMMEDIATE');old=c.execute('SELECT revision FROM source_targets WHERE ip=?',(ip,)).fetchone()
            revision=old[0] if old else 0
            if revision!=data['revision']:raise ValueError('revision_conflict')
            c.execute('INSERT OR REPLACE INTO source_targets VALUES(?,?,?,?,?,?,?)',(ip,level,status,note,json.dumps(tags,ensure_ascii=False),revision+1,time.time()))
        return next(r for r in self.listing(ip)if r['ip']==ip)
    def delete(self,ip,revision):
        ip=str(ipaddress.ip_address(ip))
        with closing(self.connect()) as c,c:
            changed=c.execute('DELETE FROM source_targets WHERE ip=? AND revision=?',(ip,revision)).rowcount
            if not changed:raise ValueError('revision_conflict')

