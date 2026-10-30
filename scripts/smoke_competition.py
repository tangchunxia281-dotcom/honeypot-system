"""Actual isolated loopback launch, login, request capture and no-model investigation."""
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urljoin
import requests
ROOT=Path(__file__).resolve().parents[1]

def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]

def main():
    with tempfile.TemporaryDirectory() as tmp:
        folder=Path(tmp);web,dash,ssh=port(),port(),port();password=secrets.token_urlsafe(20)
        env=dict(os.environ,PYTHONUTF8='1',WEB_PORT=str(web),DASHBOARD_PORT=str(dash),SSH_PORT=str(ssh),WEB_HOST='127.0.0.1',DASHBOARD_HOST='127.0.0.1',SSH_HOST='127.0.0.1',ADMIN_PASS=password,PRODUCTION_MODE='false',SECRET_KEY=secrets.token_urlsafe(32),DB_TYPE='sqlite',DB_PATH=str(folder/'events.sqlite'),HONEYPOT_AI_DB=str(folder/'ai.sqlite'),HONEYPOT_LOCAL_INDEX=str(folder/'index.sqlite'),HONEYPOT_AI_ENABLED='false',HONEYPOT_AI_ANALYSIS_ENABLED='false',HONEYPOT_AI_WEB_INTERACTION_ENABLED='true',HONEYPOT_STOP_FILE=str(folder/'stop'),SHOW_SUMMARY_CREDS='false')
        log=(folder/'services.log').open('w',encoding='utf-8');proc=subprocess.Popen([sys.executable,'-X','utf8','main.py'],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
        base=f'http://127.0.0.1:{dash}';c=requests.Session();c.trust_env=False
        try:
            deadline=time.monotonic()+35
            while True:
                try:
                    response=c.get(base+'/super/login',timeout=1)
                    if response.status_code==200:break
                except requests.RequestException:pass
                if proc.poll() is not None or time.monotonic()>deadline:raise RuntimeError('startup_failed')
                time.sleep(.5)
            token=re.search(r'name="csrf_token"[^>]*value="([^"]+)"',response.text).group(1)
            response=c.post(base+'/super/login',data={'username':'admin','password':password,'csrf_token':token},headers={'Origin':base},timeout=5)
            assert '/super/login' not in response.url,'login_failed'
            pages=['/workspace/overview','/workspace/events','/workspace/sessions','/workspace/investigate','/workspace/settings','/workspace/sessions?tab=graph','/workspace/sessions?tab=replay','/workspace/settings?tab=effects','/workspace/settings?tab=calls','/dashboard','/ai/analysis','/ai/workbench','/ai/local','/ai/detection','/ai/interactions','/ai']
            for path in pages:
                r=c.get(base+path,timeout=5);assert r.status_code==200,(path,r.status_code)
                for asset in re.findall(r'(?:src|href)="(/static/[^\"]+)"',r.text):
                    a=c.get(urljoin(base,asset.replace('&amp;','&')),timeout=5);assert a.status_code==200,(asset,a.status_code)
            canonical=c.get(base+'/ai/investigations',timeout=5)
            assert '/workspace/investigate' in canonical.url,'legacy_route_still_opens_second_case_system'
            archive=c.get(base+'/ai/legacy-investigations',timeout=5)
            assert archive.status_code==200 and '历史报告档案' in archive.text,'legacy_data_archive_not_preserved'
            page=c.get(base+'/ai/local',timeout=5).text;token=re.search(r'name="csrf-token" content="([^"]+)"',page).group(1)
            headers={'Origin':base,'X-CSRF-Token':token}
            w=f'http://127.0.0.1:{web}'
            for path in ['/search?q=normal','/search?q=%3Cscript%3Ealert(1)%3C/script%3E','/products?id=1%20UNION%20SELECT%201,2']:
                c.get(w+path,timeout=5)
            r=c.post(base+'/api/local/sync',json={},headers=headers,timeout=5);assert not r.json()['error'],r.text
            rows=c.get(base+'/api/local/evidence',headers=headers,timeout=5).json();assert rows['total']>=3,rows
            story=c.get(base+'/api/local/story',headers=headers,timeout=5).json();assert story['facts'] and not story['inferences']
            r=c.post(base+'/api/local/jobs',json={'question':'根据这些记录解释可疑请求','query':{'ip':'127.0.0.1'},'request_id':secrets.token_hex(16)},headers=headers,timeout=5);assert r.status_code==202,r.text
            identifier=r.json()['id'];deadline=time.monotonic()+15
            while True:
                j=c.get(base+'/api/local/jobs/'+identifier,headers=headers,timeout=5).json()
                if j['status'] not in ('queued','running'):break
                assert time.monotonic()<deadline,'job_did_not_finish';time.sleep(.5)
            assert j['status']=='fallback' and j['result']['story']['facts'],j
            events=c.get(base+'/api/workspace/events?ip=127.0.0.1',headers=headers,timeout=5).json()
            event_id=events['records'][0]['id']
            detail=c.get(base+'/api/workspace/events/'+event_id,headers=headers,timeout=5).json()
            assert detail['id']==event_id and 'rule' in detail,detail
            r=c.post(base+'/api/workspace/events/'+event_id+'/review',json={'revision':0,'label':'attack','note':'合成验收记录'},headers=headers,timeout=5)
            assert r.status_code==200 and r.json()['revision']==1,r.text
            r=c.post(base+'/api/workspace/cases',json={'title':'隔离环境验收调查','evidence_id':event_id},headers=headers,timeout=5)
            assert r.status_code==201,r.text
            case=r.json();assert any(row['id']==event_id for row in case['evidence']),case
            r=c.post(base+'/api/workspace/cases/'+case['id']+'/ask',json={'question':'解释这些请求并列出证据不足的地方','request_id':secrets.token_hex(16)},headers=headers,timeout=5)
            assert r.status_code==202,r.text
            identifier=r.json()['id'];deadline=time.monotonic()+15
            while True:
                j=c.get(base+'/api/local/jobs/'+identifier,headers=headers,timeout=5).json()
                if j['status'] not in ('queued','running'):break
                assert time.monotonic()<deadline,'case_job_did_not_finish';time.sleep(.5)
            assert j['status']=='fallback',j
            exported=c.get(base+'/api/workspace/cases/'+case['id']+'/export',headers=headers,timeout=5).json()
            assert exported['jobs'][0]['id']==identifier and exported['query']==case['query'],exported
            r=c.post(base+'/api/workspace/cases/'+case['id'],json={'revision':0,'status':'closed','note':'已检查备用流程'},headers=headers,timeout=5)
            assert r.status_code==200 and r.json()['status']=='closed',r.text
            assert c.post(base+'/api/workspace/cases/'+case['id']+'/ask',json={'question':'关闭后不可直接提问'},headers=headers,timeout=5).status_code==400
            environment=c.get(base+'/api/setup/environment',headers=headers,timeout=8)
            assert environment.status_code==200 and 'hardware' in environment.json(),environment.text
            for endpoint in ['/api/users','/api/sensors','/api/ingest','/api/team/graph']:
                assert c.get(base+endpoint,headers=headers,timeout=5).status_code==404,endpoint
            print(json.dumps({'startup':'passed','pages_and_assets':len(pages),'captured':rows['total'],'no_model_timeline':'passed','no_model_job':j['status'],'case_create_ask_review_export':'passed','setup_environment':'passed','team_routes':'absent'},ensure_ascii=False))
        finally:
            (folder/'stop').touch()
            try:proc.wait(timeout=15)
            except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=5)
            log.close()
            if proc.returncode!=0:print((folder/'services.log').read_text(encoding='utf-8',errors='replace')[-4000:])
        assert proc.returncode==0,proc.returncode

if __name__=='__main__':main()
