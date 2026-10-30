"""Isolated actual supervisor + six protocols + classified evidence + case export.

The classifier is an explicitly labelled transport fixture, not a trained model.
--hold keeps this synthetic instance available for browser verification.
"""
import argparse
import configparser
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import requests
from protocol_demo import exercise
ROOT=Path(__file__).resolve().parents[1]

def port():
    with socket.socket()as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
class Fixture(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def do_POST(self):
        data=json.loads(self.rfile.read(int(self.headers.get('Content-Length',0))));attack='UNION'in str(data).upper()
        out=json.dumps(dict(attack_type='sqli'if attack else 'normal',is_attack=attack,attack_prob=.9,ai_points=20,model_label='transport-fixture-not-trained-model')).encode()
        self.send_response(200);self.send_header('Content-Length',str(len(out)));self.end_headers();self.wfile.write(out)

def main(folder,hold):
    folder.mkdir(parents=True,exist_ok=True);ports={x:port()for x in ('web','dashboard','ssh','mysql','redis','ftp','telnet')};password=secrets.token_urlsafe(22)
    config=configparser.ConfigParser(interpolation=None);config.read(ROOT/'honeypot.ini.example',encoding='utf-8-sig')
    for name,value in ports.items():
        section='services.'+name
        if not config.has_section(section):config.add_section(section)
        config[section]['host']='127.0.0.1';config[section]['port']=str(value)
    config['app']['production_mode']='false';config['admin']['password']=password
    ini=folder/'honeypot.ini'
    with ini.open('w',encoding='utf-8')as f:config.write(f)
    ai=folder/'ai.ini';ai.write_text('[ai]\nenabled=false\nmodel=\nprovider=local\n',encoding='utf-8')
    classifier=ThreadingHTTPServer(('127.0.0.1',0),Fixture);threading.Thread(target=classifier.serve_forever,daemon=True).start()
    classify=folder/'classifier.ini';classify.write_text('[classifier]\nenabled=true\nurl=http://127.0.0.1:'+str(classifier.server_port)+'/api/v1/detect\ntimeout=1\n',encoding='utf-8')
    stop=folder/'STOP'
    if stop.exists():stop.unlink()
    env=dict(os.environ,PYTHONUTF8='1',HONEYPOT_CONFIG=str(ini),DB_TYPE='sqlite',DB_PATH=str(folder/'events.db'),HONEYPOT_AI_CONFIG=str(ai),HONEYPOT_AI_DB=str(folder/'ai.db'),HONEYPOT_LOCAL_INDEX=str(folder/'index.db'),HONEYPOT_CLASSIFIER_CONFIG=str(classify),HONEYPOT_CLASSIFIER_DB=str(folder/'classifier.db'),HONEYPOT_STOP_FILE=str(stop),ADMIN_PASS=password,SECRET_KEY=secrets.token_urlsafe(36),PRODUCTION_MODE='false',SHOW_SUMMARY_CREDS='false',ALERT_ENABLED='false')
    log=(folder/'services.log').open('w',encoding='utf-8');proc=subprocess.Popen([sys.executable,'-X','utf8','main.py'],cwd=ROOT,env=env,stdout=log,stderr=subprocess.STDOUT)
    try:
        c=requests.Session();c.trust_env=False;base='http://127.0.0.1:'+str(ports['dashboard']);deadline=time.monotonic()+35
        while True:
            try:
                r=c.get(base+'/super/login',timeout=1)
                if r.status_code==200:break
            except requests.RequestException:pass
            if proc.poll()is not None or time.monotonic()>deadline:raise RuntimeError('startup_failed')
            time.sleep(.4)
        token=re.search(r'name="csrf_token"[^>]*value="([^"]+)"',r.text).group(1)
        r=c.post(base+'/super/login',data={'username':'admin','password':password,'csrf_token':token},headers={'Origin':base},timeout=5)
        assert '/super/login'not in r.url
        page=c.get(base+'/workspace/overview',timeout=5)
        token=re.search(r'name="csrf-token" content="([^"]+)"',page.text).group(1);h={'X-CSRF-Token':token,'Origin':base}
        c.headers['Origin']=base
        protocols=exercise(ports)
        w='http://127.0.0.1:'+str(ports['web'])
        c.get(w+'/products?id=1%20UNION%20SELECT%201,2&demo_run=integration24',timeout=4)
        c.get(w+'/search?q=normal&demo_run=integration24',timeout=4)
        for _ in range(10):
            synced=c.post(base+'/api/local/sync',json={},headers=h,timeout=5)
            assert synced.status_code==200,synced.text
            response=c.get(base+'/api/workspace/events',timeout=5)
            assert response.status_code==200,response.text
            rows=response.json()['records']
            channels={r['channel']for r in rows}
            if set(ports)-{'dashboard'}<=channels:break
            time.sleep(.5)
        assert {'web','ssh','mysql','redis','ftp','telnet'}<=channels,channels
        row=next(r for r in rows if r['table']=='raw_request'and 'UNION'in r['excerpt'])
        for _ in range(20):
            detail=c.get(base+'/api/workspace/events/'+row['id'],timeout=5).json()
            if (detail.get('classification')or{}).get('status')=='completed':break
            time.sleep(.2)
        assert detail['classification']['result']['attack_type']=='sqli',detail
        filtered=c.get(base+'/api/workspace/events?channel=mysql',timeout=5).json();assert filtered['records']and all(r['channel']=='mysql'for r in filtered['records'])
        case=c.post(base+'/api/workspace/cases',json={'title':'六协议实际连接验收','query':{'ip':'127.0.0.1'}},headers=h,timeout=5).json()
        export=c.get(base+'/api/workspace/cases/'+case['id']+'/export',timeout=5).json()
        assert {'mysql','redis','ftp','telnet'}<={r['channel']for r in export['evidence']}
        target=c.post(base+'/api/integrations/targets',json=dict(ip='127.0.0.1',level='medium',status='reviewing',note='本机合成验收，非真实攻击身份。',tags=['合成验收'],revision=0),headers=h,timeout=5)
        assert target.status_code==200,target.text
        assert c.get(base+'/api/integrations/cloud',timeout=4).status_code==200
        report={'ports':ports,'protocols':protocols,'channels':sorted(channels),'classified_evidence':'passed with explicit fake transport','case_export':'passed','source_target':'passed','ui_base':base,'case_id':case['id'],'classifier_model':'transport-fixture-not-trained-model'}
        (folder/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
        (folder/'connection.json').write_text(json.dumps({'base':base,'password':password}),encoding='utf-8')
        print(json.dumps(report,ensure_ascii=False,indent=2),flush=True)
        if hold:
            print('Synthetic browser instance ready; create STOP to finish.',flush=True)
            while not stop.exists()and proc.poll()is None:time.sleep(.5)
    finally:
        stop.touch()
        try:proc.wait(timeout=18)
        except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=5)
        log.close();classifier.shutdown();classifier.server_close()
        if proc.returncode:print((folder/'services.log').read_text(encoding='utf-8',errors='replace')[-5000:])
    assert proc.returncode==0,proc.returncode
    for value in ports.values():
        with socket.socket()as s:s.settimeout(.2);assert s.connect_ex(('127.0.0.1',value))!=0,('port_leaked',value)
    print('All seven service ports released.',flush=True)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',required=True);p.add_argument('--hold',action='store_true');a=p.parse_args();main(Path(a.output).resolve(),a.hold)
