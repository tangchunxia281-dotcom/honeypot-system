"""Bounded loopback-only honeypot demonstration; synthetic HTTP + virtual SSH.

Run from the project root: python scripts/mixed_attack_demo.py --ssh
No subnet scans, exploit execution, credential guessing lists or external targets.
"""
import argparse
import base64
import getpass
import hashlib
import json
import re
import secrets
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit,urlencode,quote

import requests

HOST='127.0.0.1'
ANSI=re.compile(r'\x1b\][\s\S]*?(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]|[\x00-\x08\x0b-\x1f\x7f]')


def scenarios(run_id,quick=False):
    marker={'demo_run':run_id}
    cases=[
        ('正常访问','正常搜索对照','GET','/search',{'q':'python tutorial',**marker},None,'normal'),
        ('入口探测','管理入口','GET','/admin',marker,None,'recon'),
        ('入口探测','扫描工具特征','GET','/admin',marker,None,'scanner'),
        ('输入探测','XSS 脚本输入','GET','/search',{'q':'<script>alert("honeypot-demo")</script>',**marker},None,'xss'),
        ('输入探测','SQL 联合查询输入','GET','/products',{'id':'1 UNION SELECT username,password FROM users',**marker},None,'sqli'),
        ('输入探测','路径遍历输入','GET','/download',{'file':'../../etc/passwd',**marker},None,'path_traversal'),
    ]
    if not quick:
        cases.extend([
            ('正常访问','安全讨论关键词对照','GET','/search',{'q':'为什么 script 标签需要转义，如何选择 SQL 教程',**marker},None,'normal'),
            ('输入探测','命令拼接输入','GET','/tools',{'cmd':'whoami;cat /etc/passwd',**marker},None,'command_injection'),
            ('输入探测','模板表达式输入','GET','/search',{'name':'{{7*7}}',**marker},None,'ssti'),
            ('输入探测','XML 外部实体声明','POST','/api/preview',marker,
             '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>','xxe'),
            ('输入探测','内网目标预览输入','GET','/api/preview',{'url':'http://169.254.169.254/latest/meta-data/',**marker},None,'ssrf'),
        ])
    cases.append(('受控交互','外部示例目标的模拟预览','GET','/api/preview',{'url':'https://example.test/demo',**marker},None,'preview'))
    return cases


def trusted_poll_path(value):
    if not isinstance(value,str):return None
    # An attacker-facing reply may not redirect this driver to an external URL.
    if re.fullmatch(r'/api/preview/jobs/[0-9a-f]{24}',value):return value
    return None


class Demo:
    def __init__(self,web_port=5000,ssh_port=2222,gap=4,timeout=35,run_id=None):
        self.web_port=web_port;self.ssh_port=ssh_port;self.gap=gap;self.timeout=timeout
        self.run_id=run_id or 'hp_demo_'+datetime.now().strftime('%Y%m%d_%H%M%S')+'_'+secrets.token_hex(2)
        if not re.fullmatch(r'[a-zA-Z0-9_]{1,64}',self.run_id):raise ValueError('Invalid run identifier')
        self.records=[];self.finished=False;self.interrupted=False;self.started=datetime.now().isoformat(timespec='seconds')
        self.client=requests.Session();self.client.trust_env=False
        self.client.headers.update({'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36',
            'Accept':'text/html,application/json;q=0.9,*/*;q=0.8','Accept-Language':'zh-CN,zh;q=0.9','X-Honeypot-Demo':self.run_id})

    def record(self,phase,label,protocol,status,**fields):
        row={'at':datetime.now().isoformat(timespec='seconds'),'phase':phase,'label':label,'protocol':protocol,'status':status,**fields}
        self.records.append(row)
        suffix=' · HTTP '+str(fields['http_status']) if 'http_status' in fields else ''
        print(f'[{len(self.records):02d}] {phase} / {label}：{status}{suffix}',flush=True)

    def request(self,label,phase='受控交互',method='GET',path='/',params=None,body=None,tag=''):
        if not path.startswith('/') or path.startswith('//') or urlsplit(path).netloc:raise ValueError('Only local relative paths allowed')
        started=time.monotonic()
        headers={'User-Agent':'sqlmap/1.8'} if tag=='scanner' else {}
        if isinstance(body,dict):
            headers['Content-Type']='application/json';body=json.dumps(body,ensure_ascii=False).encode('utf-8')
        elif body:headers['Content-Type']='application/xml'
        # Use %20 for spaces so the project's existing bounded URL-decoding
        # evidence pipeline receives readable SQL/template samples.
        query=urlencode(params or {},quote_via=quote)
        url=f'http://{HOST}:{self.web_port}'+path+((('&' if '?' in path else '?')+query) if query else '')
        try:
            with self.client.request(method,url,data=body,
                headers=headers,timeout=(3,self.timeout),allow_redirects=False,stream=True) as response:
                # Bounded byte-wise read also handles a slow trickle of bytes.
                data=bytearray();cut=False
                for chunk in response.iter_content(chunk_size=1):
                    if time.monotonic()-started>self.timeout:raise TimeoutError('Response deadline exceeded')
                    data.extend(chunk)
                    if len(data)>=16384:cut=True;break
                text=data.decode('utf-8',errors='replace')
                try:payload=json.loads(text) if not cut else None
                except ValueError:payload=None
                self.record(phase,label,'web','response_received',method=method,path=path,params=params or {},
                    sample_type=tag,http_status=response.status_code,response_preview=ANSI.sub('',text)[:1200],
                    preview_truncated=cut or len(text)>1200,elapsed_ms=round((time.monotonic()-started)*1000))
                return payload
        except (requests.RequestException,TimeoutError,OSError) as error:
            self.record(phase,label,'web','transport_error',path=path,error=type(error).__name__)
            return None

    def web(self,quick=False):
        for phase,label,method,path,params,body,tag in scenarios(self.run_id,quick):
            payload=self.request(label,phase,method,path,params,body,tag)
            if tag in ('ssrf','preview') and isinstance(payload,dict):
                path=trusted_poll_path(payload.get('poll'))
                if path:
                    time.sleep(self.gap)
                    self.request('查询同会话模拟任务',path=path,params={'demo_run':self.run_id},tag='job_lookup')
                elif payload.get('poll'):
                    self.record('受控交互','拒绝非预期任务查询地址','web','poll_path_rejected')
            time.sleep(self.gap)

    def business(self):
        for label,method,path,body in [('业务状态','GET','/api/erp/status',None),('业务目录','GET','/api/erp/catalog',None),('订单认证前对照','GET','/api/erp/orders',None),('虚拟业务登录','POST','/api/erp/login',{'username':'guest','password':'training-only'}),('订单读取','GET','/api/erp/orders',None),('创建虚拟导出','POST','/api/erp/export',{})]:
            data=self.request(label,'业务交互',method,path,{'demo_run':self.run_id},body,'erp')
            poll=data.get('poll','') if isinstance(data,dict) else ''
            if isinstance(poll,str) and re.fullmatch(r'/api/erp/jobs/[0-9a-f]{24}',poll):
                time.sleep(self.gap);self.request('读取同会话导出任务','业务交互',path=poll,params={'demo_run':self.run_id})
            time.sleep(self.gap)

    @staticmethod
    def read_shell(channel,timeout):
        deadline=time.monotonic()+timeout;data=bytearray();prompt=re.compile(r'(?:^|\n)[^\r\n]{0,160}[#$] $')
        while time.monotonic()<deadline:
            if channel.recv_ready():
                chunk=channel.recv(4096)
                if not chunk:break
                data.extend(chunk)
                if len(data)>32768:raise RuntimeError('SSH reply exceeds limit')
                cleaned=ANSI.sub('',data.decode('utf-8',errors='replace')).replace('\r','')
                if prompt.search(cleaned):return cleaned
            elif channel.closed:break
            else:time.sleep(.05)
        raise TimeoutError('SSH prompt not received before deadline')

    def ssh(self,username,password,failure_demo=False):
        try:import paramiko
        except ImportError:
            self.record('SSH','缺少 paramiko 依赖','ssh','dependency_missing');return
        def client():
            value=paramiko.SSHClient()
            # Only this fixed loopback host; do not modify the user's known_hosts.
            value.set_missing_host_key_policy(paramiko.AutoAddPolicy());return value
        if failure_demo:
            wrong=client()
            try:
                wrong.connect(HOST,port=self.ssh_port,username='demo_invalid_user',password=secrets.token_hex(12),
                    look_for_keys=False,allow_agent=False,timeout=5,banner_timeout=8,auth_timeout=10)
                self.record('SSH认证对照','一次虚构账号尝试','ssh','unexpected_auth_acceptance')
            except paramiko.AuthenticationException:self.record('SSH认证对照','一次虚构账号尝试','ssh','expected_auth_rejection')
            except Exception as error:self.record('SSH认证对照','认证测试未完成','ssh','transport_error',error=type(error).__name__)
            finally:wrong.close()
            time.sleep(self.gap)
        value=client()
        try:
            value.connect(HOST,port=self.ssh_port,username=username,password=password,look_for_keys=False,allow_agent=False,
                timeout=5,banner_timeout=8,auth_timeout=10)
            key=value.get_transport().get_remote_server_key()
            fingerprint='SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')
            self.record('SSH认证','使用启动窗口的已知测试账号','ssh','virtual_login_accepted',username=username,server_fingerprint=fingerprint)
            channel=value.invoke_shell(term='dumb',width=120,height=30)
            self.read_shell(channel,10)
            directory='/tmp/'+self.run_id
            commands=[('当前身份','whoami'),('准备虚拟演示目录','mkdir '+directory),('进入虚拟目录','cd '+directory),
                ('写入虚拟演示文件','echo '+self.run_id+' > marker.txt'),('读回虚拟文件','cat '+directory+'/marker.txt'),
                ('模型主机概览','sysinfo '+self.run_id),('模型未知命令策略','demo_unknown_'+self.run_id),('虚拟服务列表','appctl status'),('主机诊断','diag')]
            for label,command in commands:
                channel.sendall((command+'\n').encode())
                text=self.read_shell(channel,self.timeout)
                safe=text.replace(password,'[redacted]') if password else text
                self.record('SSH交互',label,'ssh','response_received',command=command,response_preview=safe[:1600],
                    preview_truncated=len(text)>1600)
                time.sleep(self.gap)
            channel.sendall(b'exit\n')
            # Let the honeypot finish logout before closing the transport, avoiding
            # a misleading "Socket is closed" error in its session log.
            deadline=time.monotonic()+3
            while not channel.closed and time.monotonic()<deadline:
                if channel.recv_ready():
                    if not channel.recv(1024):break
                else:time.sleep(.05)
            channel.close()
        except paramiko.AuthenticationException:
            self.record('SSH认证','已知账号未通过','ssh','auth_failed',note='请使用本次 main.py 启动窗口显示的 SSH 测试密码。')
        except Exception as error:
            self.record('SSH交互','会话未完成','ssh','transport_error',error=type(error).__name__)
        finally:value.close()

    def save(self,folder):
        folder=Path(folder);folder.mkdir(parents=True,exist_ok=True)
        result={'run_id':self.run_id,'started':self.started,'finished':self.finished,'interrupted':self.interrupted,
                'target':{'host':HOST,'web_port':self.web_port,'ssh_port':self.ssh_port},'records':self.records,
                'scope':'Synthetic requests and virtual SSH commands against a fixed loopback target. HTTP status and SSH login are not proof of exploitation or AI participation.'}
        path=folder/(self.run_id+'.json');path.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        guide=folder/(self.run_id+'.md')
        guide.write_text('# 本机蜜罐混合演示记录\n\n运行标记：`'+self.run_id+'`\n\n'+
            '\n'.join(f'- {r["phase"]} / {r["label"]}：{r["status"]}'+('，HTTP '+str(r['http_status']) if 'http_status' in r else '') for r in self.records)+
            '\n\n## 展示 AI\n\n登录管理后台 /ai/analysis，等待新记录索引和报告完成。\n'+
            '问答来源填写 127.0.0.1，关键词填写本次运行标记。最多检索8条，模型选取最多6条代表证据。\n'+
            '建议问：这些输入可能有什么目的？哪些证据支持判断？哪些结论不能确认？\n'+
            'AI 是否实际参与，应检查后台的调用编号、完成状态和引用。\n\n'+
            '## 测试最新调查功能\n\n'+
            '1. 打开完成的 AI 报告，点击“加入调查工作台”，建立调查。\n'+
            '2. 关联同次演示的另一份报告，检查原规则、AI风险和证据快照。\n'+
            '3. 点击“让 AI 分析这份调查”，问“攻击过程有哪些阶段？下一步复核什么？”\n'+
            '4. 将状态设为“调查中”，保存笔记，再改为“已结案”，查看版本与操作历史。\n'+
            '5. 导出调查记录；在团队工作台查看关联图、分歧复核、周期报告与检测评测。\n'+
            '6. 首页悬浮国家、拖动、缩放和重置地图；国家提示与来源联动应继续可用。\n',encoding='utf-8')
        return path,guide


def parse_args(argv=None):
    p=argparse.ArgumentParser(description='本机蜜罐混合测试：仅127.0.0.1，有限请求，控制速度，不扫描或爆破。')
    p.add_argument('--web-port',type=int,default=5000);p.add_argument('--ssh-port',type=int,default=2222)
    p.add_argument('--dashboard-port',type=int,default=5001)
    p.add_argument('--ssh',action='store_true',help='加入同会话 SSH 虚拟命令，密码会交互询问')
    p.add_argument('--ssh-user',default='root');p.add_argument('--auth-failure-demo',action='store_true',help='另做一次虚构账号失败对照；无密码字典')
    p.add_argument('--business',action='store_true',help='加入ERP模拟登录、目录、订单和导出流程')
    p.add_argument('--quick',action='store_true',help='较短的 Web 样例集')
    p.add_argument('--gap',type=float,default=4,help='步骤间隔，1～30秒，默认4')
    p.add_argument('--timeout',type=float,default=35,help='单步等待上限，5～60秒')
    p.add_argument('--output',default='demo-results');p.add_argument('--list',action='store_true',help='列出样例，不发送流量')
    args=p.parse_args(argv)
    for port in (args.web_port,args.ssh_port,args.dashboard_port):
        if not 1<=port<=65535:p.error('端口必须在1～65535之间')
    if not 1<=args.gap<=30 or not 5<=args.timeout<=60:p.error('gap需1～30，timeout需5～60')
    if args.auth_failure_demo and not args.ssh:p.error('--auth-failure-demo需要同时使用--ssh')
    return args


def main(argv=None):
    args=parse_args(argv)
    if args.list:
        for phase,label,method,path,params,body,tag in scenarios('preview_only',args.quick):print(f'{phase} | {label} | {method} {path} | {tag}')
        return 0
    demo=Demo(args.web_port,args.ssh_port,args.gap,args.timeout)
    print('固定测试目标：127.0.0.1；请确认这些端口运行的是你自己的蜜罐。',flush=True)
    print('运行标记：'+demo.run_id,flush=True)
    print('HTTP 400/404/503 也可能已记录；脚本不据此认定攻击成功。',flush=True)
    try:
        # Fail early if the local Web service is unavailable; no automatic retries.
        if demo.request('本机服务连通性','准备',path='/') is None and demo.records[-1]['status']=='transport_error':
            print('Web服务不可用，请先启动main.py并核对端口。',flush=True);return 2
        password=getpass.getpass('输入本次启动窗口的 SSH 测试密码（不会保存）：') if args.ssh else None
        demo.web(args.quick)
        if args.business:demo.business()
        if args.ssh:demo.ssh(args.ssh_user,password,args.auth_failure_demo)
        demo.finished=True
        return 2 if any(r['status'] in ('transport_error','auth_failed','dependency_missing') for r in demo.records) else 0
    except KeyboardInterrupt:
        demo.interrupted=True;print('\n已停止，保留已经完成的步骤。',flush=True);return 130
    finally:
        demo.client.close();path,guide=demo.save(args.output)
        print('结果：'+str(path.resolve()),flush=True)
        print('展示提示：'+str(guide.resolve()),flush=True)
        print(f'后台：http://127.0.0.1:{args.dashboard_port}/ai/analysis',flush=True)
        print('先等待索引和报告，再在问答中按运行标记筛选。请勿为刷数量连续重跑。',flush=True)


if __name__=='__main__':
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf-8',errors='replace')
    raise SystemExit(main())
