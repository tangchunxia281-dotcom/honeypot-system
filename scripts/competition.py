"""Portable single-host setup, diagnostics and launch entry point."""
import argparse
import configparser
import getpass
import os
import secrets
import socket
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def initialize(password=None):
    target=ROOT/'honeypot.ini'
    if target.exists():return False
    password=password or getpass.getpass('设置后台管理员密码（至少12位）：')
    if len(password)<12 or '\n' in password or '\r' in password:raise ValueError('密码至少12位，不能含换行')
    p=configparser.ConfigParser(interpolation=None);p.read(ROOT/'honeypot.ini.example',encoding='utf-8-sig')
    p['admin']['password']=password;p['app']['secret_key']=secrets.token_urlsafe(48)
    p['app']['production_mode']='true';p['app']['show_summary_creds']='false';p['app']['show_demo_credentials']='false'
    for section in ('services.ssh','services.web','services.dashboard','services.mysql','services.redis','services.ftp','services.telnet'):p[section]['host']='127.0.0.1'
    with target.open('x',encoding='utf-8') as f:p.write(f)
    ai=ROOT/'ai.local.ini'
    if not ai.exists():ai.write_text((ROOT/'ai.local.ini.example').read_text(encoding='utf-8'),encoding='utf-8')
    print('初始化完成。后台账号 admin，密码为你刚设置的密码。默认仅本机监听，AI关闭。')
    return True

def main():
    parser=argparse.ArgumentParser(description='单机参赛版控制台')
    parser.add_argument('action',choices=['init','start','doctor','ai']);parser.add_argument('--model')
    args=parser.parse_args()
    if args.action in ('init','start'):initialize()
    if args.action=='init':return
    if args.action=='ai':
        if not args.model:raise ValueError('请通过 --model 填写 ollama list 中实际安装的模型名')
        p=configparser.ConfigParser(interpolation=None);p.read(ROOT/'ai.local.ini.example',encoding='utf-8-sig')
        p['ai']['model']=args.model;p['ai']['enabled']='true'
        for key in ('ssh_enabled','analysis_enabled','detection_enabled','web_interaction_enabled'):p['ai'][key]='true'
        with (ROOT/'ai.local.ini').open('w',encoding='utf-8') as f:p.write(f)
        print('已启用本机Ollama；重启项目后生效。模型来源需自行核实。');return
    if args.action=='doctor':
        print('Python:',sys.version.split()[0]);print('配置已初始化:',(ROOT/'honeypot.ini').exists())
        p=configparser.ConfigParser(interpolation=None);p.read(ROOT/'honeypot.ini',encoding='utf-8-sig')
        for service,port in [('web',5000),('dashboard',5001),('ssh',2222),('mysql',13306),('redis',16379),('ftp',2121),('telnet',2223)]:
            port=p.getint('services.'+service,'port',fallback=port)
            with socket.socket() as sock:sock.settimeout(.3);active=sock.connect_ex(('127.0.0.1',port))==0
            print(service,port,'已占用/服务运行中' if active else '未监听')
        print('模型可选；未安装模型不影响规则检测。详细模型诊断在后台“系统与评测→模型调用明细”。');return
    p=configparser.ConfigParser(interpolation=None);p.read(ROOT/'honeypot.ini',encoding='utf-8-sig')
    if len(p.get('admin','password',fallback=''))<12:raise ValueError('配置未设置足够长的后台密码；请重新初始化新目录')
    print('后台：http://127.0.0.1:'+p.get('services.dashboard','port',fallback='5001')+'/super/login',flush=True)
    try:subprocess.run([sys.executable,'-X','utf8',str(ROOT/'main.py')],cwd=ROOT,check=True)
    except KeyboardInterrupt:pass

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,subprocess.CalledProcessError) as error:
        print('操作未完成：'+str(error),file=sys.stderr);raise SystemExit(1)
