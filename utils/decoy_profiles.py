"""Synthetic hosts and business state; no real process, file or network access."""
import hashlib
import json
import re
import os

PROFILES={
 'erp_web':{'os':'Ubuntu 24.04.2 LTS','kernel':'6.8.0-52-generic','hostname':'erp-app','role':'ERP application server','services':{'nginx':'running','erp-api':'running','postgresql':'stopped'},'ports':[22,80,8080]},
 'data_node':{'os':'Ubuntu 22.04.5 LTS','kernel':'5.15.0-113-generic','hostname':'data-node','role':'Internal data service','services':{'postgresql':'running','redis':'running','backup-worker':'stopped'},'ports':[22,5432,6379]},
 'support_node':{'os':'Ubuntu 24.04.2 LTS','kernel':'6.8.0-52-generic','hostname':'support','role':'Support portal server','services':{'nginx':'running','support-api':'running','redis':'stopped'},'ports':[22,443,8081]},
}


def profile(identity):
    digest=hashlib.sha256(str(identity).encode()).hexdigest();name=list(PROFILES)[int(digest[:8],16)%len(PROFILES)]
    from ssh_honeypot.ssh_config import KERNEL_RELEASE
    p=dict(PROFILES[name]);p['services']=dict(p['services']);p['id']=name;p['hostname']=p['hostname']+'-'+digest[:4];p['machine_id']=digest[:32];p['os']='Ubuntu 24.04.2 LTS';p['kernel']=KERNEL_RELEASE;return p


def initialize_shell(shell):
    p=profile(os.environ.get('HONEYPOT_PERSONA_SEED','team-sensor'));shell.decoy_profile=p;shell.hostname=p['hostname']
    if not hasattr(shell,'files_content'):shell.files_content={}
    if not hasattr(shell,'fs_state'):shell.fs_state={}
    from ssh_honeypot.ssh_config import KERNEL_RELEASE
    p['kernel']=KERNEL_RELEASE;p['os']='Ubuntu 24.04.2 LTS'
    shell.files_content['/etc/hostname']=p['hostname']+'\n'
    shell.files_content['/etc/os-release']=f'NAME="Ubuntu"\nPRETTY_NAME="{p["os"]}"\nID=ubuntu\n'
    shell.files_content['/opt/company/app.conf']=f'role={p["role"]}\nprofile={p["id"]}\nmaintenance=scheduled\n'
    shell.files_content['/var/log/company-app.log']='[info] application bootstrap complete\n[info] health endpoint ready\n'
    shell.fs_state.setdefault('/opt/company',[])
    if 'app.conf' not in shell.fs_state['/opt/company']:shell.fs_state['/opt/company'].append('app.conf')
    shell.fs_state.setdefault('/opt',[])
    if 'company' not in shell.fs_state['/opt']:shell.fs_state['/opt'].append('company')
    if 'company-app.log' not in shell.fs_state.setdefault('/var/log',[]):shell.fs_state['/var/log'].append('company-app.log')
    if hasattr(shell,'processes'):
        from ssh_honeypot import commands
        for name,state in p['services'].items():commands._set_service_running(shell,name,state=='running',save=False)


def intent(command):
    raw=str(command).strip()
    if len(raw)>500 or re.search(r'[;|&<>`\n\r]|\$\(',raw):return None
    parts=raw.split();name=parts[0] if parts else ''
    if name in ('sysinfo','hostinfo','diag','support-status'):return {'action':'profile_summary','service':''}
    if name=='appctl' and len(parts) in (2,3):
        if parts[1]=='status':return {'action':'service_status','service':parts[2] if len(parts)==3 else ''}
        if parts[1] in ('start','stop','restart') and len(parts)==3:return {'action':'service_'+parts[1],'service':parts[2]}
        if parts[1]=='logs':return {'action':'virtual_logs','service':parts[2] if len(parts)==3 else ''}
    if name=='dbdiag':return {'action':'database_health','service':'postgresql'}
    return None


def render(shell,action,service=''):
    if not hasattr(shell,'decoy_profile'):initialize_shell(shell)
    p=shell.decoy_profile;services=p['services']
    if hasattr(shell,'services_state'):
        for name in services:
            if name in shell.services_state:services[name]='running' if shell.services_state[name].get('running') else 'stopped'
    if service and service not in services:return f'{service}: service not installed\n'
    if action=='profile_summary':return f'hostname: {shell.hostname}\nos: {p["os"]}\nkernel: {p["kernel"]}\nrole: {p["role"]}\nworking directory: {shell.current_path}\n'
    if action=='service_status':return '\n'.join(f'{name}: {state}' for name,state in services.items() if not service or name==service)+'\n'
    if action in ('service_start','service_stop','service_restart'):
        if not service:return 'service name required\n'
        if getattr(shell,'username','root')!='root':return f'{service}: Permission denied\n'
        services[service]='stopped' if action=='service_stop' else 'running'
        if hasattr(shell,'processes'):
            from ssh_honeypot import commands
            commands._set_service_running(shell,service,services[service]=='running')
        # Changes only this connection's synthetic profile and virtual log.
        shell.files_content['/var/log/company-app.log']+=f'[operator] {action} {service}\n'
        shell.files_content['/var/log/company-app.log']=shell.files_content['/var/log/company-app.log'][-4000:]
        return f'{service}: {services[service]}\n'
    if action=='virtual_logs':return shell.files_content['/var/log/company-app.log'][-1200:]
    if action=='database_health':return 'postgresql: '+services.get('postgresql','not installed')+'\n'
    return 'service temporarily unavailable\n'


def business_payload(state,resource,action):
    p=profile(state['persona_seed']);state['profile_id']=p['id']
    if resource=='status':return {'hostname':p['hostname'],'role':p['role'],'services':p['services']},200
    if resource=='catalog':return {'items':[{'sku':'DEMO-1001','name':'Office printer','stock':18},{'sku':'DEMO-1002','name':'Managed switch','stock':7}],'source':'cached'},200
    if resource=='orders':
        if not state.get('business_authenticated'):return {'error':'Authentication required'},401
        return {'orders':[{'order_id':'ORD-DEMO-001','status':'processing','total':1200}]},200
    if resource=='login':
        state['business_authenticated']=True;return {'status':'signed_in','user':'guest-operator'},200
    if resource=='export':
        if not state.get('business_authenticated'):return {'error':'Authentication required'},401
        state.setdefault('export_id',hashlib.sha256((state['persona_seed']+'export').encode()).hexdigest()[:24]);state['export_status']='queued'
        return {'job_id':state['export_id'],'status':'queued','poll':'/api/erp/jobs/'+state['export_id']},202
    if resource=='job':return {'job_id':state['export_id'],'status':'ready','records':1},200
    return {'error':'Unsupported resource'},404
