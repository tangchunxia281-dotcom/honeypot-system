"""Run isolated regression and local investigation checks; no real model required."""
import os
import shutil
import subprocess
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

if __name__=='__main__':
    subprocess.run([sys.executable,'-X','utf8','-m','unittest','discover','-s','scripts','-p','test_scope_regressions.py','-v'],cwd=ROOT,check=True)
    checks=[['-m','unittest','discover','-s','scripts','-p','test_integrations24.py','-v'],['-m','unittest','discover','-s','scripts','-p','test_product_ui.py','-v'],['-m','unittest','discover','-s','scripts','-p','test_workspace.py','-v'],['-m','unittest','discover','-s','scripts','-p','test_ai_setup.py','-v'],['scripts/verify_project.py'],['-m','unittest','discover','-s','scripts','-p','test_competition.py','-v'],['-m','unittest','discover','-s','scripts','-p','test_active.py','-v'],['-m','unittest','discover','-s','scripts','-p','test_effectiveness.py','-v'],['-m','unittest','discover','-s','scripts','-p','test_story.py','-v'],['-m','unittest','discover','-s','scripts','-p','test_model_timing.py','-v']]
    for args in checks:
        subprocess.run([sys.executable,'-X','utf8',*args],cwd=ROOT,check=True,env=dict(os.environ,PYTHONUTF8='1'))
    if shutil.which('node'):
        for path in ('scripts/verify_frontend.js','scripts/test_workspace_navigation.js','scripts/test_product_sections.js','scripts/test_shell_navigation.js'):
            subprocess.run(['node',path],cwd=ROOT,check=True)
    else:print('未安装Node：跳过可选前端逻辑检查，Python检查照常完成。')
    print('本轮检查全部通过；不包含真实模型准确率、独立盲测或无限压力认证。')
