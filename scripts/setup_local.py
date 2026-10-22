"""Create a portable local environment from pyproject; preserve the supplied .venv."""
import os
import subprocess
import sys
import venv
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
if __name__=='__main__':
    if sys.version_info<(3,11):raise SystemExit('请使用 Python 3.11 或更高版本运行此安装助手。')
    import tomllib
    target=ROOT/'.venv-local'
    python=target/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
    if not python.exists():venv.EnvBuilder(with_pip=True).create(target)
    with (ROOT/'pyproject.toml').open('rb') as file:dependencies=tomllib.load(file)['project']['dependencies']
    print('正在安装项目声明的依赖；原 .venv、配置和数据库保持原样。',flush=True)
    subprocess.run([str(python),'-m','pip','install',*dependencies],cwd=ROOT,check=True)
    print('完成。运行：'+str(python)+' '+str(ROOT/'main.py'),flush=True)
