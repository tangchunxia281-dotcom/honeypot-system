#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

CONFIG_FILE="${HONEYPOT_CONFIG:-${ROOT_DIR}/honeypot.ini}"
export HONEYPOT_CONFIG="${CONFIG_FILE}"

if [[ ! -f "${CONFIG_FILE}" ]]; then
  cp "${ROOT_DIR}/honeypot.ini.example" "${CONFIG_FILE}"
  chmod 600 "${CONFIG_FILE}" || true
  echo "[Init] 已生成根目录配置文件: ${CONFIG_FILE}"
  echo "[Info] 请编辑 honeypot.ini（尤其是 [app] production_mode、[admin] password、[alerting] webhook_url）后重新运行。"
  exit 1
fi

# 固定 SECRET_KEY（如 honeypot.ini 未配置 secret_key，则 app_config.py 会读取此文件）
SECRET_FILE="${SECRET_FILE:-${ROOT_DIR}/.secret_key}"
if [[ ! -f "${SECRET_FILE}" ]]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32 > "${SECRET_FILE}"
  else
    python3 - <<'PY' > "${SECRET_FILE}"
import os
print(os.urandom(32).hex())
PY
  fi
  chmod 600 "${SECRET_FILE}" || true
  echo "[Init] 已生成 .secret_key"
fi

# Check and Install uv
if ! command -v uv &> /dev/null; then
    echo "[Init] 'uv' not found. Installing..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
fi

echo "[Init] Syncing environment via uv..."
uv sync

echo "[Check] 校验统一配置: ${HONEYPOT_CONFIG}"
uv run python - <<'PY'
from app_config import config, describe_config_source, validate_runtime_config, is_production
validate_runtime_config()
conf = config['default']
mode = 'production' if is_production() else 'development'
print(f"[Config] source={describe_config_source()}")
print(f"[Config] mode={mode}")
print(f"[Config] db={conf.DB_TYPE}")
PY

echo "[Run ] uv run python main.py"
exec uv run python main.py
