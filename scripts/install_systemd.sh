#!/usr/bin/env bash
set -euo pipefail

# 用法:
#   bash scripts/install_systemd.sh
#   bash scripts/install_systemd.sh /opt/sheji honeypot
#   RUN_USER=ubuntu RUN_GROUP=ubuntu bash scripts/install_systemd.sh

APP_DIR="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
SERVICE_NAME="${2:-honeypot}"
RUN_USER="${RUN_USER:-$(id -un)}"
RUN_GROUP="${RUN_GROUP:-$(id -gn)}"

TEMPLATE="${APP_DIR}/scripts/honeypot.service.example"
CONFIG_EXAMPLE="${APP_DIR}/honeypot.ini.example"
CONFIG_FILE="${APP_DIR}/honeypot.ini"
TMP_SERVICE="/tmp/${SERVICE_NAME}.service"
SYSTEMD_SERVICE="/etc/systemd/system/${SERVICE_NAME}.service"

if [[ ! -f "${TEMPLATE}" ]]; then
  echo "[ERROR] 模板不存在: ${TEMPLATE}"
  exit 1
fi

if [[ ! -f "${APP_DIR}/main.py" ]]; then
  echo "[ERROR] APP_DIR 无效（未找到 main.py）: ${APP_DIR}"
  exit 1
fi

if [[ ! -x "${APP_DIR}/.venv/bin/python" ]]; then
  echo "[ERROR] 未找到可执行 Python: ${APP_DIR}/.venv/bin/python"
  echo "请先在项目目录执行: uv sync"
  exit 1
fi

if [[ ! -f "${CONFIG_FILE}" ]]; then
  cp "${CONFIG_EXAMPLE}" "${CONFIG_FILE}"
  chmod 600 "${CONFIG_FILE}" || true
  echo "[INFO] 已生成根目录配置文件: ${CONFIG_FILE}"
  echo "[INFO] 请先编辑 [app] production_mode、[admin] password 等配置后再启动服务。"
fi

sed \
  -e "s|__APP_DIR__|${APP_DIR}|g" \
  -e "s|__SERVICE_NAME__|${SERVICE_NAME}|g" \
  -e "s|__RUN_USER__|${RUN_USER}|g" \
  -e "s|__RUN_GROUP__|${RUN_GROUP}|g" \
  "${TEMPLATE}" > "${TMP_SERVICE}"

echo "[INFO] 安装 systemd 服务: ${SYSTEMD_SERVICE}"
sudo cp "${TMP_SERVICE}" "${SYSTEMD_SERVICE}"
sudo chmod 644 "${SYSTEMD_SERVICE}"
rm -f "${TMP_SERVICE}"

sudo systemctl daemon-reload
sudo systemctl enable "${SERVICE_NAME}"

echo
echo "[OK] 安装完成。后续命令："
echo "  sudo systemctl restart ${SERVICE_NAME}"
echo "  sudo systemctl status ${SERVICE_NAME} -n 50 --no-pager"
echo "  sudo journalctl -u ${SERVICE_NAME} -f -o cat"
