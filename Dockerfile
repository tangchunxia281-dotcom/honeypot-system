# syntax=docker/dockerfile:1
# 网络威胁态势感知与蜜罐诱捕系统 - 一体化镜像
# 构建:  docker build -t honeypot-system .
# 运行:  docker run -d -p 2222:2222 -p 5000:5000 -p 5001:5001 \
#          -v honeypot-database:/app/database -v honeypot-logs:/app/logs honeypot-system
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    TZ=Asia/Shanghai

WORKDIR /app

# 先装依赖，充分利用构建缓存
COPY requirements.txt ./
RUN pip install -r requirements.txt

# 再拷贝源码（.dockerignore 已排除本地状态与敏感文件）
COPY . .

# 运行时数据目录：SQLite 库 / 归档 / 日志 / 会话录像等
RUN mkdir -p /app/database /app/logs
VOLUME ["/app/database", "/app/logs"]

# 2222 SSH 蜜罐 / 5000 Web 蜜罐 / 5001 Dashboard
EXPOSE 2222 5000 5001

# 生产部署请通过环境变量或挂载 honeypot.ini 设置：
#   PRODUCTION_MODE=true  ADMIN_PASS=<强口令>
CMD ["python", "main.py"]
