FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap dnsutils default-jre-headless ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY scripts/install_zap.py scripts/install_zap.py
RUN python scripts/install_zap.py && rm -f .runtime/tools/zap.zip
COPY backend backend
COPY scripts/container_entrypoint.py scripts/container_entrypoint.py
RUN useradd --uid 10001 --create-home vulnx && mkdir /data && chown -R vulnx:vulnx /data /app/.runtime
ENV VULNX_BIND=0.0.0.0 VULNX_DATA_DIR=/data VULNX_REQUIRE_PERSISTENT_STORAGE=1 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 JAVA_TOOL_OPTIONS=-Xmx512m
EXPOSE 8080
CMD ["python", "scripts/container_entrypoint.py"]
