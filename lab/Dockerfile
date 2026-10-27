FROM python:3.12-slim
RUN pip install --no-cache-dir cryptography==46.0.7 dnspython==2.9.0 \
    && useradd --uid 10001 --create-home lab
WORKDIR /app
COPY lab/server.py /app/lab/server.py
RUN mkdir -p /app/.runtime/lab && chown -R lab:lab /app/.runtime
USER 10001:10001
ENV VULNX_LAB_BIND=0.0.0.0 PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 18080 18443 15353/udp
CMD ["python", "lab/server.py"]
