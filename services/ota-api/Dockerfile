FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    flask gunicorn redis psycopg2-binary minio --break-system-packages

WORKDIR /app
COPY app.py .
COPY svc_client.py .

EXPOSE 8080
CMD ["gunicorn", "-w", "16", "-b", "0.0.0.0:8080", "app:app", "--timeout", "120", "--keep-alive", "5"]
