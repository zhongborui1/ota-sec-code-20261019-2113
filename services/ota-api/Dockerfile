FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    python3 python3-pip build-essential cmake git \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    flask gunicorn redis psycopg2-binary minio --break-system-packages

# API independently verifies root-signed policies; it needs GmSSL but no private key.
RUN git clone --depth 1 https://github.com/guanzhi/GmSSL.git /tmp/GmSSL && \
    cd /tmp/GmSSL && mkdir build && cd build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make -j$(nproc) && make install && ldconfig && rm -rf /tmp/GmSSL

WORKDIR /app
COPY ota-api/app.py .
COPY ota-api/svc_client.py .
COPY ota_common /app/ota_common

EXPOSE 8080
CMD ["gunicorn", "-w", "16", "-b", "0.0.0.0:8080", "app:app", "--timeout", "120", "--keep-alive", "5"]
