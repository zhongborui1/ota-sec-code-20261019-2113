FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    build-essential cmake git \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/guanzhi/GmSSL.git /tmp/GmSSL && \
    cd /tmp/GmSSL && mkdir build && cd build && \
    cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local && \
    make -j$(nproc) && make install && \
    ldconfig && \
    rm -rf /tmp/GmSSL

RUN pip3 install --no-cache-dir flask gunicorn --break-system-packages

WORKDIR /app
COPY signing-service/app.py .
COPY signing-service/security.py .
COPY ota_common /app/ota_common

EXPOSE 8081
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8081", "app:app"]
