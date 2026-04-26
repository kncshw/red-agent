FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Update and install Kali tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    nikto \
    gobuster \
    whatweb \
    curl \
    wget \
    openssl \
    netcat-openbsd \
    enum4linux \
    hydra \
    sqlmap \
    masscan \
    dnsutils \
    smbclient \
    dirb \
    wordlists \
    python3 \
    python3-pip \
    python3-venv \
    tmux \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python server dependencies
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY server.py .

EXPOSE 443

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "443"]
