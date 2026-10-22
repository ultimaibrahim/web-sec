# Dockerfile - Web-Sec Cyber-Deck Suite

# Core stage
FROM python:3.13-slim AS core

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TERM=xterm-256color \
    DEBIAN_FRONTEND=noninteractive

# Install essential system tools and network reconnaissance binaries (core)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    nmap \
    net-tools \
    sqlite3 \
    ca-certificates \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Create dedicated non‑root security user
RUN useradd -m -u 1000 websec && \
    mkdir -p /app/outputs /home/websec/.config/websec/wordlists && \
    chown -R websec:websec /app /home/websec

# Copy project files
COPY --chown=websec:websec . /app/

# Ensure secure key permissions
RUN touch /app/.vault.key && chmod 600 /app/.vault.key && \
    chmod +x /app/run.sh

USER websec

VOLUME ["/app/outputs", "/home/websec/.config/websec"]

ENTRYPOINT ["/app/run.sh"]
CMD ["2"]

# Extended stage with additional Red‑Team tooling
FROM python:3.13-slim AS extended

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TERM=xterm-256color \
    DEBIAN_FRONTEND=noninteractive

# Install core tools plus Red‑Team binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    nmap \
    net-tools \
    sqlite3 \
    ca-certificates \
    procps \
    # Red‑Team utilities from apt (where available)
    findomain \
    dnsx \
    httpx \
    naabu \
    nuclei \
    nikto \
    zaproxy \
    sqlmap \
    && rm -rf /var/lib/apt/lists/*

# Install Go‑based tools not in apt repositories
RUN curl -sSL https://github.com/EmpireProject/SharpHound/releases/download/v4.2.0/sharphound_linux_amd64 -o /usr/local/bin/sharphound && chmod +x /usr/local/bin/sharphound \
    && curl -sSL https://github.com/GhostPack/Rubeus/releases/download/v2.0.0/rubeus_linux_amd64 -o /usr/local/bin/rubeus && chmod +x /usr/local/bin/rubeus

WORKDIR /app

# Install Python dependencies (same as core)
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Re‑create non‑root user (same UID/GID as core)
RUN useradd -m -u 1000 websec && \
    mkdir -p /app/outputs /home/websec/.config/websec/wordlists && \
    chown -R websec:websec /app /home/websec

# Copy project files
COPY --chown=websec:websec . /app/

# Secure key permissions
RUN touch /app/.vault.key && chmod 600 /app/.vault.key && \
    chmod +x /app/run.sh

USER websec

VOLUME ["/app/outputs", "/home/websec/.config/websec"]

ENTRYPOINT ["/app/run.sh"]
CMD ["2"]
