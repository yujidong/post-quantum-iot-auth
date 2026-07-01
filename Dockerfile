# =============================================================================
# Post-Quantum IoT Blockchain Experiment Environment
# Builds liboqs from source, installs liboqs-python, Hardhat, and all deps.
# =============================================================================
# Build:  docker compose build
# Test:   docker compose run --rm experiments pytest tests/ -v
# Shell:  docker compose run --rm experiments bash
# =============================================================================

FROM ubuntu:22.04 AS base

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# ── System dependencies ──
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git wget curl ca-certificates \
    python3 python3-pip python3-venv \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Install Node.js 20.x via NodeSource ──
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    node --version && npm --version

# ── Build liboqs 0.15.0 from official release tarball ──
ARG LIBOQS_VERSION=0.15.0
RUN wget -q -O /tmp/liboqs.tar.gz \
        "https://github.com/open-quantum-safe/liboqs/archive/refs/tags/${LIBOQS_VERSION}.tar.gz" && \
    mkdir -p /tmp/liboqs && \
    tar -xzf /tmp/liboqs.tar.gz -C /tmp/liboqs --strip-components=1 && \
    cd /tmp/liboqs && mkdir build && cd build && \
    cmake -GNinja .. \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DOQS_ALGS_ENABLED=STD && \
    ninja -j"$(nproc)" && ninja install && \
    ldconfig && rm -rf /tmp/liboqs /tmp/liboqs.tar.gz

# ── Python dependencies ──
RUN pip3 install --no-cache-dir \
    pip setuptools wheel && \
    pip3 install --no-cache-dir \
    liboqs-python>=0.12.0 \
    pqcrypto>=0.1.0 \
    cryptography>=42.0.0 \
    pytest>=8.0.0 \
    web3>=6.0.0 \
    psutil>=5.9.0 \
    pandas>=2.0.0 \
    matplotlib>=3.8.0

WORKDIR /app/experiments

# ── Install Hardhat dependencies ──
COPY smart-contracts/package.json /app/experiments/smart-contracts/
COPY smart-contracts/package-lock.json* /app/experiments/smart-contracts/
RUN cd /app/experiments/smart-contracts && npm install

# ── Copy all experiment code ──
COPY . /app/experiments/

# ── Verify liboqs works ──
RUN python3 -c "import oqs; sig = oqs.Signature('Falcon-512'); pk = sig.generate_keypair(); print(f'liboqs Falcon-512 OK: PK={len(pk)}B'); del sig" && \
    python3 -c "import oqs; print('Supported:', [a for a in oqs.get_enabled_sig_mechanisms() if 'Falcon' in a or 'ML-DSA' in a])"

# ── Entrypoint ──
COPY scripts/docker-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["python3", "-m", "pytest", "tests/", "-v", "--tb=short"]
