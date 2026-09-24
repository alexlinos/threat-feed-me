FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Refresh the base image's OS packages at build time. python:3.11-slim drifts
# behind Debian security updates between base rebuilds, so a fresh build still
# ships known-vulnerable openssl/util-linux/etc.; upgrading here pulls the
# fixes that DO exist (Grype-confirmed) without changing the Python minor.
# Won't-fix Debian CVEs (perl-base, libc) remain — those need a base change,
# not apt. Clean apt lists afterward to keep the layer small.
RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 appuser

# The base image's own build tooling (pip, setuptools with its vendored
# jaraco.context, wheel) lags its advisories; the service never installs
# packages at runtime, but a scan of the image should come back clean on
# everything with a fix, so bring them current first.
RUN pip install --no-cache-dir --upgrade "pip>=26.2" "setuptools>=83" "wheel>=0.46.2"

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the package so `threatfeedme` is importable (python -m threatfeedme.main,
# uvicorn threatfeedme.app:app, etc.).
RUN pip install --no-cache-dir -e .

# Create directories for data persistence and make the entrypoint executable.
# The runtime user owns ONLY what the app writes: data/ (DB, .env, uploads,
# backups) and output/ (exports). It used to own all of /app, so anything
# running as appuser could rewrite the application code or config.yaml.
RUN mkdir -p /app/data /app/output && \
    chmod +x /app/entrypoint.sh && \
    chown -R appuser:appuser /app/data /app/output

# The source tree is now read-only to appuser; don't let Python try (and
# silently fail) to write __pycache__ into it.
ENV PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER appuser

# Expose dashboard port
EXPOSE 8080

# Health check. Uses an unauthenticated feed endpoint so it still works when
# dashboard Basic auth is enabled (the /api/* routes would return 401).
# Health probe: /healthz is constant-cost and unauthenticated. Never probe a
# feed URL here — /feeds/all.txt response time grows with the corpus and
# eventually exceeds the probe timeout, marking healthy deployments unhealthy.
# start-period: a first start after an upgrade may migrate the database before
# serving (2.5.0: ~2 min on a 1.9 GB database); keep in sync with compose.
HEALTHCHECK --interval=30s --timeout=10s --start-period=300s --retries=3 \
    CMD python -c "import socket,requests,sys; ip=socket.gethostbyname(socket.gethostname()); sys.exit(0 if requests.get('http://'+ip+':8080/healthz', timeout=5).ok else 1)" || exit 1

# Default command: start dashboard immediately; run the pipeline in the
# background so a failing/slow feed fetch never blocks startup.
ENV DASHBOARD_HOST=0.0.0.0
CMD ["/app/entrypoint.sh"]
