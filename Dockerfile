FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Create non-root user for security
RUN useradd -m -u 1000 appuser

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install the package so `threatfeedme` is importable (python -m threatfeedme.main,
# uvicorn threatfeedme.app:app, etc.).
RUN pip install --no-cache-dir -e .

# Create directories for data persistence and make the entrypoint executable
RUN mkdir -p /app/data /app/output && \
    chmod +x /app/entrypoint.sh && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose dashboard port
EXPOSE 8080

# Health check. Uses an unauthenticated feed endpoint so it still works when
# dashboard Basic auth is enabled (the /api/* routes would return 401).
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import socket,requests,sys; ip=socket.gethostbyname(socket.gethostname()); sys.exit(0 if requests.get('http://'+ip+':8080/feeds/all.txt', timeout=5).ok else 1)" || exit 1

# Default command: start dashboard immediately; run the pipeline in the
# background so a failing/slow feed fetch never blocks startup.
ENV DASHBOARD_HOST=0.0.0.0
CMD ["/app/entrypoint.sh"]
