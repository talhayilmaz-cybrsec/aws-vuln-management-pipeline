# Remediated image.
# - python:3.13-slim: supported Python on a supported Debian release
# - dependencies upgraded to patched versions (see requirements.txt)
# - runs as an unprivileged user (fixes Trivy DS-0002)
# - HEALTHCHECK lets the orchestrator detect a hung process (DS-0026)
FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

RUN useradd --system --uid 10001 --no-create-home appuser
USER appuser

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)"

CMD ["python", "app.py"]
