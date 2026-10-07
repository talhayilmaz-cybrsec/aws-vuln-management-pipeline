# INTENTIONALLY VULNERABLE image - demo scan target only.
# - python:3.8-slim-buster: end-of-life Python on end-of-life Debian 10
# - runs as root, no HEALTHCHECK (misconfigurations the config scan flags)
FROM python:3.8-slim-buster

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8080
CMD ["python", "app.py"]
