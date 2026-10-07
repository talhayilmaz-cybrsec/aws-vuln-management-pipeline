"""Minimal sample web service used as the scan target for this pipeline.

The application logic is intentionally trivial. What matters for the project
is the container image it ships in (see Dockerfile and requirements.txt),
which deliberately contains outdated components so the scanners have real
findings to report.
"""

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/health")
def health():
    return jsonify(status="ok")


@app.route("/")
def index():
    return jsonify(service="vuln-pipeline-demo", version="1.0.0")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
