FROM python:3.12-slim AS builder

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml /app/pyproject.toml
COPY README.md /app/README.md
COPY app /app/app
RUN pip install --no-cache-dir --disable-pip-version-check --no-compile .

FROM gcr.io/distroless/python3-debian12

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PATH="/opt/venv/bin:$PATH"

COPY --from=builder /opt/venv /opt/venv

EXPOSE 2525 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/opt/venv/bin/python", "-c", "import json,sys,urllib.request; resp = urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3); data = json.load(resp); sys.exit(0 if (resp.status == 200 and data.get('redis') == 'up') else 1)"]

CMD ["/opt/venv/bin/uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
