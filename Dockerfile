# Stage 1: Builder
FROM python:3.11-slim AS builder

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY pyproject.toml README.md ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefix=/install .

# Stage 2: Runtime - Distroless
FROM gcr.io/distroless/python3-debian12:nonroot

USER nonroot:nonroot
WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /install/lib/python3.11/site-packages /home/nonroot/.local/lib/python3.11/site-packages
COPY --chown=nonroot:nonroot app ./app

ENV PYTHONPATH=/home/nonroot/.local/lib/python3.11/site-packages:/app
ENV PYTHONUNBUFFERED=1
ENV PATH=/home/nonroot/.local/bin:$PATH

EXPOSE 8000 2525

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import json,sys,urllib.request; resp = urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3); data = json.load(resp); sys.exit(0 if (resp.status == 200 and data.get('redis') == 'up') else 1)"]

ENTRYPOINT ["python", "-m", "uvicorn"]
CMD ["app.main:app", "--host", "0.0.0.0", "--port", "8000"]
