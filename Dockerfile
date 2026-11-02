FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30 AS builder
RUN pip install --no-cache-dir uv==0.11.32
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable --python /usr/local/bin/python

FROM python:3.12-slim@sha256:b18b261e1b4974b4f321451ad5251ded85abb22c2b8b262da527dda1d031ab30
RUN groupadd --gid 1000 mcp \
    && useradd --uid 1000 --gid 1000 --no-create-home mcp \
    && mkdir -p /state /run/discord-secrets \
    && chown mcp:mcp /state /run/discord-secrets \
    && chmod 700 /state /run/discord-secrets
COPY --from=builder /app/.venv /app/.venv
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
USER 1000:1000
EXPOSE 19230
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:19230/healthz', timeout=3)"]
ENTRYPOINT ["/app/.venv/bin/discord-history-mcp"]
CMD ["--config", "/config/config.json", "serve", "--host", "0.0.0.0"]
