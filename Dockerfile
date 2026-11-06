FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 APC_MODE=DEMO APC_DB_PATH=/var/lib/apc/apc.db
WORKDIR /opt/apc
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN python -m pip install --no-cache-dir --upgrade pip     && python -m pip install --no-cache-dir .     && groupadd --system --gid 10001 apc     && useradd --system --uid 10001 --gid apc --home-dir /nonexistent --shell /usr/sbin/nologin apc     && mkdir -p /var/lib/apc     && chown -R 10001:10001 /var/lib/apc
USER 10001:10001
EXPOSE 8787
VOLUME ["/var/lib/apc"]
CMD ["apc", "serve", "--host", "0.0.0.0", "--port", "8787"]
