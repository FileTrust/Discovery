FROM debian:bookworm-slim@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/filetrust-source
COPY requirements.txt ./
RUN python3 -m venv /opt/filetrust-env \
    && /opt/filetrust-env/bin/python -m pip install --no-cache-dir --disable-pip-version-check --timeout 120 --retries 5 -r requirements.txt \
    && /opt/filetrust-env/bin/python -m pip check
ENV PATH="/opt/filetrust-env/bin:${PATH}"
COPY . ./
RUN python -c "from ft_package import source_manifest; source_manifest()" \
    && groupadd --gid 10001 ftapp \
    && useradd --uid 10001 --gid 10001 --home-dir /app --no-create-home --shell /usr/sbin/nologin ftapp \
    && mkdir -p /app /run/filetrust \
    && chown 10001:10001 /app /run/filetrust && chmod 0700 /app /run/filetrust
ENV HOME=/app TMPDIR=/run/filetrust FILETRUST_CONTAINER=1 FILETRUST_INSTALL_BANNER_SHOWN=1
USER 10001:10001
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "/opt/filetrust-source/container_cli.py"]
CMD ["run"]
