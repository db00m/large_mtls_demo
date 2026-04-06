FROM python:3.12-slim

WORKDIR /srv/signer

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

COPY server.py .

EXPOSE 8000

CMD ["python", "server.py"]
