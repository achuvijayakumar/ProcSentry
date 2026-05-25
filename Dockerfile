FROM python:3.12-slim

WORKDIR /opt/procsentry
ENV PYTHONUNBUFFERED=1

COPY pyproject.toml README.md ./
COPY app ./app
COPY config ./config
RUN pip install --no-cache-dir .

VOLUME ["/var/lib/procsentry"]
EXPOSE 8080
CMD ["procsentry", "--config", "config/procsentry.yml", "web"]

