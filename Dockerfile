FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY cloud_security_auditor ./cloud_security_auditor
COPY samples ./samples
RUN python -m pip install --no-cache-dir .

RUN useradd --create-home --uid 10001 auditor
USER auditor

ENTRYPOINT ["cloud-security-auditor"]
CMD ["--help"]
