# Phase 0 skeleton. Semgrep, gitleaks, and osv-scanner are installed in a later phase.
FROM python:3.11-slim-bookworm

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY standards ./standards
COPY prompts ./prompts
RUN pip install --no-cache-dir .

ENTRYPOINT ["tollgate"]
CMD ["--help"]
