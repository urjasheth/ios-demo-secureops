# Intentionally vulnerable Dockerfile to trigger Checkov

# 1. Outdated and potentially vulnerable base image
FROM ubuntu:18.04

# 2. Running as root (Checkov will flag this)
USER root

# 3. Exposing sensitive port unnecessarily
EXPOSE 22

RUN apt-get update && apt-get install -y curl

# 4. Hardcoded credentials in env
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

CMD ["echo", "Running Vulnerable Demo Container"]
