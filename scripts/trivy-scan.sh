#!/bin/bash
# ============================================================
# Trivy Dependency Scan Script (Pre-push hook)
# File: scripts/trivy-scan.sh
# Called by pre-commit on git push
# From: Approach B
# ============================================================

# Check if trivy is installed natively first
if command -v trivy &>/dev/null; then
  echo "🛡️ Running Trivy dependency scan (native)..."
  trivy fs \
    --severity HIGH,CRITICAL \
    --exit-code 1 \
    --quiet \
    .

  EXIT_CODE=$?

  if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ No HIGH/CRITICAL vulnerabilities found"
  else
    echo "❌ HIGH/CRITICAL vulnerabilities found — push blocked"
    echo "   Fix vulnerabilities or request an exception:"
    echo "   hardikdoshi@devrepublic.nl"
  fi

  exit $EXIT_CODE
fi

# Fallback: Docker-based Trivy
if ! command -v docker &>/dev/null; then
  echo "⚠️ Neither trivy nor Docker found — skipping dependency scan"
  echo "   Install trivy: brew install trivy"
  exit 0
fi

if ! docker info &>/dev/null 2>&1; then
  echo "⚠️ Docker is not running — skipping Trivy scan"
  exit 0
fi

echo "🛡️ Running Trivy dependency scan (Docker)..."

docker run --rm \
  -v "$(pwd):/src" \
  aquasec/trivy:latest \
  fs \
  --severity HIGH,CRITICAL \
  --exit-code 1 \
  --quiet \
  /src

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  echo "✅ No HIGH/CRITICAL vulnerabilities found"
else
  echo "❌ HIGH/CRITICAL vulnerabilities found — push blocked"
  echo "   Fix vulnerabilities or request an exception:"
  echo "   hardikdoshi@devrepublic.nl"
fi

exit $EXIT_CODE
