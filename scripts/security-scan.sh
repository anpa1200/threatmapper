#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_step() {
  local name="$1"
  shift
  printf '\n==> %s\n' "$name"
  "$@"
}

optional_step() {
  local tool="$1"
  local name="$2"
  shift 2
  if command -v "$tool" >/dev/null 2>&1; then
    run_step "$name" "$@"
  else
    printf '\n==> %s\nSKIP: %s is not installed.\n' "$name" "$tool"
  fi
}

run_step "Backend lint / SAST baseline (ruff)" bash -lc 'cd backend && ruff check .'
optional_step bandit "Backend SAST (bandit)" bash -lc 'cd backend && bandit -q -r app -x "tests,app/data" --severity-level medium --confidence-level medium'
optional_step pip-audit "Backend dependency audit (pip-audit)" bash -lc 'cd backend && pip-audit -r requirements.txt'
run_step "Frontend dependency audit (npm audit)" bash -lc 'cd frontend && npm audit --audit-level=high'
optional_step gitleaks "Secret scan (gitleaks)" gitleaks detect --source . --no-banner --redact
run_step "Docker Compose config validation" docker compose config --quiet

if command -v trivy >/dev/null 2>&1; then
  run_step "Container image scan (Trivy backend)" bash -lc 'docker build -t adversarygraph-backend:local-scan backend >/dev/null && trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 adversarygraph-backend:local-scan'
else
  printf '\n==> Container image scan (Trivy backend)\nSKIP: trivy is not installed.\n'
fi

printf '\nSecurity validation completed.\n'
