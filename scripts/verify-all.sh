#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_FILE=infra/verify.compose.yml
export COMPOSE_PROJECT_NAME=shield-verify
export REPORT_DIR=reports
export POSTGRES_PASSWORD=shield_local_test_only
export DATABASE_URL_MIGRATOR="${DATABASE_URL_MIGRATOR:-postgres://shield:shield_local_test_only@127.0.0.1:55432/shield}"
export DATABASE_URL_RUNTIME="${DATABASE_URL_RUNTIME:-postgres://shield_runtime:shield_runtime_test_only@127.0.0.1:55432/shield}"
export REDIS_URL_TEST="${REDIS_URL_TEST:-redis://127.0.0.1:56379}"
export VERIFY_API_URL="${VERIFY_API_URL:-http://127.0.0.1:33001}"
export VERIFY_API_URL_2="${VERIFY_API_URL_2:-http://127.0.0.1:33003}"
export VERIFY_OPENAI_URL="${VERIFY_OPENAI_URL:-http://127.0.0.1:4010}"
export VERIFY_WORKER_URL="${VERIFY_WORKER_URL:-http://127.0.0.1:33002/healthz}"
mkdir -p "$REPORT_DIR"
cleanup() {
  docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" logs --no-color > "$REPORT_DIR/compose.log" 2>&1 || true
  docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" down --volumes --remove-orphans || true
}
trap cleanup EXIT
docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" config > "$REPORT_DIR/compose-config.yml"
npm ci
npm install --no-save --package-lock=false axe-core@4.14.0 @lhci/cli@0.15.1
npm run typecheck
npm run lint
npm test
npm run eval | tee "$REPORT_DIR/eval.json"
python3 -m pip install -r requirements-test.txt
python3 -m playwright install chromium
docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" down --volumes --remove-orphans
docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" up -d --build postgres redis
docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" up -d --build migrate
docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" run --build --rm migrate-drill | tee "$REPORT_DIR/migrations.jsonl"
docker compose -f "$COMPOSE_FILE" -p "$COMPOSE_PROJECT_NAME" up -d --build --wait api api-2 app worker scan-worker-a scan-worker-b openai-mock
SHIELD_BASE_URL=http://127.0.0.1:33000 AXE_REQUIRED=1 python3 tests/e2e/browser_e2e.py | tee "$REPORT_DIR/browser-e2e.stdout"
npx lhci autorun --config=.lighthouserc.json | tee "$REPORT_DIR/lighthouse.stdout"
npm run integration | tee "$REPORT_DIR/integration.tap"
npm run chaos | tee "$REPORT_DIR/chaos.stdout"
npm run backup:restore | tee "$REPORT_DIR/backup-restore.stdout"
for profile in baseline ramp spike soak; do
  docker run --rm --add-host=host.docker.internal:host-gateway -e "PROFILE=$profile" -e "TARGET_URL=http://host.docker.internal:33001" -e "SOAK_DURATION=${SOAK_DURATION:-10m}" -v "$PWD:/work" -w /work grafana/k6:0.53.0 run --summary-export "/work/reports/k6-$profile.json" /work/scripts/load.k6.js | tee "$REPORT_DIR/k6-$profile.stdout"
done
docker run --rm --network shield-verify_default -v "$PWD/reports:/zap/wrk/:rw" zaproxy/zap-stable zap-baseline.py -t http://app:80 -J zap-baseline.json | tee "$REPORT_DIR/zap-baseline.stdout"
docker run --rm --network shield-verify_default -v "$PWD/reports:/zap/wrk/:rw" zaproxy/zap-stable zap-api-scan.py -t http://api:3001/openapi.yaml -f openapi -J zap-api.json | tee "$REPORT_DIR/zap-api.stdout"
printf 'Verification completed. Reports are in %s\n' "$REPORT_DIR"
