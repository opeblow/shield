$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $repoRoot
$env:COMPOSE_FILE = 'infra/verify.compose.yml'
$env:COMPOSE_PROJECT_NAME = 'shield-verify'
$env:REPORT_DIR = 'reports'
$env:POSTGRES_PASSWORD = 'shield_local_test_only'
$env:DATABASE_URL_MIGRATOR = 'postgres://shield:shield_local_test_only@127.0.0.1:55432/shield'
$env:DATABASE_URL_RUNTIME = 'postgres://shield_runtime:shield_runtime_test_only@127.0.0.1:55432/shield'
$env:REDIS_URL_TEST = 'redis://127.0.0.1:56379'
$env:VERIFY_API_URL = 'http://127.0.0.1:33001'
$env:VERIFY_API_URL_2 = 'http://127.0.0.1:33003'
$env:VERIFY_OPENAI_URL = 'http://127.0.0.1:4010'
$env:VERIFY_WORKER_URL = 'http://127.0.0.1:33002/healthz'
New-Item -ItemType Directory -Force -Path $env:REPORT_DIR | Out-Null
function Invoke-Checked([string]$Command, [string[]]$Arguments) {
  & $Command @Arguments
  if ($LASTEXITCODE -ne 0) { throw "$Command $($Arguments -join ' ') failed with exit code $LASTEXITCODE" }
}
try {
  docker compose -f $env:COMPOSE_FILE -p $env:COMPOSE_PROJECT_NAME config | Set-Content reports/compose-config.yml
  if ($LASTEXITCODE -ne 0) { throw 'docker compose config failed' }
  Invoke-Checked 'npm.cmd' @('ci')
  Invoke-Checked 'npm.cmd' @('install','--no-save','--package-lock=false','axe-core@4.14.0','@lhci/cli@0.15.1')
  Invoke-Checked 'npm.cmd' @('run','typecheck')
  Invoke-Checked 'npm.cmd' @('run','lint')
  Invoke-Checked 'npm.cmd' @('test')
  npm.cmd run eval | Tee-Object reports/eval.stdout
  if ($LASTEXITCODE -ne 0) { throw 'eval failed' }
  Invoke-Checked 'python' @('-m','pip','install','-r','requirements-test.txt')
  Invoke-Checked 'python' @('-m','playwright','install','chromium')
  Invoke-Checked 'docker' @('compose','-f',$env:COMPOSE_FILE,'-p',$env:COMPOSE_PROJECT_NAME,'down','--volumes','--remove-orphans')
  Invoke-Checked 'docker' @('compose','-f',$env:COMPOSE_FILE,'-p',$env:COMPOSE_PROJECT_NAME,'up','-d','--build','postgres','redis')
  Invoke-Checked 'docker' @('compose','-f',$env:COMPOSE_FILE,'-p',$env:COMPOSE_PROJECT_NAME,'up','-d','--build','migrate')
  docker compose -f $env:COMPOSE_FILE -p $env:COMPOSE_PROJECT_NAME run --build --rm migrate-drill | Tee-Object reports/migrations.stdout
  if ($LASTEXITCODE -ne 0) { throw 'migration drill failed' }
  Invoke-Checked 'docker' @('compose','-f',$env:COMPOSE_FILE,'-p',$env:COMPOSE_PROJECT_NAME,'up','-d','--build','--wait','api','api-2','app','worker','scan-worker-a','scan-worker-b','openai-mock')
  $env:SHIELD_BASE_URL = 'http://127.0.0.1:33000'
  $env:AXE_REQUIRED = '1'
  python tests/e2e/browser_e2e.py | Tee-Object reports/browser-e2e.stdout
  if ($LASTEXITCODE -ne 0) { throw 'browser E2E failed' }
  npx.cmd lhci autorun --config=.lighthouserc.json | Tee-Object reports/lighthouse.stdout
  if ($LASTEXITCODE -ne 0) { throw 'Lighthouse CI failed' }
  Invoke-Checked 'npm.cmd' @('run','integration')
  Invoke-Checked 'npm.cmd' @('run','chaos')
  Invoke-Checked 'npm.cmd' @('run','backup:restore')
  foreach ($profile in @('baseline','ramp','spike','soak')) {
    $mount = "${repoRoot}:/work"
    docker run --rm --add-host=host.docker.internal:host-gateway -e "PROFILE=$profile" -e 'TARGET_URL=http://host.docker.internal:33001' -e 'SOAK_DURATION=10m' -v $mount -w /work grafana/k6:0.53.0 run --summary-export "/work/reports/k6-$profile.json" /work/scripts/load.k6.js | Tee-Object "reports/k6-$profile.stdout"
    if ($LASTEXITCODE -ne 0) { throw "k6 $profile failed" }
  }
  docker run --rm --network shield-verify_default -v "${repoRoot}/reports:/zap/wrk/:rw" zaproxy/zap-stable zap-baseline.py -t http://app:80 -J zap-baseline.json | Tee-Object reports/zap-baseline.stdout
  if ($LASTEXITCODE -ne 0) { throw 'ZAP baseline scan failed' }
  docker run --rm --network shield-verify_default -v "${repoRoot}/reports:/zap/wrk/:rw" zaproxy/zap-stable zap-api-scan.py -t http://api:3001/openapi.yaml -f openapi -J zap-api.json | Tee-Object reports/zap-api.stdout
  if ($LASTEXITCODE -ne 0) { throw 'ZAP API scan failed' }
  Write-Host "Verification completed. Reports are in $env:REPORT_DIR"
} finally {
  docker compose -f $env:COMPOSE_FILE -p $env:COMPOSE_PROJECT_NAME logs --no-color | Set-Content reports/compose.log
  docker compose -f $env:COMPOSE_FILE -p $env:COMPOSE_PROJECT_NAME down --volumes --remove-orphans
}
