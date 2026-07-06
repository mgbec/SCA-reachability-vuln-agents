# Build and push all agent Docker images to ECR.
#
# Usage:
#   .\scripts\build_and_push.ps1 [-Region us-east-1] [-AccountId 339712707840]

param(
    [string]$Region = "us-east-1",
    [string]$AccountId = "339712707840"
)

$ErrorActionPreference = "Stop"

$ECR_REGISTRY = "${AccountId}.dkr.ecr.${Region}.amazonaws.com"
$PROJECT = "agentcore-reachability-sca-prod"

$ORCHESTRATOR_REPO = "${ECR_REGISTRY}/${PROJECT}/sca-orchestrator"
$SCANNER_REPO = "${ECR_REGISTRY}/${PROJECT}/sca-scanner"
$ANALYSIS_REPO = "${ECR_REGISTRY}/${PROJECT}/sca-analysis"

Write-Host "==> Logging into ECR (${ECR_REGISTRY})..." -ForegroundColor Cyan
aws ecr get-login-password --region $Region | docker login --username AWS --password-stdin $ECR_REGISTRY

Write-Host ""
Write-Host "==> Building orchestrator image..." -ForegroundColor Cyan
docker build --platform linux/arm64 -t sca-orchestrator:latest -f Dockerfile.orchestrator .

Write-Host ""
Write-Host "==> Building scanner image..." -ForegroundColor Cyan
docker build --platform linux/arm64 -t sca-scanner:latest -f Dockerfile.scanner .

Write-Host ""
Write-Host "==> Building analysis image..." -ForegroundColor Cyan
docker build --platform linux/arm64 -t sca-analysis:latest -f Dockerfile.analysis .

Write-Host ""
Write-Host "==> Tagging images..." -ForegroundColor Cyan
docker tag sca-orchestrator:latest "${ORCHESTRATOR_REPO}:latest"
docker tag sca-scanner:latest "${SCANNER_REPO}:latest"
docker tag sca-analysis:latest "${ANALYSIS_REPO}:latest"

Write-Host ""
Write-Host "==> Pushing orchestrator image..." -ForegroundColor Cyan
docker push "${ORCHESTRATOR_REPO}:latest"

Write-Host ""
Write-Host "==> Pushing scanner image..." -ForegroundColor Cyan
docker push "${SCANNER_REPO}:latest"

Write-Host ""
Write-Host "==> Pushing analysis image..." -ForegroundColor Cyan
docker push "${ANALYSIS_REPO}:latest"

Write-Host ""
Write-Host "==> Done! All images pushed to ECR." -ForegroundColor Green
Write-Host "    Orchestrator: ${ORCHESTRATOR_REPO}:latest"
Write-Host "    Scanner:      ${SCANNER_REPO}:latest"
Write-Host "    Analysis:     ${ANALYSIS_REPO}:latest"
