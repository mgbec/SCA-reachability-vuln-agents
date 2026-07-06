#!/usr/bin/env bash
# Build and push all agent Docker images to ECR.
#
# Usage:
#   ./scripts/build_and_push.sh [REGION] [ACCOUNT_ID]
#
# Parameters:
#   REGION     - AWS region (default: us-east-1)
#   ACCOUNT_ID - AWS account ID (default: 339712707840)

set -euo pipefail

REGION="${1:-us-east-1}"
ACCOUNT_ID="${2:-339712707840}"

ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"
PROJECT="agentcore-reachability-sca-prod"

ORCHESTRATOR_REPO="${ECR_REGISTRY}/${PROJECT}/sca-orchestrator"
SCANNER_REPO="${ECR_REGISTRY}/${PROJECT}/sca-scanner"
ANALYSIS_REPO="${ECR_REGISTRY}/${PROJECT}/sca-analysis"

echo "==> Logging into ECR (${ECR_REGISTRY})..."
aws ecr get-login-password --region "${REGION}" | \
  docker login --username AWS --password-stdin "${ECR_REGISTRY}"

echo ""
echo "==> Building orchestrator image..."
docker build -t sca-orchestrator:latest -f Dockerfile.orchestrator .

echo ""
echo "==> Building scanner image..."
docker build -t sca-scanner:latest -f Dockerfile.scanner .

echo ""
echo "==> Building analysis image..."
docker build -t sca-analysis:latest -f Dockerfile.analysis .

echo ""
echo "==> Tagging images..."
docker tag sca-orchestrator:latest "${ORCHESTRATOR_REPO}:latest"
docker tag sca-scanner:latest "${SCANNER_REPO}:latest"
docker tag sca-analysis:latest "${ANALYSIS_REPO}:latest"

echo ""
echo "==> Pushing orchestrator image..."
docker push "${ORCHESTRATOR_REPO}:latest"

echo ""
echo "==> Pushing scanner image..."
docker push "${SCANNER_REPO}:latest"

echo ""
echo "==> Pushing analysis image..."
docker push "${ANALYSIS_REPO}:latest"

echo ""
echo "==> Done! All images pushed to ECR."
echo "    Orchestrator: ${ORCHESTRATOR_REPO}:latest"
echo "    Scanner:      ${SCANNER_REPO}:latest"
echo "    Analysis:     ${ANALYSIS_REPO}:latest"
