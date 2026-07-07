# Set environment variables for the SCA Demo CLI from Terraform outputs.
#
# Usage (from project root):
#   . .\scripts\set_env.ps1
#
# Note: Use dot-sourcing (.) so variables persist in your current session.

param(
    [string]$TerraformDir = "terraform"
)

$ErrorActionPreference = "Stop"

Write-Host "Loading environment from Terraform outputs..." -ForegroundColor Cyan

Push-Location $TerraformDir

try {
    # Cognito
    $env:AGENTCORE_COGNITO_ENDPOINT = terraform output -raw cognito_user_pool_endpoint 2>$null
    $env:AGENTCORE_COGNITO_CLIENT_ID = terraform output -raw cognito_client_id 2>$null

    # Agent Runtime Endpoint ARNs (used to derive invoke URLs)
    $orchestratorId = terraform output -raw orchestrator_agent_runtime_id 2>$null
    $scannerId = terraform output -raw scanner_agent_runtime_id 2>$null
    $analysisId = terraform output -raw analysis_agent_runtime_id 2>$null

    # Construct invoke URLs from runtime IDs
    # AgentCore Runtime endpoint format: https://bedrock-agentcore.{region}.amazonaws.com/runtimes/{id}/invoke
    $region = "us-east-1"
    $baseUrl = "https://bedrock-agentcore.${region}.amazonaws.com"

    $env:AGENTCORE_ORCHESTRATOR_ENDPOINT = "${baseUrl}/runtimes/${orchestratorId}"
    $env:AGENTCORE_SCANNER_ENDPOINT = "${baseUrl}/runtimes/${scannerId}"
    $env:AGENTCORE_ANALYSIS_ENDPOINT = "${baseUrl}/runtimes/${analysisId}"
}
finally {
    Pop-Location
}

Write-Host ""
Write-Host "Environment configured:" -ForegroundColor Green
Write-Host "  AGENTCORE_COGNITO_ENDPOINT     = $env:AGENTCORE_COGNITO_ENDPOINT"
Write-Host "  AGENTCORE_COGNITO_CLIENT_ID    = $env:AGENTCORE_COGNITO_CLIENT_ID"
Write-Host "  AGENTCORE_ORCHESTRATOR_ENDPOINT = $env:AGENTCORE_ORCHESTRATOR_ENDPOINT"
Write-Host "  AGENTCORE_SCANNER_ENDPOINT     = $env:AGENTCORE_SCANNER_ENDPOINT"
Write-Host "  AGENTCORE_ANALYSIS_ENDPOINT    = $env:AGENTCORE_ANALYSIS_ENDPOINT"
Write-Host ""
Write-Host "Run 'sca-demo authenticate' to test." -ForegroundColor Cyan
