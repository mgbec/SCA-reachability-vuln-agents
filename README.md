# Reachability-Enhanced SCA Security Platform

A multi-agent security platform that performs **reachability-enhanced Software Composition Analysis (SCA)** using Amazon Bedrock AgentCore Identity. The platform combines traditional dependency scanning with static call graph analysis to identify which vulnerabilities in a project's dependencies are actually reachable from the application's code.

## Overview

Traditional SCA tools report all known vulnerabilities in your dependency tree regardless of whether they're exploitable. This creates alert fatigue — teams waste time patching unreachable code. This platform solves that by tracing call paths from your application's entry points through the dependency graph, producing **exploitability scores** that reflect actual risk.

### Key Outputs

- **Enriched CycloneDX SBOM** — Software Bill of Materials with reachability status per component
- **Exploitability Scores** — CVSS × reachability multiplier (reachable=1.0, unreachable=0.2, indeterminate=0.6)
- **Prioritized Findings** — Sorted by actual exploitability, not raw CVSS
- **Fix Recommendations** — Minimum safe version upgrades, grouped by dependency, with breaking change detection

## Architecture

```
User → Demo CLI → Cognito (JWT)
                → Orchestrator Agent (JWT validation, identity propagation)
                    → Scanner Agent (GitHub OAuth: security_events, repo)
                        → GitHub API (Dependabot alerts, manifests, source code)
                    → Analysis Agent (M2M client credentials)
                        → Vulnerability DBs (NVD, OSV, GHSA)
                        → tree-sitter (call graph analysis)

Observability (direct export, no Collector sidecar):
  Each Agent → AWS X-Ray (traces via ADOT layer)
            → CloudWatch (metrics via EMF, logs via structured logging)
```

Three agents deployed as separate AgentCore Runtime instances:

| Agent | Role | Auth Method |
|-------|------|-------------|
| **Orchestrator** | Coordinates pipeline, validates JWTs, propagates identity | JWT Bearer + mTLS outbound |
| **Scanner** | Fetches GitHub data (alerts, manifests, source) | User-delegated OAuth with PKCE (AuthZ Code Grant) |
| **Analysis** | Call graph analysis, scoring, recommendations | M2M (Client Credentials Grant) |

All inter-agent communication is secured with **mutual TLS** and **HMAC-signed identity context** propagation.

## Quick Start

### Prerequisites

- Python 3.11+
- AWS credentials configured (for Secrets Manager, deployment)
- Terraform 1.5+ (for infrastructure provisioning)

### Installation

```bash
pip install -e ".[dev]"
```

### Run Tests

```bash
# All tests (unit + property + integration + smoke)
pytest tests/

# Property-based tests only
pytest tests/properties/ -m property

# Integration tests only
pytest tests/integration/ -m integration

# Smoke tests (requires deployed infrastructure)
pytest tests/smoke/ -m smoke
```

### CLI Usage

```bash
# Authenticate using Device Authorization Grant (OAuth 2.1 default)
sca-demo authenticate

# Legacy authentication (deprecated, shows warning)
sca-demo authenticate --legacy --username <user> --password <pass>

# Run full demo (all 5 workflows)
sca-demo run-demo --username <user> --password <pass>

# Individual workflows
sca-demo user-delegated --token <jwt>
sca-demo m2m
sca-demo delegation --token <jwt>
sca-demo full-analysis --token <jwt>

# Verbose mode (shows decoded JWTs, HTTP headers, OAuth exchanges)
sca-demo -v run-demo --username <user> --password <pass>
```

### Configuration

Configuration follows CLI args > environment variables precedence:

| CLI Argument | Environment Variable | Description |
|---|---|---|
| `--orchestrator-endpoint` | `AGENTCORE_ORCHESTRATOR_ENDPOINT` | Orchestrator Agent URL |
| `--scanner-endpoint` | `AGENTCORE_SCANNER_ENDPOINT` | Scanner Agent URL |
| `--analysis-endpoint` | `AGENTCORE_ANALYSIS_ENDPOINT` | Analysis Agent URL |
| `--cognito-endpoint` | `AGENTCORE_COGNITO_ENDPOINT` | Cognito User Pool URL |
| `--cognito-client-id` | `AGENTCORE_COGNITO_CLIENT_ID` | Cognito Client ID |

## Infrastructure

Infrastructure is fully defined as Terraform code:

```
terraform/
├── main.tf              # Provider, backend
├── variables.tf         # Input variables
├── outputs.tf           # Endpoints for CLI
├── backend.tf           # S3 + KMS state encryption
├── bootstrap/           # One-time state backend setup
│   └── main.tf          # Creates S3 bucket, KMS key, DynamoDB lock table
└── modules/
    ├── cognito/         # User pool, client, test user
    ├── agentcore/       # Runtime instances, identity directory
    ├── iam/             # Least-privilege roles per agent
    ├── certificates/    # Internal CA, per-agent mTLS certs
    ├── secrets/         # Secrets Manager + rotation
    ├── observability/   # CloudWatch dashboard, alarms, log groups
    └── networking/      # VPC, security groups
```

### Bootstrap (one-time)

Before deploying infrastructure, you need to create the Terraform state backend resources (S3 bucket with KMS encryption + DynamoDB lock table):

```bash
cd terraform/bootstrap
terraform init
terraform apply
```

Then switch to the remote backend:

1. Edit `terraform/backend.tf` — uncomment the S3 backend block, remove the local backend block
2. Run:
```bash
cd terraform
terraform init -migrate-state
```

### Deploy

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

### Destroy

```bash
terraform destroy
```

## Security Model

### Authentication Layers

1. **User → Platform**: Cognito OAuth 2.1 Authorization Code Grant with PKCE → JWT
2. **CLI → Platform**: Device Authorization Grant (RFC 8628) — no passwords transmitted
3. **Agent → Agent**: Mutual TLS (X.509 client certificates from internal CA)
4. **Agent → GitHub**: User-delegated OAuth with PKCE (scopes: `security_events`, `repo`)
5. **Agent → Vuln DBs**: M2M Client Credentials Grant
6. **Identity Propagation**: HMAC-SHA256 signed context envelope across boundaries

### OAuth 2.1 Compliance

This platform implements OAuth 2.1 (draft-ietf-oauth-v2-1) with the following changes from OAuth 2.0:

- **PKCE mandatory** on all authorization code flows (S256 challenge method)
- **Device Authorization Grant** (RFC 8628) for CLI authentication — no passwords
- **Refresh token rotation** with replay detection (used tokens are rejected)
- **Implicit grant formally unsupported** — removed per OAuth 2.1
- **Resource Owner Password Credentials (ROPC) formally unsupported** — removed per OAuth 2.1

### Secrets Management

- All secrets stored in AWS Secrets Manager (never hardcoded)
- HMAC signing keys, OAuth client secrets, cert private keys
- Retrieved at agent startup with exponential backoff retry
- Terraform state encrypted with S3 + KMS, locked via DynamoDB

### Observability

- OpenTelemetry SDK instrumentation → direct AWS export (no Collector sidecar required)
- Traces → AWS X-Ray (via ADOT layer with X-Ray ID generator + propagator)
- Metrics → CloudWatch EMF (via ADOT layer OTLP endpoint)
- Logs → CloudWatch Logs (structured JSON, 90-day retention)
- Auth failure rate alarm (configurable threshold, default 10%)
- Graceful degradation: works without AWS backends locally (in-memory/console fallback)

## Scoring Algorithm

```
exploitability_score = cvss_base_score × reachability_multiplier

reachability_multiplier:
  reachable     = 1.0   (path exists from entry point)
  unreachable   = 0.2   (no path found)
  indeterminate = 0.6   (dynamic dispatch, reflection, etc.)

Priority Tiers:
  Critical  ≥ 9.0
  High      7.0 – 8.9
  Medium    4.0 – 6.9
  Low       < 4.0
```

**Example**: CVE with CVSS 9.8 + unreachable → 9.8 × 0.2 = 1.96 (Low priority)

## Supported Languages

Call graph analysis via tree-sitter supports:
- JavaScript / TypeScript
- Python
- Java
- Go
- Rust

## Supported Manifest Formats

- `package.json` (npm)
- `requirements.txt` (pip)
- `pom.xml` (Maven)
- `go.mod` (Go modules)
- `Cargo.toml` (Rust/Cargo)

## Project Structure

```
src/
├── agents/          # Agent implementations (Orchestrator, Scanner, Analysis)
├── cli/             # Click-based demo CLI
├── core/            # Shared libraries (identity, auth, telemetry, retry)
└── sca/             # SCA-specific (call graph, SBOM, scoring, recommendations)

tests/
├── properties/      # Hypothesis property-based tests (19 properties)
├── integration/     # Integration tests (mTLS, OAuth, pipeline)
├── smoke/           # Infrastructure validation tests
└── unit/            # Unit tests

terraform/           # Infrastructure as Code (modular Terraform)
```

## License

See [LICENSE](LICENSE) for details.
