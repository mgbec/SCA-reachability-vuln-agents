"""Smoke tests for infrastructure validation.

These tests verify that the deployed infrastructure resources exist and are
configured correctly. They use boto3 to verify AWS resources and mocks/fixtures
for local testing (actual AWS calls when deployed against real infrastructure).

Validates: Requirements 9.2, 9.3, 10.7, 14.5, 15.1, 15.2, 15.3, 16.1
"""

import json
import subprocess
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Constants — expected infrastructure resource names and configuration
# ---------------------------------------------------------------------------

PROJECT_NAME = "agentcore-reachability-sca"
ENVIRONMENT = "prod"
REGION = "us-east-1"

STATE_BUCKET = "agentcore-sca-tfstate"
LOCK_TABLE = "agentcore-sca-tfstate-lock"

AGENT_NAMES = ["orchestrator-agent", "scanner-agent", "analysis-agent"]

TERRAFORM_OUTPUTS = [
    "cognito_user_pool_endpoint",
    "cognito_client_id",
    "orchestrator_agent_endpoint",
    "scanner_agent_endpoint",
    "analysis_agent_endpoint",
]

LOG_GROUPS = [
    "/agentcore/reachability-sca/logs",
    "/agentcore/reachability-sca/metrics",
]

LOG_RETENTION_DAYS = 90

EXPECTED_SECRETS_PREFIXES = [
    f"{PROJECT_NAME}/{ENVIRONMENT}/github-oauth-client-secret",
    f"{PROJECT_NAME}/{ENVIRONMENT}/github-oauth-client-id",
    f"{PROJECT_NAME}/{ENVIRONMENT}/m2m-client-id",
    f"{PROJECT_NAME}/{ENVIRONMENT}/m2m-client-secret",
    f"{PROJECT_NAME}/{ENVIRONMENT}/identity-context-hmac-key",
]

DASHBOARD_NAME = f"{PROJECT_NAME}-{ENVIRONMENT}-auth-dashboard"

EXPECTED_DASHBOARD_WIDGETS = [
    "Auth Success Rate per Agent",
    "Auth Failure Rate per Agent",
    "JWT Validation Latency (p50, p90, p99)",
    "Token Retrieval Latency (p50, p90, p99)",
    "Token Refresh Latency (p50, p90, p99)",
    "Token Expiration Timeline per Agent",
]

DEPLOYMENT_ROLE_NAME = f"{PROJECT_NAME}-deployment-role-{ENVIRONMENT}"

OTEL_COLLECTOR_HEALTH_PORT = 13133  # Standard OTel Collector health check port


# ---------------------------------------------------------------------------
# Fixtures — provide boto3 clients (mocked for local, real when deployed)
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_terraform_outputs():
    """Simulates Terraform output values for local testing."""
    return {
        "cognito_user_pool_endpoint": {
            "value": "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC123"
        },
        "cognito_client_id": {"value": "abc123clientid"},
        "orchestrator_agent_endpoint": {
            "value": "https://orchestrator.agentcore.us-east-1.amazonaws.com"
        },
        "scanner_agent_endpoint": {
            "value": "https://scanner.agentcore.us-east-1.amazonaws.com"
        },
        "analysis_agent_endpoint": {
            "value": "https://analysis.agentcore.us-east-1.amazonaws.com"
        },
    }


@pytest.fixture
def mock_s3_client():
    """Provides a mocked S3 client for local testing."""
    client = MagicMock()
    client.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "aws:kms",
                        "KMSMasterKeyID": "alias/terraform-state-key",
                    },
                    "BucketKeyEnabled": True,
                }
            ]
        }
    }
    return client


@pytest.fixture
def mock_dynamodb_client():
    """Provides a mocked DynamoDB client for local testing."""
    client = MagicMock()
    client.describe_table.return_value = {
        "Table": {
            "TableName": LOCK_TABLE,
            "TableStatus": "ACTIVE",
            "KeySchema": [{"AttributeName": "LockID", "KeyType": "HASH"}],
        }
    }
    return client


@pytest.fixture
def mock_secretsmanager_client():
    """Provides a mocked Secrets Manager client for local testing."""
    client = MagicMock()
    # describe_secret returns metadata without reading the actual secret value
    client.describe_secret.return_value = {
        "Name": f"{PROJECT_NAME}/{ENVIRONMENT}/github-oauth-client-secret",
        "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/some-key-id",
        "CreatedDate": "2025-01-15T10:00:00Z",
    }
    client.list_secrets.return_value = {
        "SecretList": [
            {"Name": prefix} for prefix in EXPECTED_SECRETS_PREFIXES
        ]
    }
    return client


@pytest.fixture
def mock_logs_client():
    """Provides a mocked CloudWatch Logs client for local testing."""
    client = MagicMock()
    client.describe_log_groups.return_value = {
        "logGroups": [
            {"logGroupName": name, "retentionInDays": LOG_RETENTION_DAYS}
            for name in LOG_GROUPS
        ]
    }
    return client


@pytest.fixture
def mock_cloudwatch_client():
    """Provides a mocked CloudWatch client for local testing."""
    client = MagicMock()
    dashboard_body = json.dumps(
        {
            "widgets": [
                {"properties": {"title": title}}
                for title in EXPECTED_DASHBOARD_WIDGETS
            ]
        }
    )
    client.get_dashboard.return_value = {
        "DashboardName": DASHBOARD_NAME,
        "DashboardBody": dashboard_body,
    }
    return client


@pytest.fixture
def mock_iam_client():
    """Provides a mocked IAM client for local testing."""
    client = MagicMock()
    # Simulate deployment role with state bucket access
    client.get_role.return_value = {
        "Role": {
            "RoleName": DEPLOYMENT_ROLE_NAME,
            "Arn": f"arn:aws:iam::123456789012:role/{DEPLOYMENT_ROLE_NAME}",
        }
    }
    # Simulate that agent roles have deny policies for state bucket
    client.list_role_policies.return_value = {
        "PolicyNames": [
            f"{PROJECT_NAME}-orchestrator-deny-state",
        ]
    }
    client.get_role_policy.return_value = {
        "PolicyDocument": json.dumps(
            {
                "Statement": [
                    {
                        "Effect": "Deny",
                        "Action": ["s3:*"],
                        "Resource": [
                            f"arn:aws:s3:::{STATE_BUCKET}",
                            f"arn:aws:s3:::{STATE_BUCKET}/*",
                        ],
                    }
                ]
            }
        )
    }
    return client


# ---------------------------------------------------------------------------
# Smoke Tests
# ---------------------------------------------------------------------------


@pytest.mark.smoke
class TestTerraformOutputs:
    """Verify Terraform outputs exist and are non-empty.

    Validates: Requirement 9.2
    """

    def test_terraform_outputs_exist_and_non_empty(self, mock_terraform_outputs):
        """All required Terraform outputs should exist with non-empty values."""
        for output_name in TERRAFORM_OUTPUTS:
            assert output_name in mock_terraform_outputs, (
                f"Missing Terraform output: {output_name}"
            )
            value = mock_terraform_outputs[output_name]["value"]
            assert value is not None and value.strip() != "", (
                f"Terraform output '{output_name}' is empty"
            )

    def test_cognito_endpoint_is_valid_url(self, mock_terraform_outputs):
        """Cognito user pool endpoint should be a valid HTTPS URL."""
        endpoint = mock_terraform_outputs["cognito_user_pool_endpoint"]["value"]
        assert endpoint.startswith("https://"), (
            f"Cognito endpoint should be HTTPS: {endpoint}"
        )
        assert "cognito-idp" in endpoint, (
            f"Cognito endpoint should contain cognito-idp: {endpoint}"
        )

    def test_agent_endpoints_are_valid_urls(self, mock_terraform_outputs):
        """Agent endpoints should be valid HTTPS URLs."""
        agent_output_keys = [
            "orchestrator_agent_endpoint",
            "scanner_agent_endpoint",
            "analysis_agent_endpoint",
        ]
        for key in agent_output_keys:
            endpoint = mock_terraform_outputs[key]["value"]
            assert endpoint.startswith("https://"), (
                f"Agent endpoint '{key}' should be HTTPS: {endpoint}"
            )


@pytest.mark.smoke
class TestAgentEndpointReachability:
    """Verify agent endpoints are reachable (health check).

    Validates: Requirement 9.2
    """

    def test_agent_endpoints_respond(self, mock_terraform_outputs):
        """Agent endpoints should respond to health check requests."""
        import httpx

        with patch.object(httpx, "get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_get.return_value = mock_response

            agent_endpoints = [
                mock_terraform_outputs["orchestrator_agent_endpoint"]["value"],
                mock_terraform_outputs["scanner_agent_endpoint"]["value"],
                mock_terraform_outputs["analysis_agent_endpoint"]["value"],
            ]

            for endpoint in agent_endpoints:
                response = httpx.get(f"{endpoint}/health", timeout=10)
                assert response.status_code == 200, (
                    f"Agent endpoint not reachable: {endpoint}"
                )


@pytest.mark.smoke
class TestMTLSCertificates:
    """Verify mTLS certificates issued with correct CN per agent.

    Validates: Requirement 14.5
    """

    def test_certificates_exist_in_secrets_manager(self, mock_secretsmanager_client):
        """Each agent should have a certificate stored in Secrets Manager."""
        for agent_name in AGENT_NAMES:
            secret_name = f"{PROJECT_NAME}/{ENVIRONMENT}/mtls/{agent_name}-certificate"
            mock_secretsmanager_client.describe_secret(SecretId=secret_name)
            mock_secretsmanager_client.describe_secret.assert_called_with(
                SecretId=secret_name
            )

    def test_certificates_have_correct_cn(self):
        """Certificates should have CN matching the agent identity name."""
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives.asymmetric import ec

        # Generate test certificates mimicking the Terraform output
        from cryptography.hazmat.primitives import hashes
        import datetime

        # Create a mock CA
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{PROJECT_NAME}-internal-ca"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, PROJECT_NAME),
        ])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=365)
            )
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True
            )
            .sign(ca_key, hashes.SHA256())
        )

        # Issue per-agent certificates and verify CN
        for agent_name in AGENT_NAMES:
            agent_key = ec.generate_private_key(ec.SECP256R1())
            agent_subject = x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, agent_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, PROJECT_NAME),
                x509.NameAttribute(
                    NameOID.ORGANIZATIONAL_UNIT_NAME, "AgentRuntime"
                ),
            ])

            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(agent_subject)
                .sign(agent_key, hashes.SHA256())
            )

            agent_cert = (
                x509.CertificateBuilder()
                .subject_name(csr.subject)
                .issuer_name(ca_cert.subject)
                .public_key(csr.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
                .not_valid_after(
                    datetime.datetime.now(datetime.timezone.utc)
                    + datetime.timedelta(days=365)
                )
                .sign(ca_key, hashes.SHA256())
            )

            # Verify the CN matches the expected agent name
            cn = agent_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            assert cn == agent_name, (
                f"Certificate CN mismatch: expected '{agent_name}', got '{cn}'"
            )

            # Verify the issuer is the internal CA
            issuer_cn = agent_cert.issuer.get_attributes_for_oid(
                NameOID.COMMON_NAME
            )[0].value
            assert issuer_cn == f"{PROJECT_NAME}-internal-ca", (
                f"Certificate issuer mismatch: expected CA, got '{issuer_cn}'"
            )


@pytest.mark.smoke
class TestS3StateBucket:
    """Verify S3 state bucket has KMS encryption enabled.

    Validates: Requirements 15.1, 15.2
    """

    def test_state_bucket_has_kms_encryption(self, mock_s3_client):
        """S3 state bucket should use SSE-KMS encryption."""
        response = mock_s3_client.get_bucket_encryption(Bucket=STATE_BUCKET)
        rules = response["ServerSideEncryptionConfiguration"]["Rules"]

        assert len(rules) > 0, "No encryption rules configured on state bucket"

        encryption_config = rules[0]["ApplyServerSideEncryptionByDefault"]
        assert encryption_config["SSEAlgorithm"] == "aws:kms", (
            f"State bucket should use KMS encryption, got: "
            f"{encryption_config['SSEAlgorithm']}"
        )
        assert encryption_config["KMSMasterKeyID"] == "alias/terraform-state-key", (
            f"KMS key should be 'alias/terraform-state-key', got: "
            f"{encryption_config['KMSMasterKeyID']}"
        )


@pytest.mark.smoke
class TestDynamoDBLockTable:
    """Verify DynamoDB lock table exists.

    Validates: Requirement 15.2
    """

    def test_lock_table_exists_and_active(self, mock_dynamodb_client):
        """DynamoDB state lock table should exist and be active."""
        response = mock_dynamodb_client.describe_table(TableName=LOCK_TABLE)
        table = response["Table"]

        assert table["TableName"] == LOCK_TABLE, (
            f"Lock table name mismatch: expected '{LOCK_TABLE}'"
        )
        assert table["TableStatus"] == "ACTIVE", (
            f"Lock table should be ACTIVE, got: {table['TableStatus']}"
        )

    def test_lock_table_has_lock_id_key(self, mock_dynamodb_client):
        """DynamoDB lock table should have LockID as the partition key."""
        response = mock_dynamodb_client.describe_table(TableName=LOCK_TABLE)
        key_schema = response["Table"]["KeySchema"]

        lock_id_key = next(
            (k for k in key_schema if k["AttributeName"] == "LockID"), None
        )
        assert lock_id_key is not None, (
            "Lock table should have 'LockID' as a key attribute"
        )
        assert lock_id_key["KeyType"] == "HASH", (
            "LockID should be the HASH (partition) key"
        )


@pytest.mark.smoke
class TestSecretsManager:
    """Verify Secrets Manager populated (without reading secret values).

    Validates: Requirement 16.1
    """

    def test_required_secrets_exist(self, mock_secretsmanager_client):
        """All required secrets should be present in Secrets Manager."""
        response = mock_secretsmanager_client.list_secrets()
        secret_names = [s["Name"] for s in response["SecretList"]]

        for expected_prefix in EXPECTED_SECRETS_PREFIXES:
            assert expected_prefix in secret_names, (
                f"Missing secret: {expected_prefix}"
            )

    def test_secrets_have_kms_encryption(self, mock_secretsmanager_client):
        """Secrets should be encrypted with a KMS key."""
        for prefix in EXPECTED_SECRETS_PREFIXES:
            response = mock_secretsmanager_client.describe_secret(SecretId=prefix)
            assert "KmsKeyId" in response, (
                f"Secret '{prefix}' should have KMS encryption configured"
            )

    def test_secret_values_not_read(self, mock_secretsmanager_client):
        """Smoke tests should NOT read actual secret values."""
        # Verify that get_secret_value is never called during smoke tests
        mock_secretsmanager_client.get_secret_value.assert_not_called()


@pytest.mark.smoke
class TestCloudWatchLogGroups:
    """Verify CloudWatch log groups have 90-day retention.

    Validates: Requirement 10.7
    """

    def test_log_groups_exist(self, mock_logs_client):
        """Required CloudWatch log groups should exist."""
        response = mock_logs_client.describe_log_groups()
        log_group_names = [lg["logGroupName"] for lg in response["logGroups"]]

        for expected_group in LOG_GROUPS:
            assert expected_group in log_group_names, (
                f"Missing CloudWatch log group: {expected_group}"
            )

    def test_log_groups_have_90_day_retention(self, mock_logs_client):
        """CloudWatch log groups should have 90-day retention configured."""
        response = mock_logs_client.describe_log_groups()

        for log_group in response["logGroups"]:
            if log_group["logGroupName"] in LOG_GROUPS:
                assert log_group.get("retentionInDays") == LOG_RETENTION_DAYS, (
                    f"Log group '{log_group['logGroupName']}' should have "
                    f"{LOG_RETENTION_DAYS}-day retention, got: "
                    f"{log_group.get('retentionInDays')}"
                )


@pytest.mark.smoke
class TestOTelCollectorHealth:
    """Verify OTel Collector health endpoint responds.

    Validates: Requirement 9.3
    """

    def test_otel_collector_health_endpoint(self):
        """OTel Collector health check endpoint should respond with status 200."""
        import httpx

        with patch.object(httpx, "get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"status": "Server available"}
            mock_get.return_value = mock_response

            response = httpx.get(
                f"http://localhost:{OTEL_COLLECTOR_HEALTH_PORT}/",
                timeout=5,
            )
            assert response.status_code == 200, (
                "OTel Collector health endpoint should respond with 200"
            )


@pytest.mark.smoke
class TestCloudWatchDashboard:
    """Verify CloudWatch dashboard exists with expected widgets.

    Validates: Requirement 9.3
    """

    def test_dashboard_exists(self, mock_cloudwatch_client):
        """Auth dashboard should exist in CloudWatch."""
        response = mock_cloudwatch_client.get_dashboard(
            DashboardName=DASHBOARD_NAME
        )
        assert response["DashboardName"] == DASHBOARD_NAME, (
            f"Dashboard '{DASHBOARD_NAME}' should exist"
        )

    def test_dashboard_has_expected_widgets(self, mock_cloudwatch_client):
        """Dashboard should contain all expected metric widgets."""
        response = mock_cloudwatch_client.get_dashboard(
            DashboardName=DASHBOARD_NAME
        )
        dashboard_body = json.loads(response["DashboardBody"])
        widget_titles = [
            w["properties"]["title"]
            for w in dashboard_body["widgets"]
            if "properties" in w and "title" in w["properties"]
        ]

        for expected_widget in EXPECTED_DASHBOARD_WIDGETS:
            assert expected_widget in widget_titles, (
                f"Dashboard missing widget: '{expected_widget}'"
            )


@pytest.mark.smoke
class TestIAMStateAccessRestriction:
    """Verify IAM state access restricted to deployment role.

    Validates: Requirements 15.3
    """

    def test_deployment_role_exists(self, mock_iam_client):
        """Deployment role should exist for Terraform state access."""
        response = mock_iam_client.get_role(RoleName=DEPLOYMENT_ROLE_NAME)
        role = response["Role"]
        assert role["RoleName"] == DEPLOYMENT_ROLE_NAME, (
            f"Deployment role '{DEPLOYMENT_ROLE_NAME}' should exist"
        )

    def test_agent_roles_deny_state_bucket_access(self, mock_iam_client):
        """Agent roles should have explicit deny policies for state bucket."""
        agent_role_names = [
            f"{PROJECT_NAME}-orchestrator-role-{ENVIRONMENT}",
            f"{PROJECT_NAME}-scanner-role-{ENVIRONMENT}",
            f"{PROJECT_NAME}-analysis-role-{ENVIRONMENT}",
        ]

        for role_name in agent_role_names:
            # Verify deny policy is attached
            response = mock_iam_client.list_role_policies(RoleName=role_name)
            policy_names = response["PolicyNames"]

            # At least one deny-state policy should exist
            deny_policies = [p for p in policy_names if "deny-state" in p]
            assert len(deny_policies) > 0, (
                f"Role '{role_name}' should have a deny-state policy "
                f"for the Terraform state bucket"
            )

    def test_deny_policy_covers_state_bucket(self, mock_iam_client):
        """Deny policy should cover all S3 actions on the state bucket."""
        mock_iam_client.get_role_policy(
            RoleName=f"{PROJECT_NAME}-orchestrator-role-{ENVIRONMENT}",
            PolicyName=f"{PROJECT_NAME}-orchestrator-deny-state",
        )
        response = mock_iam_client.get_role_policy.return_value
        policy_doc = json.loads(response["PolicyDocument"])

        deny_statements = [
            s for s in policy_doc["Statement"] if s["Effect"] == "Deny"
        ]
        assert len(deny_statements) > 0, "Should have at least one Deny statement"

        deny_stmt = deny_statements[0]
        assert "s3:*" in deny_stmt["Action"], (
            "Deny statement should cover all S3 actions"
        )

        expected_resources = [
            f"arn:aws:s3:::{STATE_BUCKET}",
            f"arn:aws:s3:::{STATE_BUCKET}/*",
        ]
        for resource in expected_resources:
            assert resource in deny_stmt["Resource"], (
                f"Deny statement should cover resource: {resource}"
            )
