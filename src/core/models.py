"""Core data models for AgentCore Identity and authentication workflows.

Defines dataclasses for identity context propagation, user identity,
workload identity, delegation chains, token management, and scope configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class WorkloadIdentity:
    """Represents an agent's workload identity registered in AgentCore Identity Directory.

    Attributes:
        arn: Unique ARN following the pattern
             arn:aws:bedrock-agentcore:{region}:{account}:workload-identity/directory/default/workload-identity/{agent-name}
        name: Human-readable agent name (e.g., "orchestrator-agent").
    """

    arn: str
    name: str


@dataclass(frozen=True)
class UserIdentity:
    """Represents the authenticated end-user identity propagated across agent boundaries.

    Attributes:
        subject: User subject claim from the JWT (sub).
        issuer: Token issuer URL (iss), e.g., Cognito user pool endpoint.
        audience: Intended audience for the token (aud).
        scopes: List of granted OAuth scopes.
        issued_at: Timestamp when the token was issued (ISO 8601).
        expires_at: Timestamp when the token expires (ISO 8601).
        token_reference: JTI or hash reference to the original token.
    """

    subject: str
    issuer: str
    audience: str
    scopes: list[str]
    issued_at: datetime
    expires_at: datetime
    token_reference: str


@dataclass(frozen=True)
class DelegationEntry:
    """Records a single delegation hop in the agent-to-agent propagation chain.

    Attributes:
        agent_arn: ARN of the agent that delegated the task.
        delegated_at: Timestamp when the delegation occurred (ISO 8601).
    """

    agent_arn: str
    delegated_at: datetime


@dataclass
class IdentityContext:
    """Complete identity context envelope passed between agents during delegation.

    Contains the source agent identity, propagated user identity, delegation
    chain for audit trail, and an HMAC-SHA256 signature for tamper detection.

    Attributes:
        version: Schema version of the identity context (e.g., "1.0").
        correlation_id: UUID v4 correlation ID for distributed tracing.
        source_agent: Workload identity of the agent that constructed this context.
        user_identity: Propagated end-user identity claims.
        delegation_chain: Ordered list of delegation hops for audit trail.
        signature: Base64-encoded HMAC-SHA256 signature over serialized context fields.
    """

    version: str
    correlation_id: str
    source_agent: WorkloadIdentity
    user_identity: UserIdentity
    delegation_chain: list[DelegationEntry] = field(default_factory=list)
    signature: str = ""


@dataclass
class TokenInfo:
    """Stores OAuth 2.0 token information for an agent-user pair or M2M credential.

    Attributes:
        access_token: The OAuth 2.0 access token.
        refresh_token: The OAuth 2.0 refresh token (None for client credentials grant).
        expires_at: Timestamp when the access token expires.
        scopes: List of granted scopes on the token.
        agent_identity: ARN of the agent associated with this token.
        token_type: Token type, typically "Bearer".
    """

    access_token: str
    refresh_token: str | None
    expires_at: datetime
    scopes: list[str]
    agent_identity: str
    token_type: str = "Bearer"


@dataclass(frozen=True)
class ScopeConfig:
    """Configuration for maximum allowed OAuth scopes per agent credential provider.

    Attributes:
        maximum_scopes: The full set of scopes this agent is allowed to request.
        agent_identity: ARN of the agent this scope configuration applies to.
    """

    maximum_scopes: set[str]
    agent_identity: str
