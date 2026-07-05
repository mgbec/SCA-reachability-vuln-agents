"""Shared Hypothesis strategies for property-based testing.

Provides reusable strategies for generating random test data matching
the platform's domain: user claims, agent ARNs, scopes, timestamps,
CVSS scores, semver versions, and dependency trees.
"""

from datetime import datetime, timedelta, timezone

from hypothesis import strategies as st


# --- AWS Regions ---
AWS_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-southeast-1", "ap-northeast-1",
]

aws_regions = st.sampled_from(AWS_REGIONS)

# --- AWS Account IDs (12-digit numeric strings) ---
aws_account_ids = st.from_regex(r"[0-9]{12}", fullmatch=True)

# --- Agent Names ---
AGENT_NAMES = ["orchestrator-agent", "scanner-agent", "analysis-agent"]

agent_names = st.sampled_from(AGENT_NAMES)


# --- Agent ARNs ---
def agent_arns(
    region=None,
    account_id=None,
    name=None,
):
    """Generate valid AgentCore workload identity ARNs.

    Pattern: arn:aws:bedrock-agentcore:{region}:{account}:workload-identity/directory/default/workload-identity/{agent-name}
    """
    r = region if region is not None else aws_regions
    a = account_id if account_id is not None else aws_account_ids
    n = name if name is not None else agent_names

    return st.builds(
        lambda reg, acct, nm: (
            f"arn:aws:bedrock-agentcore:{reg}:{acct}:"
            f"workload-identity/directory/default/workload-identity/{nm}"
        ),
        reg=r,
        acct=a,
        nm=n,
    )


# --- OAuth Scopes ---
ALL_SCOPES = ["security_events", "repo", "openid", "profile", "email", "read:org", "read:user"]

scopes = st.sampled_from(ALL_SCOPES)

scope_sets = st.frozensets(scopes, min_size=1, max_size=len(ALL_SCOPES))

# Non-empty scope sets for cases where at least one scope is required
non_empty_scope_sets = st.frozensets(scopes, min_size=1)


# --- Timestamps ---
def timestamps(
    min_value=datetime(2024, 1, 1, tzinfo=timezone.utc),
    max_value=datetime(2026, 12, 31, tzinfo=timezone.utc),
):
    """Generate timezone-aware UTC datetime objects within a reasonable range."""
    return st.datetimes(
        min_value=min_value.replace(tzinfo=None),
        max_value=max_value.replace(tzinfo=None),
    ).map(lambda dt: dt.replace(tzinfo=timezone.utc))


def timestamp_pairs(min_duration_seconds=60, max_duration_seconds=7200):
    """Generate (issued_at, expires_at) pairs where expires_at > issued_at."""
    return timestamps().flatmap(
        lambda issued: st.integers(
            min_value=min_duration_seconds, max_value=max_duration_seconds
        ).map(lambda delta: (issued, issued + timedelta(seconds=delta)))
    )


# --- CVSS Scores (0.0 to 10.0) ---
cvss_scores = st.floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False)


# --- Reachability Statuses ---
REACHABILITY_STATUSES = ["reachable", "unreachable", "indeterminate"]

reachability_statuses = st.sampled_from(REACHABILITY_STATUSES)


# --- Semver Versions ---
def semver_versions(
    max_major=20,
    max_minor=50,
    max_patch=100,
):
    """Generate semantic version strings in major.minor.patch format."""
    return st.builds(
        lambda major, minor, patch: f"{major}.{minor}.{patch}",
        major=st.integers(min_value=0, max_value=max_major),
        minor=st.integers(min_value=0, max_value=max_minor),
        patch=st.integers(min_value=0, max_value=max_patch),
    )


def semver_tuples(max_major=20, max_minor=50, max_patch=100):
    """Generate semantic version tuples (major, minor, patch)."""
    return st.tuples(
        st.integers(min_value=0, max_value=max_major),
        st.integers(min_value=0, max_value=max_minor),
        st.integers(min_value=0, max_value=max_patch),
    )


# --- Package Names ---
PACKAGE_ECOSYSTEMS = ["npm", "pypi", "maven", "golang", "cargo"]

package_names = st.from_regex(r"[a-z][a-z0-9\-]{1,30}", fullmatch=True)

package_ecosystems = st.sampled_from(PACKAGE_ECOSYSTEMS)


# --- Package URLs (purl) ---
def purls():
    """Generate package URLs in pkg:{ecosystem}/{name}@{version} format."""
    return st.builds(
        lambda eco, name, ver: f"pkg:{eco}/{name}@{ver}",
        eco=package_ecosystems,
        name=package_names,
        ver=semver_versions(),
    )


# --- Dependency Relationships ---
DEPENDENCY_RELATIONSHIPS = ["direct", "transitive"]

dependency_relationships = st.sampled_from(DEPENDENCY_RELATIONSHIPS)


# --- Dependency Nodes ---
def dependency_nodes():
    """Generate DependencyNode-like dicts with name, version, purl, and relationship."""
    return st.fixed_dictionaries({
        "name": package_names,
        "version": semver_versions(),
        "purl": purls(),
        "relationship": dependency_relationships,
    })


# --- Dependency Trees ---
def dependency_trees(min_size=1, max_size=20):
    """Generate lists of dependency nodes representing a dependency tree."""
    return st.lists(dependency_nodes(), min_size=min_size, max_size=max_size)


# --- User Identity Claims ---
def user_subjects():
    """Generate UUID-like user subject identifiers."""
    return st.uuids().map(str)


def cognito_issuers():
    """Generate Cognito user pool issuer URLs."""
    return st.builds(
        lambda region, pool_id: f"https://cognito-idp.{region}.amazonaws.com/{pool_id}",
        region=aws_regions,
        pool_id=st.from_regex(r"[a-z]{2}-[a-z]+-[0-9]_[A-Za-z0-9]{9}", fullmatch=True),
    )


def user_claims():
    """Generate complete user identity claim sets.

    Returns dicts with: subject, issuer, audience, scopes, issued_at, expires_at.
    """
    return timestamp_pairs().flatmap(
        lambda pair: st.fixed_dictionaries({
            "subject": user_subjects(),
            "issuer": cognito_issuers(),
            "audience": st.text(min_size=5, max_size=40, alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"))),
            "scopes": st.lists(scopes, min_size=1, max_size=4),
            "issued_at": st.just(pair[0]),
            "expires_at": st.just(pair[1]),
        })
    )


# --- Correlation IDs (UUID v4) ---
correlation_ids = st.uuids(version=4).map(str)


# --- HMAC Keys ---
hmac_keys = st.binary(min_size=32, max_size=64)


# --- Token Expiration Scenarios ---
def token_expiration_scenarios(buffer_seconds=60):
    """Generate (current_time, token_expiration, expected_needs_refresh) triples.

    Useful for testing token refresh decision logic.
    """
    now = st.just(datetime(2025, 1, 15, 10, 0, 0, tzinfo=timezone.utc))

    return now.flatmap(
        lambda current: st.one_of(
            # Expired token
            st.integers(min_value=1, max_value=3600).map(
                lambda secs: (current, current - timedelta(seconds=secs), True)
            ),
            # Within buffer (needs refresh) — includes exact boundary
            st.integers(min_value=0, max_value=buffer_seconds).map(
                lambda secs: (current, current + timedelta(seconds=secs), True)
            ),
            # Outside buffer (no refresh needed) — strictly beyond buffer
            st.integers(min_value=buffer_seconds + 1, max_value=7200).map(
                lambda secs: (current, current + timedelta(seconds=secs), False)
            ),
        )
    )


# --- CVE IDs ---
cve_ids = st.builds(
    lambda year, seq: f"CVE-{year}-{seq:05d}",
    year=st.integers(min_value=2020, max_value=2025),
    seq=st.integers(min_value=1, max_value=99999),
)


# --- Vulnerability Findings ---
def vulnerability_findings():
    """Generate vulnerability finding dicts for testing scoring and recommendations."""
    return st.fixed_dictionaries({
        "cve_id": cve_ids,
        "dependency_name": package_names,
        "dependency_version": semver_versions(),
        "cvss_base_score": cvss_scores,
        "reachability_status": reachability_statuses,
    })
