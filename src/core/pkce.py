"""PKCE (Proof Key for Code Exchange) utilities for OAuth 2.1 compliance.

Implements RFC 7636 PKCE for all authorization code flows. OAuth 2.1
mandates PKCE on every authorization code grant to prevent authorization
code interception attacks.

Functions:
    generate_code_verifier: Create a cryptographically random code verifier.
    compute_code_challenge: Derive the S256 code challenge from a verifier.

Requirements: OAuth 2.1 §4.1 (PKCE mandatory)
"""

from __future__ import annotations

import base64
import hashlib
import secrets


def generate_code_verifier(length: int = 64) -> str:
    """Generate a cryptographically random PKCE code verifier.

    Produces a high-entropy random string between 43 and 128 characters,
    encoded as base64url without padding, suitable for use as a PKCE
    code_verifier per RFC 7636 §4.1.

    Args:
        length: Number of random bytes to generate before encoding.
            Must produce a base64url string between 43 and 128 chars.
            Default is 64 bytes (produces 86 characters).

    Returns:
        A base64url-encoded string (no padding) of 43-128 characters.

    Raises:
        ValueError: If length would produce a verifier outside 43-128 chars.
    """
    # base64url encoding expands bytes by ~4/3: ceil(length * 4/3)
    encoded_length = (length * 4 + 2) // 3  # approximate without padding
    if encoded_length < 43 or encoded_length > 128:
        raise ValueError(
            f"length={length} produces ~{encoded_length} chars; "
            f"must be between 43 and 128 characters per RFC 7636"
        )

    random_bytes = secrets.token_bytes(length)
    verifier = base64.urlsafe_b64encode(random_bytes).rstrip(b"=").decode("ascii")

    # Trim to 128 if slightly over due to encoding
    if len(verifier) > 128:
        verifier = verifier[:128]

    return verifier


def compute_code_challenge(verifier: str) -> str:
    """Compute the S256 PKCE code challenge from a code verifier.

    Applies SHA-256 to the ASCII-encoded verifier and returns the
    base64url-encoded digest without padding, per RFC 7636 §4.2.

    Args:
        verifier: The code verifier string (43-128 characters).

    Returns:
        The base64url-encoded SHA-256 hash (no padding) of the verifier.

    Raises:
        ValueError: If verifier is empty or outside valid length range.
    """
    if not verifier:
        raise ValueError("code_verifier must not be empty")

    if len(verifier) < 43 or len(verifier) > 128:
        raise ValueError(
            f"code_verifier length {len(verifier)} outside valid range 43-128"
        )

    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return challenge
