"""Browser-based Authorization Code flow with PKCE for CLI authentication.

Implements a localhost-redirect OAuth 2.1 Authorization Code Grant with PKCE,
compatible with Amazon Cognito hosted UI. Opens the user's browser, captures
the authorization code via a temporary local HTTP server, and exchanges it
for tokens.

Flow:
1. Generate PKCE code_verifier and code_challenge (S256)
2. Start a local HTTP server on localhost to capture the redirect
3. Open the Cognito authorization URL in the user's default browser
4. Wait for the authorization code callback (with timeout)
5. Verify the state parameter matches
6. Exchange the authorization code for tokens at the token endpoint
7. Return id_token, access_token, refresh_token, expires_in

Requirements: OAuth 2.1 §4.1 (Authorization Code + PKCE mandatory)
"""

from __future__ import annotations

import secrets
import socket
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import httpx

from src.core.pkce import compute_code_challenge, generate_code_verifier

# Default port for the localhost callback server
DEFAULT_PORT = 8910

# Timeout in seconds waiting for the user to authorize in the browser
AUTHORIZATION_TIMEOUT = 120


class _AuthorizationError(Exception):
    """Raised when the authorization flow encounters an error."""


class _CallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler that captures the OAuth callback parameters.

    Stores the query parameters from the authorization callback on the
    server instance for retrieval after the request is handled.
    """

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET request from the OAuth redirect."""
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        # Store params on the server instance
        self.server.callback_params = params  # type: ignore[attr-defined]

        # Respond with a success page the user sees in their browser
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        response_html = (
            "<html><body style='font-family: sans-serif; text-align: center; padding: 60px;'>"
            "<h1>&#10004; Authorization Successful</h1>"
            "<p>You can close this tab and return to the CLI.</p>"
            "</body></html>"
        )
        self.wfile.write(response_html.encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default HTTP server logging unless verbose."""
        # Silenced to avoid noisy output in the CLI
        pass


def _find_available_port(preferred: int = DEFAULT_PORT) -> int:
    """Find an available port, preferring the given one.

    Args:
        preferred: Port number to try first.

    Returns:
        An available port number.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", preferred))
            return preferred
    except OSError:
        # Preferred port unavailable, let the OS pick one
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


def _build_authorize_url(
    cognito_endpoint: str,
    client_id: str,
    redirect_uri: str,
    state: str,
    code_challenge: str,
) -> str:
    """Build the Cognito hosted UI authorization URL.

    Args:
        cognito_endpoint: Base Cognito endpoint (e.g. https://domain.auth.region.amazoncognito.com)
        client_id: The Cognito user pool client ID.
        redirect_uri: The localhost redirect URI.
        state: Random state string for CSRF protection.
        code_challenge: The S256 PKCE code challenge.

    Returns:
        The full authorization URL to open in the browser.
    """
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{cognito_endpoint}/oauth2/authorize?{urllib.parse.urlencode(params)}"


def _exchange_code_for_tokens(
    cognito_endpoint: str,
    client_id: str,
    code: str,
    redirect_uri: str,
    code_verifier: str,
) -> dict:
    """Exchange the authorization code for tokens at the Cognito token endpoint.

    Args:
        cognito_endpoint: Base Cognito endpoint.
        client_id: The Cognito user pool client ID.
        code: The authorization code from the callback.
        redirect_uri: The redirect URI used in the authorization request.
        code_verifier: The PKCE code verifier.

    Returns:
        Dict with id_token, access_token, refresh_token, expires_in.

    Raises:
        _AuthorizationError: If the token exchange fails.
    """
    token_url = f"{cognito_endpoint}/oauth2/token"

    response = httpx.post(
        token_url,
        data={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30.0,
    )

    if response.status_code != 200:
        error_detail = response.text[:200] if response.text else "No response body"
        raise _AuthorizationError(
            f"Token exchange failed (HTTP {response.status_code}): {error_detail}"
        )

    data = response.json()
    return {
        "id_token": data.get("id_token", ""),
        "access_token": data.get("access_token", ""),
        "refresh_token": data.get("refresh_token", ""),
        "expires_in": data.get("expires_in", 3600),
    }


def authenticate_with_browser(
    cognito_endpoint: str,
    client_id: str,
    verbose: bool = False,
) -> dict:
    """Authenticate via browser-based Authorization Code flow with PKCE.

    Opens the user's default browser to the Cognito hosted UI, captures
    the authorization code via a temporary localhost HTTP server, and
    exchanges it for tokens.

    Args:
        cognito_endpoint: Cognito hosted UI base URL
            (e.g. https://domain.auth.region.amazoncognito.com).
        client_id: The Cognito user pool client ID.
        verbose: Whether to print verbose debug information.

    Returns:
        Dict with 'id_token', 'access_token', 'refresh_token', 'expires_in'.

    Raises:
        _AuthorizationError: If authorization fails at any step.
        TimeoutError: If the user does not complete authorization within the timeout.
    """
    # Step 1: Generate PKCE parameters
    code_verifier = generate_code_verifier()
    code_challenge = compute_code_challenge(code_verifier)
    state = secrets.token_urlsafe(32)

    if verbose:
        print(f"  [PKCE] code_verifier length: {len(code_verifier)}")
        print(f"  [PKCE] code_challenge: {code_challenge[:16]}...")
        print(f"  [State] {state[:16]}...")

    # Step 2: Start local HTTP server
    port = _find_available_port(DEFAULT_PORT)
    redirect_uri = f"http://localhost:{port}/callback"

    server = HTTPServer(("127.0.0.1", port), _CallbackHandler)
    server.callback_params = {}  # type: ignore[attr-defined]
    server.timeout = AUTHORIZATION_TIMEOUT

    if verbose:
        print(f"  [Server] Listening on {redirect_uri}")

    # Step 3: Build authorization URL and open browser
    authorize_url = _build_authorize_url(
        cognito_endpoint=cognito_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        state=state,
        code_challenge=code_challenge,
    )

    if verbose:
        print(f"  [URL] {authorize_url[:80]}...")

    webbrowser.open(authorize_url)

    # Step 4: Wait for the callback (with timeout)
    callback_received = threading.Event()

    def _handle_request() -> None:
        server.handle_request()
        callback_received.set()

    server_thread = threading.Thread(target=_handle_request, daemon=True)
    server_thread.start()

    if not callback_received.wait(timeout=AUTHORIZATION_TIMEOUT):
        server.server_close()
        raise TimeoutError(
            f"Authorization timed out after {AUTHORIZATION_TIMEOUT} seconds. "
            "Please try again."
        )

    # Step 5: Extract authorization code from callback
    params = server.callback_params  # type: ignore[attr-defined]
    server.server_close()

    # Check for error response from the authorization server
    if "error" in params:
        error = params["error"][0]
        description = params.get("error_description", [""])[0]
        raise _AuthorizationError(f"Authorization denied: {error} - {description}")

    if "code" not in params:
        raise _AuthorizationError("No authorization code received in callback")

    code = params["code"][0]

    # Step 6: Verify state matches
    received_state = params.get("state", [""])[0]
    if received_state != state:
        raise _AuthorizationError(
            "State mismatch: possible CSRF attack. "
            f"Expected '{state[:8]}...', got '{received_state[:8]}...'"
        )

    if verbose:
        print(f"  [Code] Authorization code received: {code[:8]}...")
        print("  [State] State verified successfully")

    # Step 7: Exchange code for tokens
    tokens = _exchange_code_for_tokens(
        cognito_endpoint=cognito_endpoint,
        client_id=client_id,
        code=code,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier,
    )

    if verbose:
        print(f"  [Tokens] id_token: {tokens['id_token'][:16]}..." if tokens["id_token"] else "  [Tokens] No id_token")
        print(f"  [Tokens] expires_in: {tokens['expires_in']}s")

    return tokens
