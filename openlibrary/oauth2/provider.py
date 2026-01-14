"""
OAuth2 Provider Implementation for OpenLibrary

This module implements the server-side OAuth2 provider functionality including
authorization code flow, token management, and client registration.
"""

import base64
import hashlib
import json
import logging
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any

import web

from infogami import config
from openlibrary.core.cache import MemcacheCache
from openlibrary.oauth2.mobile_auth import Token

logger = logging.getLogger("openlibrary.oauth2.provider")


def safe_get_attr(obj, attr: str, default=""):
    """
    Safely get string values from Infogami objects.

    Infogami returns "Nothing" objects for missing attributes instead of
    raising AttributeError. This helper detects and handles those cases.

    Args:
        obj: The object to get the attribute from
        attr: The attribute name
        default: Default value if attribute is None or Nothing

    Returns:
        The attribute value as a string, or the default value
    """
    value = getattr(obj, attr, default)
    # Check if it's a Nothing object or None
    if value is None or type(value).__name__ == 'Nothing':
        return default
    return str(value)


@dataclass
class OAuth2Client:
    """Represents an OAuth2 client application."""

    client_id: str
    client_secret: str
    redirect_uris: list[str]
    name: str
    description: str = ""
    scopes: list[str] | None = None
    is_confidential: bool = True

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = ["openid", "profile", "email"]

    def validate_redirect_uri(self, redirect_uri: str) -> bool:
        """Validate that the redirect URI is registered for this client."""
        return redirect_uri in self.redirect_uris

    def to_dict(self) -> dict[str, Any]:
        """Convert client to dictionary for storage."""
        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uris": self.redirect_uris,
            "name": self.name,
            "description": self.description,
            "scopes": self.scopes,
            "is_confidential": self.is_confidential,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "OAuth2Client":
        """Create client from dictionary."""
        return OAuth2Client(**data)


@dataclass
class AuthorizationCode:
    """Represents an OAuth2 authorization code."""

    code: str
    client_id: str
    user_id: str
    redirect_uri: str
    scopes: list[str]
    code_challenge: str | None = None
    code_challenge_method: str | None = None
    expires_at: float | None = None

    def __post_init__(self):
        if self.expires_at is None:
            self.expires_at = time.time() + 300  # 5 minutes expiration

    def is_expired(self) -> bool:
        """Check if authorization code has expired."""
        # expires_at is guaranteed to be set by __post_init__
        assert self.expires_at is not None
        return time.time() >= self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Convert authorization code to dictionary for storage."""
        return {
            "code": self.code,
            "client_id": self.client_id,
            "user_id": self.user_id,
            "redirect_uri": self.redirect_uri,
            "scopes": self.scopes,
            "code_challenge": self.code_challenge,
            "code_challenge_method": self.code_challenge_method,
            "expires_at": self.expires_at,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "AuthorizationCode":
        """Create authorization code from dictionary."""
        return AuthorizationCode(**data)


class OAuth2Provider:
    """Main OAuth2 provider implementation."""

    def __init__(self):
        self.clients: dict[str, OAuth2Client] = {}

        # Use memcache for persistent storage instead of in-memory dicts
        self.cache = MemcacheCache()

        # Load configuration
        self._load_configuration()

    def _load_configuration(self):
        """Load OAuth2 configuration from settings."""
        # This would be loaded from config in production
        # For now, we'll use a default configuration
        pass

    def register_client(self, client: OAuth2Client):
        """Register an OAuth2 client."""
        self.clients[client.client_id] = client

    def get_client(self, client_id: str) -> OAuth2Client | None:
        """Get OAuth2 client by ID."""
        return self.clients.get(client_id)

    def generate_authorization_code(
        self,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scopes: list[str],
        code_challenge: str | None = None,
        code_challenge_method: str | None = None,
    ) -> AuthorizationCode:
        """Generate a new authorization code."""
        code = secrets.token_urlsafe(32)

        # Store code challenge with method prefix for validation
        stored_code_challenge = code_challenge
        if code_challenge_method == "S256":
            stored_code_challenge = f"S256:{code_challenge}"

        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scopes=scopes,
            code_challenge=stored_code_challenge,
            code_challenge_method=code_challenge_method,
        )

        # Store in memcache with expiration (5 minutes)
        self.cache.set(f"oauth2_auth_code:{code}", auth_code.to_dict(), expires=300)
        return auth_code

    def validate_authorization_code(
        self,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> AuthorizationCode | None:
        """Validate an authorization code and return it if valid."""
        # Retrieve from memcache
        auth_code_data = self.cache.get(f"oauth2_auth_code:{code}")
        if not auth_code_data:
            logger.warning("Authorization code not found or already used")
            return None

        auth_code = AuthorizationCode.from_dict(auth_code_data)

        if auth_code.is_expired():
            logger.warning("Authorization code expired")
            self.cache.delete(f"oauth2_auth_code:{code}")
            return None

        if auth_code.client_id != client_id:
            logger.warning("Client ID mismatch during code validation")
            return None

        if auth_code.redirect_uri != redirect_uri:
            logger.warning("Redirect URI mismatch during code validation")
            return None

        # Validate PKCE if code challenge was provided
        if (
            auth_code.code_challenge
            and code_verifier
            and not self._validate_pkce(auth_code.code_challenge, code_verifier)
        ):
            logger.warning("PKCE validation failed")
            return None

        return auth_code

    def _validate_pkce(self, code_challenge: str, code_verifier: str) -> bool:
        """Validate PKCE code verifier against code challenge."""
        if code_challenge.startswith("S256:"):
            # S256 method - SHA256 hash of verifier
            expected_challenge = code_challenge[5:]  # Remove "S256:" prefix

            verifier_hash = hashlib.sha256(code_verifier.encode()).digest()
            verifier_challenge = (
                base64.urlsafe_b64encode(verifier_hash).decode().rstrip("=")
            )

            return secrets.compare_digest(expected_challenge, verifier_challenge)
        else:
            # Plain method - direct comparison
            return secrets.compare_digest(code_challenge, code_verifier)

    def generate_token(self, auth_code: AuthorizationCode, client_id: str) -> Token:
        """Generate access token from authorization code."""
        # Delete the authorization code as it can only be used once
        self.cache.delete(f"oauth2_auth_code:{auth_code.code}")

        # Generate access token
        access_token = secrets.token_urlsafe(48)
        refresh_token = secrets.token_urlsafe(48)

        token = Token(
            access_token=access_token,
            token_type="Bearer",
            expires_in=3600,  # 1 hour
            refresh_token=refresh_token,
            scope=" ".join(auth_code.scopes),
        )

        # Store token in memcache with 1 hour expiration
        # Also store user_id mapping so we can retrieve the user later
        token_data = token.to_dict()
        token_data['user_id'] = auth_code.user_id  # Add user_id to token data
        self.cache.set(f"oauth2_token:{access_token}", token_data, expires=3600)

        return token

    def validate_token(self, access_token: str) -> Token | None:
        """Validate an access token."""
        # Retrieve token from memcache
        token_data = self.cache.get(f"oauth2_token:{access_token}")
        if not token_data:
            return None

        # Remove user_id from token_data before creating Token (Token doesn't have user_id field)
        token_data_clean = {k: v for k, v in token_data.items() if k != 'user_id'}
        token = Token.from_dict(token_data_clean)

        if token.is_expired:
            # Remove from memcache
            self.cache.delete(f"oauth2_token:{access_token}")
            return None

        return token

    def get_user_id_for_token(self, access_token: str) -> str | None:
        """Get the user_id associated with an access token."""
        token_data = self.cache.get(f"oauth2_token:{access_token}")
        if not token_data:
            return None
        return token_data.get('user_id')

    def refresh_token(self, refresh_token: str, client_id: str) -> Token | None:
        """
        Refresh an access token using a refresh token.

        Note: This feature is not currently implemented. The current memcache-based
        storage doesn't support efficient token lookup by refresh_token. A full
        implementation would require:
        1. Store refresh_token -> access_token mapping in memcache/database
        2. Implement token lookup by refresh_token
        3. Generate new access token while preserving user_id association

        Returns:
            None (not implemented)
        """
        logger.warning(
            "Token refresh not implemented - requires database-backed token storage"
        )
        return None


class OAuth2WebHandler:
    """Web handler for OAuth2 endpoints."""

    def __init__(self):
        self.provider = OAuth2Provider()
        self.setup_default_clients()

    def setup_default_clients(self):
        """Load OAuth2 clients from configuration."""
        # Load OAuth2 client configurations from config file
        oauth2_clients_config = config.get('oauth2_clients', [])

        # Register each configured client
        for client_config in oauth2_clients_config:
            try:
                client = OAuth2Client(
                    client_id=client_config["client_id"],
                    client_secret=client_config["client_secret"],
                    redirect_uris=client_config.get("redirect_uris", []),
                    name=client_config.get("name", "Unknown Client"),
                    description=client_config.get("description", ""),
                    scopes=client_config.get("scopes"),
                    is_confidential=client_config.get("is_confidential", True),
                )
                self.provider.register_client(client)
                logger.info(f"Registered OAuth2 client: {client.name}")
            except (KeyError, TypeError) as e:
                logger.error(
                    f"Failed to register OAuth2 client from config: {e!s}",
                    exc_info=True,
                )

    def authorize(self):
        """Handle OAuth2 authorization requests."""
        i = web.input(
            response_type=None,
            client_id=None,
            redirect_uri=None,
            scope=None,
            state=None,
            code_challenge=None,
            code_challenge_method=None,
        )

        # Validate required parameters
        if i.response_type != "code":
            return self._error_response(
                "invalid_request", "response_type must be 'code'"
            )

        if not i.client_id:
            return self._error_response("invalid_request", "client_id is required")

        if not i.redirect_uri:
            return self._error_response("invalid_request", "redirect_uri is required")

        # Get client
        client = self.provider.get_client(i.client_id)
        if not client:
            logger.warning(f"Unknown client_id: {i.client_id}")
            return self._error_response("invalid_client", "client_id not found")

        # Validate redirect URI (handle URL decoding in case of double-encoding)
        decoded_redirect_uri = urllib.parse.unquote(i.redirect_uri)

        if not client.validate_redirect_uri(decoded_redirect_uri):
            logger.warning(f"Invalid redirect_uri for client {i.client_id}")
            return self._error_response(
                "invalid_redirect_uri", "redirect_uri not registered for client"
            )

        # Use the decoded version for the rest of the flow
        i.redirect_uri = decoded_redirect_uri

        # Check if user is already authenticated
        current_user = self._get_current_user()

        if current_user:
            # User is already authenticated, proceed with authorization
            return self._handle_authorized_user(
                client,
                i.redirect_uri,
                i.scope,
                i.state,
                i.code_challenge,
                i.code_challenge_method,
            )
        else:
            # User needs to authenticate first
            return self._handle_authentication_required(
                client,
                i.redirect_uri,
                i.scope,
                i.state,
                i.code_challenge,
                i.code_challenge_method,
            )

    def _get_current_user(self):
        """Get the currently authenticated user."""
        try:
            return web.ctx.site.get_user()
        except Exception:  # noqa: BLE001
            # Catch all exceptions to gracefully handle any authentication failures
            return None

    def _handle_authorized_user(
        self,
        client: OAuth2Client,
        redirect_uri: str,
        scope: str,
        state: str,
        code_challenge: str,
        code_challenge_method: str,
    ):
        """Handle authorization for already authenticated user."""
        current_user = self._get_current_user()

        # Parse and validate scopes
        requested_scopes = scope.split(" ") if scope else ["openid", "profile", "email"]
        # client.scopes is guaranteed to be set by OAuth2Client.__post_init__
        assert client.scopes is not None
        valid_scopes = [s for s in requested_scopes if s in client.scopes]

        # Generate authorization code
        auth_code = self.provider.generate_authorization_code(
            client_id=client.client_id,
            user_id=current_user.key,
            redirect_uri=redirect_uri,
            scopes=valid_scopes,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

        # Build redirect URL with authorization code
        redirect_url = f"{redirect_uri}?code={auth_code.code}"
        if state:
            redirect_url += f"&state={state}"

        # Redirect to the client application
        raise web.seeother(redirect_url)

    def _handle_authentication_required(
        self,
        client: OAuth2Client,
        redirect_uri: str,
        scope: str,
        state: str,
        code_challenge: str,
        code_challenge_method: str,
    ):
        """Handle authorization when user needs to authenticate."""
        # Generate a unique request ID for this authorization attempt
        request_data = f"{client.client_id}{redirect_uri}{state}{time.time()}"
        request_id = hashlib.md5(request_data.encode('utf-8')).hexdigest()

        # Store the pending request in memcache (10 minute expiration)
        pending_request = {
            "client_id": client.client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        }
        self.provider.cache.set(
            f"oauth2_pending_request:{request_id}", pending_request, expires=600
        )

        # Redirect to login page with request ID
        login_url = f"/account/login?redirect=/oauth2/authorize/complete?request_id={request_id}"
        raise web.seeother(login_url)

    def authorize_complete(self):
        """Complete authorization after user login."""
        i = web.input(request_id=None)

        # Validate request ID
        if not i.request_id:
            return self._error_response(
                "invalid_request", "Missing request_id parameter"
            )

        # Retrieve the pending authorization request from memcache
        auth_request = self.provider.cache.get(f"oauth2_pending_request:{i.request_id}")

        if not auth_request:
            logger.warning(
                f"Authorization request not found or expired: {i.request_id}"
            )
            return self._error_response(
                "invalid_request", "Authorization request not found or expired"
            )

        # Clean up the pending request (one-time use)
        self.provider.cache.delete(f"oauth2_pending_request:{i.request_id}")

        # Get current user
        current_user = self._get_current_user()
        if not current_user:
            return self._error_response("access_denied", "User not authenticated")

        # Get client
        client = self.provider.get_client(auth_request["client_id"])
        if not client:
            logger.warning(f"Client not found: {auth_request['client_id']}")
            return self._error_response("invalid_client", "client_id not found")

        # Generate authorization code
        auth_code = self.provider.generate_authorization_code(
            client_id=client.client_id,
            user_id=current_user.key,
            redirect_uri=auth_request["redirect_uri"],
            scopes=(
                auth_request["scope"].split(" ")
                if auth_request["scope"]
                else ["openid", "profile", "email"]
            ),
            code_challenge=auth_request["code_challenge"],
            code_challenge_method=auth_request["code_challenge_method"],
        )

        # Build redirect URL with authorization code
        redirect_url = f"{auth_request['redirect_uri']}?code={auth_code.code}"
        if auth_request["state"]:
            redirect_url += f"&state={auth_request['state']}"

        raise web.seeother(redirect_url)

    def token(self):
        """Handle OAuth2 token requests."""
        try:
            # This endpoint should only accept POST requests
            if web.ctx.method != "POST":
                return self._error_response("invalid_request", "Method not allowed")

            # Parse request body
            i = web.input(
                grant_type=None,
                code=None,
                redirect_uri=None,
                client_id=None,
                client_secret=None,
                code_verifier=None,
                refresh_token=None,
            )

            # Validate grant type
            if i.grant_type not in ["authorization_code", "refresh_token"]:
                return self._error_response(
                    "unsupported_grant_type", "grant_type not supported"
                )

            # Get client
            client = self.provider.get_client(i.client_id)
            if not client:
                logger.warning(f"Unknown client_id in token request: {i.client_id}")
                return self._error_response("invalid_client", "client_id not found")

            # Validate client secret for confidential clients
            if client.is_confidential and i.client_secret != client.client_secret:
                logger.warning(f"Invalid client_secret for client: {i.client_id}")
                return self._error_response("invalid_client", "client_secret invalid")

            if i.grant_type == "authorization_code":
                return self._handle_token_request_authorization_code(i, client)
            else:
                return self._handle_token_request_refresh_token(i, client)

        except Exception as e:
            logger.error(f"Unexpected error in token endpoint: {e!s}", exc_info=True)
            return self._error_response(
                "server_error", "Internal server error", status=500
            )

    def _handle_token_request_authorization_code(self, i, client: OAuth2Client):
        """Handle token request with authorization code grant."""
        # Validate required parameters
        if not i.code:
            return self._error_response("invalid_request", "code is required")

        if not i.redirect_uri:
            return self._error_response("invalid_request", "redirect_uri is required")

        # Validate authorization code
        auth_code = self.provider.validate_authorization_code(
            code=i.code,
            client_id=client.client_id,
            redirect_uri=i.redirect_uri,
            code_verifier=i.code_verifier,
        )

        if not auth_code:
            return self._error_response(
                "invalid_grant", "authorization_code invalid or expired"
            )

        # Generate token
        token = self.provider.generate_token(auth_code, client.client_id)

        # Return token response
        return self._token_response(token)

    def _handle_token_request_refresh_token(self, i, client: OAuth2Client):
        """Handle token request with refresh token grant."""
        # Validate required parameters
        if not i.refresh_token:
            return self._error_response("invalid_request", "refresh_token is required")

        # Refresh token
        token = self.provider.refresh_token(i.refresh_token, client.client_id)

        if not token:
            return self._error_response(
                "invalid_grant", "refresh_token invalid or expired"
            )

        # Return token response
        return self._token_response(token)

    def _token_response(self, token: Token):
        """Generate token response."""
        from infogami.utils import delegate

        try:
            response = {
                "access_token": token.access_token,
                "token_type": token.token_type,
                "expires_in": token.expires_in,
                "scope": token.scope,
            }

            if token.refresh_token:
                response["refresh_token"] = token.refresh_token

            # Set HTTP status code to 200
            web.ctx.status = "200"

            # Use delegate.RawText to prevent template wrapping
            return delegate.RawText(
                json.dumps(response), content_type="application/json"
            )

        except Exception as e:
            logger.error(f"Failed to generate token response: {e!s}", exc_info=True)
            return self._error_response(
                "server_error", "Failed to generate token response", status=500
            )

    def _error_response(self, error: str, error_description: str, status: int = 400):
        """Generate error response per OAuth2 spec (RFC 6749)."""
        from infogami.utils import delegate

        web.ctx.status = str(status)

        # OAuth2 spec requires JSON error responses
        error_response = {"error": error, "error_description": error_description}

        # Use delegate.RawText to prevent template wrapping
        return delegate.RawText(
            json.dumps(error_response), content_type="application/json"
        )

    def userinfo(self):
        """Handle OAuth2 user info requests."""
        # Get access token from Authorization header
        auth_header = web.ctx.env.get("HTTP_AUTHORIZATION", "")

        if not auth_header or not auth_header.startswith("Bearer "):
            return self._error_response(
                "invalid_request", "Authorization header missing or invalid"
            )

        access_token = auth_header[7:]  # Remove "Bearer " prefix

        # Validate token
        token = self.provider.validate_token(access_token)
        if not token:
            return self._error_response(
                "invalid_token", "Access token invalid or expired", status=401
            )

        # Get user information
        user = self._get_user_from_token(token)
        if not user:
            return self._error_response(
                "invalid_token", "User not found for token", status=401
            )

        # Return user info
        return self._userinfo_response(user)

    def _get_user_from_token(self, token: Token):
        """Get user from token.

        Returns a User object from Infogami, augmented with Account data for email access.
        """
        from openlibrary.accounts import OpenLibraryAccount

        # Get the user_id associated with this token
        user_id = self.provider.get_user_id_for_token(token.access_token)

        if not user_id:
            logger.warning("No user_id found for token")
            return None

        # Look up the user by their user_id (key)
        try:
            # Get the User document from Infogami
            user = web.ctx.site.get(user_id)

            # In Infogami, get() returns a "Nothing" object if the key doesn't exist
            if user is None or type(user).__name__ == 'Nothing':
                logger.warning(f"User not found for user_id: {user_id}")
                return None

            # Extract username from the key (e.g., "/people/username" -> "username")
            username = user_id.split("/")[-1]

            # Get the Account object which has email and other private data
            account = OpenLibraryAccount.get_by_username(username)
            if account:
                # Augment user object with account data
                user._account = account
            else:
                logger.warning(f"No account found for username: {username}")

            return user
        except Exception as e:
            logger.error(f"Error retrieving user {user_id}: {e!s}", exc_info=True)
            return None

    def _userinfo_response(self, user):
        """Generate user info response."""
        from infogami.utils import delegate

        # Extract username from key
        username = user.key.split("/")[-1] if user.key else ""

        # Get email from the Account object if available
        email = ""
        if hasattr(user, '_account') and user._account:
            email = str(user._account.email) if user._account.email else ""

        # Basic user info
        user_info = {
            "sub": str(user.key) if user.key else "",
            "username": username,
            "email": email,
            "displayname": safe_get_attr(user, "displayname", username),
        }

        # Use delegate.RawText to prevent template wrapping
        return delegate.RawText(json.dumps(user_info), content_type="application/json")

    def token_to_cookie(self):
        """Exchange OAuth2 token for session cookie."""
        # This endpoint should only accept POST requests
        if web.ctx.method != "POST":
            return self._error_response("invalid_request", "Method not allowed")

        # Parse request body
        i = web.input(access_token=None)

        # Validate access token
        if not i.access_token:
            return self._error_response("invalid_request", "access_token is required")

        token = self.provider.validate_token(i.access_token)
        if not token:
            return self._error_response(
                "invalid_token", "Access token invalid or expired", status=401
            )

        # Get user from token
        user = self._get_user_from_token(token)
        if not user:
            return self._error_response(
                "invalid_token", "User not found for token", status=401
            )

        # Generate auth token for the user
        # The generate_login_code() method is on the Account object, not User
        if hasattr(user, '_account') and user._account:
            auth_token = user._account.generate_login_code()
        else:
            logger.error(
                f"Cannot generate login code: no account data for user {user.key}"
            )
            return self._error_response(
                "server_error", "Cannot generate session cookie", status=500
            )

        # Set cookie
        expires = 3600 * 24 * 365  # 1 year
        web.setcookie(config.login_cookie_name, auth_token, expires=expires)

        # Return success response
        from infogami.utils import delegate

        # Extract username from key
        username = user.key.split("/")[-1] if user.key else ""

        # Get email from the Account object if available
        email = ""
        if hasattr(user, '_account') and user._account:
            email = str(user._account.email) if user._account.email else ""

        response_data = {
            "success": True,
            "message": "Session cookie set successfully",
            "user": {
                "username": username,
                "email": email,
                "displayname": safe_get_attr(user, "displayname", username),
            },
        }

        # Use delegate.RawText to prevent template wrapping
        return delegate.RawText(
            json.dumps(response_data), content_type="application/json"
        )


# Global provider instance
provider = OAuth2Provider()
oauth2_handler = OAuth2WebHandler()
