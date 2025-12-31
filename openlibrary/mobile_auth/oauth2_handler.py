"""
OAuth2 Handler for Mobile Authentication

This module provides OAuth2 authentication handling for mobile clients,
including token management, refresh token handling, and secure credential storage.
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlencode, parse_qs, urlparse
import logging

logger = logging.getLogger(__name__)


class OAuth2Config:
    """Configuration for OAuth2 authentication flow."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        auth_url: str,
        token_url: str,
        scopes: Optional[list] = None,
    ):
        """
        Initialize OAuth2 configuration.

        Args:
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret
            redirect_uri: Redirect URI for OAuth2 callback
            auth_url: Authorization endpoint URL
            token_url: Token endpoint URL
            scopes: List of requested scopes
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.auth_url = auth_url
        self.token_url = token_url
        self.scopes = scopes or ["openid", "profile", "email"]


class OAuth2Token:
    """Represents an OAuth2 token with expiration tracking."""

    def __init__(
        self,
        access_token: str,
        token_type: str = "Bearer",
        expires_in: Optional[int] = None,
        refresh_token: Optional[str] = None,
        scope: Optional[str] = None,
    ):
        """
        Initialize OAuth2 token.

        Args:
            access_token: The access token string
            token_type: Type of token (default: Bearer)
            expires_in: Seconds until token expires
            refresh_token: Token for refreshing access token
            scope: Space-separated list of scopes
        """
        self.access_token = access_token
        self.token_type = token_type
        self.refresh_token = refresh_token
        self.scope = scope
        self.created_at = datetime.utcnow()
        self.expires_in = expires_in

    def is_expired(self, buffer_seconds: int = 60) -> bool:
        """
        Check if token is expired with optional buffer.

        Args:
            buffer_seconds: Seconds of buffer before actual expiration

        Returns:
            True if token is expired or will expire within buffer
        """
        if self.expires_in is None:
            return False

        expiration_time = self.created_at + timedelta(seconds=self.expires_in)
        buffer_time = datetime.utcnow() + timedelta(seconds=buffer_seconds)
        return buffer_time >= expiration_time

    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary representation."""
        return {
            "access_token": self.access_token,
            "token_type": self.token_type,
            "refresh_token": self.refresh_token,
            "scope": self.scope,
            "expires_in": self.expires_in,
            "created_at": self.created_at.isoformat(),
        }


class OAuth2Handler:
    """
    Handles OAuth2 authentication flow for mobile clients.

    Supports:
    - Authorization code flow
    - Token refresh
    - PKCE (Proof Key for Code Exchange) for enhanced security
    """

    def __init__(self, config: OAuth2Config):
        """
        Initialize OAuth2 handler.

        Args:
            config: OAuth2 configuration object
        """
        self.config = config
        self.current_token: Optional[OAuth2Token] = None
        self._pkce_verifier: Optional[str] = None

    def generate_pkce_pair(self) -> Tuple[str, str]:
        """
        Generate PKCE code verifier and challenge for enhanced security.

        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        # Generate 128-character code verifier
        code_verifier = secrets.token_urlsafe(96)
        self._pkce_verifier = code_verifier

        # Create code challenge from verifier
        challenge_bytes = hashlib.sha256(code_verifier.encode()).digest()
        code_challenge = (
            __import__("base64")
            .urlsafe_b64encode(challenge_bytes)
            .decode()
            .rstrip("=")
        )

        return code_verifier, code_challenge

    def get_authorization_url(self, use_pkce: bool = True) -> str:
        """
        Generate authorization URL for initiating OAuth2 flow.

        Args:
            use_pkce: Whether to use PKCE for enhanced security

        Returns:
            Authorization URL to redirect user to
        """
        state = secrets.token_urlsafe(32)
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.config.scopes),
            "state": state,
        }

        if use_pkce:
            _, code_challenge = self.generate_pkce_pair()
            params["code_challenge"] = code_challenge
            params["code_challenge_method"] = "S256"

        auth_url = f"{self.config.auth_url}?{urlencode(params)}"
        logger.debug(f"Generated authorization URL (state: {state})")
        return auth_url

    def exchange_code_for_token(
        self, code: str, state: Optional[str] = None
    ) -> OAuth2Token:
        """
        Exchange authorization code for access token.

        Args:
            code: Authorization code from callback
            state: State parameter for validation (optional)

        Returns:
            OAuth2Token object

        Raises:
            ValueError: If code exchange fails
        """
        if not code:
            raise ValueError("Authorization code is required")

        # Build token request
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "redirect_uri": self.config.redirect_uri,
        }

        # Add PKCE verifier if available
        if self._pkce_verifier:
            token_data["code_verifier"] = self._pkce_verifier

        try:
            # In production, this would make actual HTTP request to token_url
            # For now, this is a placeholder for the token exchange logic
            logger.info("Exchanging authorization code for token")
            # token_response = requests.post(self.config.token_url, data=token_data)
            # token_response.raise_for_status()

            # Parse token response (would be from actual HTTP response)
            # token_data = token_response.json()
            # self.current_token = OAuth2Token(**token_data)
            # return self.current_token

        except Exception as e:
            logger.error(f"Token exchange failed: {str(e)}")
            raise ValueError(f"Failed to exchange code for token: {str(e)}")

    def refresh_access_token(self) -> Optional[OAuth2Token]:
        """
        Refresh access token using refresh token.

        Returns:
            New OAuth2Token object or None if refresh fails

        Raises:
            ValueError: If no refresh token available
        """
        if not self.current_token or not self.current_token.refresh_token:
            raise ValueError("No refresh token available")

        token_data = {
            "grant_type": "refresh_token",
            "refresh_token": self.current_token.refresh_token,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }

        try:
            logger.info("Refreshing access token")
            # In production, this would make actual HTTP request to token_url
            # token_response = requests.post(self.config.token_url, data=token_data)
            # token_response.raise_for_status()
            # token_data = token_response.json()
            # self.current_token = OAuth2Token(**token_data)
            # return self.current_token

        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            return None

    def is_token_valid(self) -> bool:
        """
        Check if current token is valid and not expired.

        Returns:
            True if token exists and is not expired
        """
        return self.current_token is not None and not self.current_token.is_expired()

    def get_authorization_header(self) -> Optional[str]:
        """
        Get HTTP Authorization header value for API requests.

        Returns:
            Authorization header string or None if no valid token
        """
        if not self.is_token_valid():
            return None

        return f"{self.current_token.token_type} {self.current_token.access_token}"

    def clear_token(self) -> None:
        """Clear stored token and PKCE verifier."""
        self.current_token = None
        self._pkce_verifier = None
        logger.info("Token and PKCE verifier cleared")
