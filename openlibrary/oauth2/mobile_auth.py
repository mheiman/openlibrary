"""
OAuth2 Mobile Authentication Module

This module provides OAuth2 authentication functionality for mobile applications,
including authorization code flow, token exchange, and token refresh.
"""

import hashlib
import secrets
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode, parse_qs, urlparse
import logging
from datetime import datetime, timedelta

try:
    import requests
except ImportError:
    requests = None

logger = logging.getLogger(__name__)


class OAuth2MobileAuth:
    """
    OAuth2 Mobile Authentication handler supporting the authorization code flow
    and token management for mobile applications.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        auth_endpoint: str,
        token_endpoint: str,
        scopes: Optional[list] = None,
    ):
        """
        Initialize OAuth2 Mobile Authentication handler.

        Args:
            client_id: OAuth2 client ID
            client_secret: OAuth2 client secret
            redirect_uri: Redirect URI for OAuth2 callback
            auth_endpoint: Authorization endpoint URL
            token_endpoint: Token endpoint URL
            scopes: List of scopes to request (optional)
        """
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.auth_endpoint = auth_endpoint
        self.token_endpoint = token_endpoint
        self.scopes = scopes or ["openid", "profile"]
        
        # Token storage
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
        self.id_token: Optional[str] = None
        
        # PKCE support
        self.code_verifier: Optional[str] = None
        self.code_challenge: Optional[str] = None

    def generate_pkce_pair(self) -> Tuple[str, str]:
        """
        Generate PKCE (Proof Key for Public Clients) code verifier and challenge.

        Returns:
            Tuple of (code_verifier, code_challenge)
        """
        # Generate a random code verifier (43-128 characters)
        code_verifier = secrets.token_urlsafe(32)
        
        # Create code challenge from verifier
        code_challenge = hashlib.sha256(code_verifier.encode()).digest()
        # URL-safe base64 encode without padding
        code_challenge = (
            __import__("base64")
            .urlsafe_b64encode(code_challenge)
            .decode()
            .rstrip("=")
        )
        
        self.code_verifier = code_verifier
        self.code_challenge = code_challenge
        
        logger.debug("Generated PKCE code pair")
        return code_verifier, code_challenge

    def get_authorization_url(self, use_pkce: bool = True, state: Optional[str] = None) -> str:
        """
        Generate the authorization URL for the user to visit.

        Args:
            use_pkce: Whether to use PKCE (recommended for mobile)
            state: Optional state parameter for CSRF protection

        Returns:
            Authorization URL
        """
        if use_pkce:
            self.generate_pkce_pair()

        # Generate state if not provided
        if state is None:
            state = secrets.token_urlsafe(32)

        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
        }

        if use_pkce and self.code_challenge:
            params["code_challenge"] = self.code_challenge
            params["code_challenge_method"] = "S256"

        auth_url = f"{self.auth_endpoint}?{urlencode(params)}"
        logger.debug(f"Generated authorization URL with state: {state}")
        return auth_url

    def exchange_code_for_token(self, authorization_code: str) -> Dict[str, any]:
        """
        Exchange authorization code for access token.

        Args:
            authorization_code: Authorization code from callback

        Returns:
            Dictionary containing token response with keys:
                - access_token: The access token
                - token_type: Type of token (usually 'Bearer')
                - expires_in: Token expiration time in seconds
                - refresh_token: Refresh token (if provided)
                - id_token: ID token for OpenID Connect (if provided)
                - scope: Granted scopes

        Raises:
            ValueError: If code exchange fails
            ImportError: If requests library is not available
        """
        if requests is None:
            raise ImportError("requests library is required for token exchange")

        payload = {
            "grant_type": "authorization_code",
            "code": authorization_code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.redirect_uri,
        }

        # Add PKCE code verifier if using PKCE
        if self.code_verifier:
            payload["code_verifier"] = self.code_verifier

        try:
            logger.debug("Exchanging authorization code for token")
            response = requests.post(
                self.token_endpoint,
                data=payload,
                headers={"Accept": "application/json"},
                timeout=10,
            )
            response.raise_for_status()
            
            token_response = response.json()
            self._store_token_response(token_response)
            
            logger.info("Successfully exchanged authorization code for token")
            return token_response
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Token exchange failed: {str(e)}")
            raise ValueError(f"Token exchange failed: {str(e)}")

    def refresh_access_token(self) -> Dict[str, any]:
        """
        Refresh the access token using the refresh token.

        Returns:
            Dictionary containing new token response

        Raises:
            ValueError: If refresh token is not available or refresh fails
            ImportError: If requests library is not available
        """
        if requests is None:
            raise ImportError("requests library is required for token refresh")

        if not self.refresh_token:
            raise ValueError("No refresh token available")

        payload = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        try:
            logger.debug("Refreshing access token")
            response = requests.post(
                self.token_endpoint,
                data=payload,
                headers={"Accept": "application/json"},
                timeout=10,
            )
            response.raise_for_status()
            
            token_response = response.json()
            self._store_token_response(token_response)
            
            logger.info("Successfully refreshed access token")
            return token_response
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Token refresh failed: {str(e)}")
            raise ValueError(f"Token refresh failed: {str(e)}")

    def _store_token_response(self, token_response: Dict[str, any]) -> None:
        """
        Store token response data in instance variables.

        Args:
            token_response: Token response from authorization server
        """
        self.access_token = token_response.get("access_token")
        self.refresh_token = token_response.get("refresh_token", self.refresh_token)
        self.id_token = token_response.get("id_token")
        
        # Calculate token expiry time
        expires_in = token_response.get("expires_in")
        if expires_in:
            self.token_expiry = datetime.utcnow() + timedelta(seconds=int(expires_in))
            logger.debug(f"Token will expire at: {self.token_expiry}")

    def is_token_expired(self) -> bool:
        """
        Check if the current access token is expired.

        Returns:
            True if token is expired or not set, False otherwise
        """
        if not self.access_token or not self.token_expiry:
            return True
        
        # Consider token expired if less than 1 minute remaining
        return datetime.utcnow() >= (self.token_expiry - timedelta(minutes=1))

    def get_valid_access_token(self) -> str:
        """
        Get a valid access token, refreshing if necessary.

        Returns:
            Valid access token

        Raises:
            ValueError: If token cannot be obtained or refreshed
        """
        if self.is_token_expired():
            if self.refresh_token:
                self.refresh_access_token()
            else:
                raise ValueError("Token expired and no refresh token available")
        
        if not self.access_token:
            raise ValueError("No access token available")
        
        return self.access_token

    def get_authorization_header(self) -> Dict[str, str]:
        """
        Get the Authorization header for API requests.

        Returns:
            Dictionary with Authorization header

        Raises:
            ValueError: If no valid access token is available
        """
        token = self.get_valid_access_token()
        return {"Authorization": f"Bearer {token}"}

    def revoke_token(self, revoke_endpoint: str) -> bool:
        """
        Revoke the access token.

        Args:
            revoke_endpoint: Token revocation endpoint URL

        Returns:
            True if revocation was successful, False otherwise

        Raises:
            ImportError: If requests library is not available
        """
        if requests is None:
            raise ImportError("requests library is required for token revocation")

        if not self.access_token:
            logger.warning("No access token to revoke")
            return False

        payload = {
            "token": self.access_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }

        try:
            logger.debug("Revoking access token")
            response = requests.post(
                revoke_endpoint,
                data=payload,
                timeout=10,
            )
            response.raise_for_status()
            
            # Clear token data
            self.access_token = None
            self.refresh_token = None
            self.token_expiry = None
            self.id_token = None
            
            logger.info("Successfully revoked access token")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Token revocation failed: {str(e)}")
            return False

    def get_token_info(self) -> Dict[str, any]:
        """
        Get information about the current token.

        Returns:
            Dictionary containing token information
        """
        return {
            "access_token": self.access_token[:20] + "..." if self.access_token else None,
            "has_refresh_token": self.refresh_token is not None,
            "token_expired": self.is_token_expired(),
            "token_expiry": self.token_expiry.isoformat() if self.token_expiry else None,
            "has_id_token": self.id_token is not None,
            "scopes": self.scopes,
        }

    def clear_tokens(self) -> None:
        """Clear all stored tokens."""
        self.access_token = None
        self.refresh_token = None
        self.token_expiry = None
        self.id_token = None
        self.code_verifier = None
        self.code_challenge = None
        logger.info("All tokens cleared")


class OAuth2MobileAuthFlow:
    """
    Helper class to manage the complete OAuth2 mobile authentication flow.
    """

    def __init__(self, auth_handler: OAuth2MobileAuth):
        """
        Initialize the authentication flow handler.

        Args:
            auth_handler: OAuth2MobileAuth instance
        """
        self.auth = auth_handler
        self.state = None

    def start_authentication(self, use_pkce: bool = True) -> str:
        """
        Start the authentication flow and return the authorization URL.

        Args:
            use_pkce: Whether to use PKCE

        Returns:
            Authorization URL for the user to visit
        """
        self.state = secrets.token_urlsafe(32)
        auth_url = self.auth.get_authorization_url(use_pkce=use_pkce, state=self.state)
        logger.info("Authentication flow started")
        return auth_url

    def handle_callback(self, callback_url: str) -> bool:
        """
        Handle the OAuth2 callback and exchange code for token.

        Args:
            callback_url: Full callback URL with code and state

        Returns:
            True if authentication successful, False otherwise
        """
        try:
            # Parse callback URL
            parsed = urlparse(callback_url)
            query_params = parse_qs(parsed.query)
            
            # Verify state parameter
            returned_state = query_params.get("state", [None])[0]
            if returned_state != self.state:
                logger.error("State parameter mismatch - possible CSRF attack")
                return False
            
            # Check for errors
            error = query_params.get("error", [None])[0]
            if error:
                error_description = query_params.get("error_description", [None])[0]
                logger.error(f"Authorization error: {error} - {error_description}")
                return False
            
            # Exchange code for token
            code = query_params.get("code", [None])[0]
            if not code:
                logger.error("No authorization code in callback")
                return False
            
            self.auth.exchange_code_for_token(code)
            logger.info("Successfully completed authentication flow")
            return True
            
        except Exception as e:
            logger.error(f"Error handling callback: {str(e)}")
            return False
