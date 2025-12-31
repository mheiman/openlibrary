"""
OAuth2 Mobile Authentication Module

This module provides OAuth2 authentication support for mobile applications,
including authorization flow, token management, and secure credential handling.
"""

import json
import hashlib
import secrets
from typing import Optional, Dict, Any, Tuple
from urllib.parse import urlencode, parse_qs, urlparse
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class TokenResponse:
    """Represents an OAuth2 token response"""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int = 3600
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert token response to dictionary"""
        return {k: v for k, v in asdict(self).items() if v is not None}
    
    def is_expired(self, issued_at: Optional[datetime] = None) -> bool:
        """Check if token is expired"""
        if issued_at is None:
            issued_at = datetime.utcnow()
        expiration_time = issued_at + timedelta(seconds=self.expires_in)
        return datetime.utcnow() >= expiration_time


@dataclass
class AuthorizationRequest:
    """Represents an OAuth2 authorization request"""
    client_id: str
    redirect_uri: str
    response_type: str = "code"
    scope: Optional[str] = None
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    
    def to_query_params(self) -> str:
        """Convert to URL query parameters"""
        params = {k: v for k, v in asdict(self).items() if v is not None}
        return urlencode(params)


class PKCEFlow:
    """
    Implements PKCE (Proof Key for Public Clients) flow
    for secure mobile authentication without requiring client secret
    """
    
    CHALLENGE_METHOD_S256 = "S256"
    CHALLENGE_METHOD_PLAIN = "plain"
    
    @staticmethod
    def generate_code_verifier(length: int = 128) -> str:
        """
        Generate a cryptographically secure code verifier
        
        Args:
            length: Length of the verifier (between 43 and 128)
            
        Returns:
            A URL-safe random string
        """
        if not (43 <= length <= 128):
            raise ValueError("Code verifier length must be between 43 and 128")
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_code_challenge(code_verifier: str, method: str = CHALLENGE_METHOD_S256) -> Tuple[str, str]:
        """
        Generate code challenge from verifier
        
        Args:
            code_verifier: The code verifier string
            method: The challenge method (S256 or plain)
            
        Returns:
            Tuple of (code_challenge, method)
        """
        if method == PKCEFlow.CHALLENGE_METHOD_S256:
            challenge = hashlib.sha256(code_verifier.encode()).digest()
            code_challenge = __import__('base64').urlsafe_b64encode(challenge).decode().rstrip('=')
            return code_challenge, method
        elif method == PKCEFlow.CHALLENGE_METHOD_PLAIN:
            return code_verifier, method
        else:
            raise ValueError(f"Unknown challenge method: {method}")
    
    @staticmethod
    def verify_code_challenge(code_verifier: str, code_challenge: str, method: str) -> bool:
        """
        Verify that a code verifier matches a code challenge
        
        Args:
            code_verifier: The code verifier to verify
            code_challenge: The code challenge to verify against
            method: The challenge method used
            
        Returns:
            True if verification succeeds
        """
        if method == PKCEFlow.CHALLENGE_METHOD_S256:
            computed_challenge, _ = PKCEFlow.generate_code_challenge(code_verifier, method)
            return computed_challenge == code_challenge
        elif method == PKCEFlow.CHALLENGE_METHOD_PLAIN:
            return code_verifier == code_challenge
        else:
            return False


class MobileAuthClient:
    """
    OAuth2 client for mobile applications
    Handles authorization flow, token management, and PKCE
    """
    
    def __init__(self, client_id: str, redirect_uri: str, auth_endpoint: str, token_endpoint: str):
        """
        Initialize mobile auth client
        
        Args:
            client_id: OAuth2 client ID
            redirect_uri: Redirect URI for OAuth2 callback
            auth_endpoint: Authorization endpoint URL
            token_endpoint: Token endpoint URL
        """
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.auth_endpoint = auth_endpoint
        self.token_endpoint = token_endpoint
        self.code_verifier: Optional[str] = None
        self.state: Optional[str] = None
        self.tokens: Dict[str, TokenResponse] = {}
        self.token_issued_at: Dict[str, datetime] = {}
    
    def generate_authorization_url(self, scope: Optional[str] = None, use_pkce: bool = True) -> str:
        """
        Generate authorization URL for mobile client
        
        Args:
            scope: Space-separated list of requested scopes
            use_pkce: Whether to use PKCE flow (recommended for mobile)
            
        Returns:
            Authorization URL to redirect user to
        """
        # Generate state for CSRF protection
        self.state = secrets.token_urlsafe(32)
        
        # Generate PKCE parameters if requested
        code_challenge = None
        code_challenge_method = None
        if use_pkce:
            self.code_verifier = PKCEFlow.generate_code_verifier()
            code_challenge, code_challenge_method = PKCEFlow.generate_code_challenge(
                self.code_verifier
            )
        
        # Create authorization request
        auth_request = AuthorizationRequest(
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            response_type="code",
            scope=scope,
            state=self.state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        
        return f"{self.auth_endpoint}?{auth_request.to_query_params()}"
    
    def handle_authorization_response(self, redirect_url: str, expected_state: Optional[str] = None) -> str:
        """
        Handle authorization response from OAuth2 provider
        
        Args:
            redirect_url: The redirect URL containing authorization code
            expected_state: Expected state value for CSRF validation
            
        Returns:
            Authorization code for token exchange
            
        Raises:
            ValueError: If response is invalid or state doesn't match
        """
        parsed_url = urlparse(redirect_url)
        query_params = parse_qs(parsed_url.query)
        
        # Check for errors
        if 'error' in query_params:
            error = query_params['error'][0]
            error_description = query_params.get('error_description', ['Unknown error'])[0]
            raise ValueError(f"Authorization error: {error} - {error_description}")
        
        # Validate state parameter
        state = query_params.get('state', [None])[0]
        expected = expected_state or self.state
        if state != expected:
            raise ValueError("State parameter mismatch - possible CSRF attack")
        
        # Extract authorization code
        code = query_params.get('code', [None])[0]
        if not code:
            raise ValueError("No authorization code in response")
        
        return code
    
    def exchange_code_for_token(self, code: str, http_client: Any) -> TokenResponse:
        """
        Exchange authorization code for access token
        
        Args:
            code: Authorization code from OAuth2 provider
            http_client: HTTP client with post method for token request
            
        Returns:
            TokenResponse containing access token and metadata
        """
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': self.client_id,
            'code': code,
            'redirect_uri': self.redirect_uri,
        }
        
        # Include PKCE verifier if available
        if self.code_verifier:
            token_data['code_verifier'] = self.code_verifier
        
        response = http_client.post(self.token_endpoint, data=token_data)
        
        if response.status_code != 200:
            raise ValueError(f"Token exchange failed: {response.text}")
        
        token_json = response.json()
        token_response = TokenResponse(**token_json)
        
        # Cache token
        self.tokens['current'] = token_response
        self.token_issued_at['current'] = datetime.utcnow()
        
        return token_response
    
    def get_access_token(self) -> Optional[str]:
        """
        Get current valid access token
        
        Returns:
            Access token if available and valid, None otherwise
        """
        token = self.tokens.get('current')
        if not token:
            return None
        
        issued_at = self.token_issued_at.get('current')
        if token.is_expired(issued_at):
            return None
        
        return token.access_token
    
    def refresh_access_token(self, http_client: Any) -> Optional[TokenResponse]:
        """
        Refresh access token using refresh token
        
        Args:
            http_client: HTTP client with post method for token request
            
        Returns:
            New TokenResponse or None if refresh fails
        """
        token = self.tokens.get('current')
        if not token or not token.refresh_token:
            return None
        
        token_data = {
            'grant_type': 'refresh_token',
            'client_id': self.client_id,
            'refresh_token': token.refresh_token,
        }
        
        try:
            response = http_client.post(self.token_endpoint, data=token_data)
            if response.status_code != 200:
                return None
            
            token_json = response.json()
            new_token = TokenResponse(**token_json)
            
            # Update cached token
            self.tokens['current'] = new_token
            self.token_issued_at['current'] = datetime.utcnow()
            
            return new_token
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return None
    
    def clear_tokens(self) -> None:
        """Clear cached tokens"""
        self.tokens.clear()
        self.token_issued_at.clear()
        self.code_verifier = None
        self.state = None


class MobileAuthManager:
    """
    Manager for multiple mobile auth clients and sessions
    """
    
    def __init__(self):
        """Initialize auth manager"""
        self.clients: Dict[str, MobileAuthClient] = {}
        self.sessions: Dict[str, Dict[str, Any]] = {}
    
    def register_client(self, client_id: str, client: MobileAuthClient) -> None:
        """
        Register a mobile auth client
        
        Args:
            client_id: Unique client identifier
            client: MobileAuthClient instance
        """
        self.clients[client_id] = client
    
    def get_client(self, client_id: str) -> Optional[MobileAuthClient]:
        """Get registered client"""
        return self.clients.get(client_id)
    
    def create_session(self, session_id: str, client_id: str) -> None:
        """
        Create a new auth session
        
        Args:
            session_id: Unique session identifier
            client_id: Client ID for this session
        """
        if client_id not in self.clients:
            raise ValueError(f"Unknown client: {client_id}")
        
        self.sessions[session_id] = {
            'client_id': client_id,
            'created_at': datetime.utcnow(),
            'token': None,
        }
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        return self.sessions.get(session_id)
    
    def cleanup_expired_sessions(self, max_age_hours: int = 24) -> None:
        """
        Remove expired sessions
        
        Args:
            max_age_hours: Maximum session age in hours
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        expired = [
            sid for sid, data in self.sessions.items()
            if data['created_at'] < cutoff_time
        ]
        for sid in expired:
            del self.sessions[sid]
