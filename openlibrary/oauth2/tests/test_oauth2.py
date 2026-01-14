"""
Test OAuth2 implementation
"""

from openlibrary.oauth2.provider import AuthorizationCode, OAuth2Client, OAuth2Provider


def test_oauth2_client_creation():
    """Test OAuth2 client creation."""
    client = OAuth2Client(
        client_id="test_client",
        client_secret="test_secret",
        redirect_uris=["http://localhost/callback"],
        name="Test Client",
    )

    assert client.client_id == "test_client"
    assert client.client_secret == "test_secret"
    assert client.redirect_uris == ["http://localhost/callback"]
    assert client.name == "Test Client"
    assert client.scopes == ["openid", "profile", "email"]
    assert client.is_confidential


def test_oauth2_client_validation():
    """Test OAuth2 client redirect URI validation."""
    client = OAuth2Client(
        client_id="test_client",
        client_secret="test_secret",
        redirect_uris=["http://localhost/callback", "http://example.com/callback"],
        name="Test Client",
    )

    assert client.validate_redirect_uri("http://localhost/callback")
    assert client.validate_redirect_uri("http://example.com/callback")
    assert not client.validate_redirect_uri("http://evil.com/callback")


def test_authorization_code_creation():
    """Test authorization code creation."""
    auth_code = AuthorizationCode(
        code="test_code",
        client_id="test_client",
        user_id="/users/test_user",
        redirect_uri="http://localhost/callback",
        scopes=["openid", "profile"],
    )

    assert auth_code.code == "test_code"
    assert auth_code.client_id == "test_client"
    assert auth_code.user_id == "/users/test_user"
    assert auth_code.redirect_uri == "http://localhost/callback"
    assert auth_code.scopes == ["openid", "profile"]
    assert not auth_code.is_expired()


def test_oauth2_provider_client_management():
    """Test OAuth2 provider client management."""
    provider = OAuth2Provider()

    client = OAuth2Client(
        client_id="test_client",
        client_secret="test_secret",
        redirect_uris=["http://localhost/callback"],
        name="Test Client",
    )

    # Register client
    provider.register_client(client)

    # Get client
    retrieved_client = provider.get_client("test_client")
    assert retrieved_client.client_id == "test_client"

    # Get non-existent client
    assert provider.get_client("non_existent") is None


def test_oauth2_provider_authorization_code_generation():
    """Test OAuth2 provider authorization code generation."""
    provider = OAuth2Provider()

    client = OAuth2Client(
        client_id="test_client",
        client_secret="test_secret",
        redirect_uris=["http://localhost/callback"],
        name="Test Client",
    )

    provider.register_client(client)

    # Generate authorization code
    auth_code = provider.generate_authorization_code(
        client_id="test_client",
        user_id="/users/test_user",
        redirect_uri="http://localhost/callback",
        scopes=["openid", "profile"],
    )

    assert auth_code.code is not None
    assert auth_code.client_id == "test_client"
    assert auth_code.user_id == "/users/test_user"
    assert auth_code.redirect_uri == "http://localhost/callback"
    assert auth_code.scopes == ["openid", "profile"]
    assert not auth_code.is_expired()


def test_oauth2_provider_authorization_code_validation():
    """Test OAuth2 provider authorization code validation."""
    provider = OAuth2Provider()

    client = OAuth2Client(
        client_id="test_client",
        client_secret="test_secret",
        redirect_uris=["http://localhost/callback"],
        name="Test Client",
    )

    provider.register_client(client)

    # Generate authorization code
    auth_code = provider.generate_authorization_code(
        client_id="test_client",
        user_id="/users/test_user",
        redirect_uri="http://localhost/callback",
        scopes=["openid", "profile"],
    )

    # Validate the code
    validated_code = provider.validate_authorization_code(
        code=auth_code.code,
        client_id="test_client",
        redirect_uri="http://localhost/callback",
    )

    assert validated_code is not None
    assert validated_code.code == auth_code.code

    # Test invalid client
    assert (
        provider.validate_authorization_code(
            code=auth_code.code,
            client_id="wrong_client",
            redirect_uri="http://localhost/callback",
        )
        is None
    )

    # Test invalid redirect URI
    assert (
        provider.validate_authorization_code(
            code=auth_code.code,
            client_id="test_client",
            redirect_uri="http://wrong/callback",
        )
        is None
    )


def test_oauth2_provider_token_generation():
    """Test OAuth2 provider token generation."""
    provider = OAuth2Provider()

    client = OAuth2Client(
        client_id="test_client",
        client_secret="test_secret",
        redirect_uris=["http://localhost/callback"],
        name="Test Client",
    )

    provider.register_client(client)

    # Generate authorization code
    auth_code = provider.generate_authorization_code(
        client_id="test_client",
        user_id="/users/test_user",
        redirect_uri="http://localhost/callback",
        scopes=["openid", "profile"],
    )

    # Generate token
    token = provider.generate_token(auth_code, "test_client")

    assert token.access_token is not None
    assert token.token_type == "Bearer"
    assert token.expires_in == 3600
    assert token.refresh_token is not None
    assert token.scope == "openid profile"

    # Verify authorization code was deleted
    assert auth_code.code not in provider.authorization_codes


def test_oauth2_provider_token_validation():
    """Test OAuth2 provider token validation."""
    provider = OAuth2Provider()

    client = OAuth2Client(
        client_id="test_client",
        client_secret="test_secret",
        redirect_uris=["http://localhost/callback"],
        name="Test Client",
    )

    provider.register_client(client)

    # Generate authorization code
    auth_code = provider.generate_authorization_code(
        client_id="test_client",
        user_id="/users/test_user",
        redirect_uri="http://localhost/callback",
        scopes=["openid", "profile"],
    )

    # Generate token
    token = provider.generate_token(auth_code, "test_client")

    # Validate token
    validated_token = provider.validate_token(token.access_token)
    assert validated_token is not None
    assert validated_token.access_token == token.access_token

    # Test invalid token
    assert provider.validate_token("invalid_token") is None


def test_oauth2_provider_pkce_validation():
    """Test OAuth2 provider PKCE validation."""
    provider = OAuth2Provider()

    # Test S256 PKCE
    import base64
    import hashlib
    import secrets

    code_verifier = secrets.token_urlsafe(96)
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )

    # Test valid PKCE
    assert provider._validate_pkce(f"S256:{code_challenge}", code_verifier)

    # Test invalid PKCE
    assert not provider._validate_pkce(f"S256:{code_challenge}", "wrong_verifier")

    # Test plain PKCE
    assert provider._validate_pkce(code_verifier, code_verifier)
    assert not provider._validate_pkce(code_verifier, "wrong_verifier")
