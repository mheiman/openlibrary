# OpenLibrary OAuth2 Implementation

This directory contains the OAuth2 implementation for OpenLibrary, enabling mobile applications and third-party clients to authenticate users via OAuth2 authorization code flow with PKCE support.

## Overview

The OAuth2 implementation provides:

- **Authorization Code Flow with PKCE**: Secure authentication flow for mobile and web applications
- **Token Management**: Access tokens, refresh tokens, and token validation
- **User Info Endpoint**: Standard OAuth2 user information endpoint
- **Token-to-Cookie Exchange**: Special endpoint to exchange OAuth2 tokens for OpenLibrary session cookies
- **Comprehensive Security**: CSRF protection, PKCE validation, and secure token storage

## Architecture

### Core Components

1. **`mobile_auth.py`**: Client-side OAuth2 implementation for mobile applications
   - PKCE (Proof Key for Code Exchange) support
   - Token management and storage
   - Secure token handling

2. **`provider.py`**: Server-side OAuth2 provider implementation
   - Authorization and token endpoints
   - Client management
   - Authorization code generation and validation
   - Token generation and validation
   - PKCE validation

3. **`openlibrary/plugins/oauth2/`**: Web integration layer
   - HTTP endpoint handlers (in `code.py`)
   - Integration with OpenLibrary authentication system
   - Session management
   - Uses Infogami's `delegate.RawText()` for JSON responses

### Data Models

#### OAuth2Client
Represents an OAuth2 client application with:
- `client_id`: Unique client identifier
- `client_secret`: Client secret for confidential clients
- `redirect_uris`: Registered redirect URIs
- `scopes`: Supported OAuth2 scopes
- `is_confidential`: Whether client is confidential (requires client secret)

#### AuthorizationCode
Represents an OAuth2 authorization code with:
- `code`: The authorization code string
- `client_id`: Associated client ID
- `user_id`: User who authorized the code
- `redirect_uri`: Redirect URI for this authorization
- `scopes`: Granted scopes
- `code_challenge`: PKCE code challenge (if used)
- `expires_at`: Expiration timestamp

#### Token
Represents an OAuth2 access token with:
- `access_token`: The access token string
- `token_type`: Token type (usually "Bearer")
- `expires_in`: Seconds until expiration
- `refresh_token`: Optional refresh token
- `scope`: Space-separated list of scopes

**Storage Note**: Tokens are stored in memcache with an associated `user_id` (e.g., `/people/username`) to enable user lookup when validating tokens. This allows the system to retrieve both the User document (from Infogami) and Account data (from the store) for complete user information including email addresses.

## Endpoints

### `/oauth2/authorize`
**Method**: GET
**Purpose**: Initiate OAuth2 authorization flow

**Parameters**:
- `response_type`: Must be "code"
- `client_id`: OAuth2 client ID
- `redirect_uri`: Redirect URI after authorization
- `scope`: Requested scopes (space-separated)
- `state`: CSRF protection state parameter
- `code_challenge`: PKCE code challenge
- `code_challenge_method`: PKCE method (usually "S256")

**Flow**:
1. User is redirected to this endpoint by client application
2. If user is not authenticated, they are redirected to login
3. After authentication, user is redirected back to client with authorization code

### `/oauth2/authorize/complete`
**Method**: GET
**Purpose**: Complete authorization after user login

**Internal Use**: This endpoint is used internally after user authentication to complete the authorization flow.

### `/oauth2/token`
**Method**: POST
**Purpose**: Exchange authorization code for access token

**Parameters** (Authorization Code Grant):
- `grant_type`: Must be "authorization_code"
- `code`: Authorization code from `/oauth2/authorize`
- `redirect_uri`: Must match original redirect URI
- `client_id`: OAuth2 client ID
- `client_secret`: OAuth2 client secret (for confidential clients)
- `code_verifier`: PKCE code verifier

**Parameters** (Refresh Token Grant):
- `grant_type`: Must be "refresh_token"
- `refresh_token`: Refresh token from previous token response
- `client_id`: OAuth2 client ID
- `client_secret`: OAuth2 client secret (for confidential clients)

**Response** (Success):
```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "...",
  "scope": "openid profile email"
}
```

**Response** (Error):
```json
{
  "error": "invalid_grant",
  "error_description": "authorization_code invalid or expired"
}
```

**Note**: All responses from this endpoint are JSON (including errors), compliant with OAuth 2.0 specification (RFC 6749).

### `/oauth2/userinfo`
**Method**: GET
**Purpose**: Get user information using access token

**Authentication**: Requires `Authorization: Bearer <access_token>` header

**Response**:
```json
{
  "sub": "/people/username",
  "username": "username",
  "email": "user@example.com",
  "displayname": "User Display Name"
}
```

**Note**: The `sub` field contains the user's OpenLibrary key (e.g., `/people/username`). Email addresses are retrieved from the Account store and may be empty if not available.

### `/oauth2/token-to-cookie`
**Method**: POST
**Purpose**: Exchange OAuth2 access token for OpenLibrary session cookie

**Parameters**:
- `access_token`: OAuth2 access token

**Response**:
```json
{
  "success": true,
  "message": "Session cookie set successfully",
  "user": {
    "username": "username",
    "email": "user@example.com",
    "displayname": "User Display Name"
  }
}
```

**Special Behavior**: This endpoint sets the OpenLibrary session cookie, allowing the user to be authenticated in the web interface.

## Mobile App Integration

### Authorization Flow

1. **Generate Authorization URL**:
```python
from openlibrary.oauth2.mobile_auth import OAuth2MobileAuth

auth = OAuth2MobileAuth(
    client_id="mobile_app",
    client_secret="mobile_app_secret",
    redirect_uri="com.example.openlibrary://oauth2/callback",
    authorization_endpoint="https://openlibrary.org/oauth2/authorize",
    token_endpoint="https://openlibrary.org/oauth2/token"
)

authorization_url, state = auth.generate_authorization_url()
```

2. **Open Browser**: Redirect user to `authorization_url` in mobile browser

3. **Handle Callback**: Mobile app receives callback with authorization code:
```python
# URL: com.example.openlibrary://oauth2/callback?code=AUTH_CODE&state=STATE
code = parse_url_query(url)['code']
state = parse_url_query(url)['state']

# Exchange code for token
token = auth.exchange_code_for_token(code, state)
```

4. **Use Token**: Use the access token for API requests or exchange for session cookie

### Token to Cookie Exchange

For mobile apps that need to use OpenLibrary web views:

```python
import requests

response = requests.post(
    "https://openlibrary.org/oauth2/token-to-cookie",
    data={"access_token": token.access_token}
)

# This sets the session cookie, allowing web views to be authenticated
```

## Security Features

### PKCE (Proof Key for Code Exchange)
- Prevents authorization code interception attacks
- Required for public clients (mobile apps)
- Uses S256 (SHA-256) challenge method

### CSRF Protection
- State parameter validation
- One-time use authorization codes
- Secure token storage

### Token Security
- Short-lived access tokens (1 hour)
- Long-lived refresh tokens
- Secure random token generation
- Proper token expiration handling

## Configuration

### Client Registration

OAuth2 clients are configured in `conf/openlibrary.yml`:

```yaml
# OAuth2 Client Configuration
oauth2_clients:
    - client_id: mobile_app
      client_secret: CHANGEME_mobile_app_secret
      name: OpenLibrary Mobile App
      description: Official OpenLibrary mobile application
      redirect_uris:
          - http://localhost:8080/oauth2/callback
      scopes:
          - openid
          - profile
          - email
      is_confidential: true
```

**Production Deployment:**
- Development config files use `CHANGEME_` prefix for secrets (safe to commit)
- Production deployment replaces these values via configuration management
- Follows OpenLibrary's existing pattern for secrets (same as `ia_access_secret`)
- Supports multiple OAuth2 clients by adding additional entries to the list

**Client Configuration Options:**
- `client_id` (required): Unique identifier for the OAuth2 client
- `client_secret` (required): Secret key for confidential clients
- `name` (required): Human-readable client name
- `description` (optional): Client description
- `redirect_uris` (required): List of allowed redirect URIs
- `scopes` (optional): List of allowed scopes (defaults to `["openid", "profile", "email"]`)
- `is_confidential` (optional): Whether client is confidential (default: `true`)

**Redirect URI Patterns:**
- Web callbacks: `https://example.com/oauth2/callback`
- Development: `http://localhost:8080/oauth2/callback`
- Native apps: `com.example.app://oauth2/callback` (custom URL schemes)
- Universal Links: `https://app.example.com/oauth2/callback` (iOS/Android app links)

### Scopes

Supported scopes:
- `openid`: OpenID Connect authentication
- `profile`: User profile information
- `email`: User email address

## Testing

The implementation includes comprehensive tests in `tests/test_oauth2.py`:

- Client creation and validation
- Authorization code generation and validation
- Token generation and validation
- PKCE validation
- Error handling

## Integration with Existing System

The OAuth2 implementation integrates with OpenLibrary's existing authentication system:

1. **User Authentication**: Uses OpenLibrary's existing login system (`/account/login`) for user authentication
2. **Session Management**:
   - Leverages OpenLibrary's session cookie mechanism via `generate_login_code()` from Account objects
   - Token-to-cookie endpoint bridges OAuth2 tokens to traditional session cookies
3. **User Management**:
   - Works with existing OpenLibrary User documents (Infogami, at `/people/username`)
   - Integrates with Account objects (store) for private data like email addresses
   - Uses `OpenLibraryAccount.get_by_username()` to retrieve account information
4. **Storage**: Uses memcache for authorization codes and tokens (5-minute and 1-hour expiration respectively)

## Future Enhancements

1. **Database-Backed Storage**: Replace memcache with database-backed storage for better persistence and token management
2. **Client Management UI**: Admin interface for managing OAuth2 clients
3. **Additional Scopes**: Support for more granular permissions
4. **Token Revocation**: OAuth2 token revocation endpoint (RFC 7009)
5. **JWT Tokens**: Support for JWT-based tokens
6. **OpenID Connect**: Full OpenID Connect implementation
7. **Refresh Token Support**: Complete implementation of refresh token grant flow
8. **Request Storage**: Move pending authorization requests from in-memory storage to memcache/database

## Deployment

To enable OAuth2 in production:

1. **Configure Clients**: Register production OAuth2 clients with proper redirect URIs
2. **Set Up Secrets**: Configure secure client secrets
3. **Enable Endpoints**: Ensure OAuth2 endpoints are accessible
4. **Monitor Usage**: Set up monitoring for OAuth2 usage and potential abuse

## Implementation Notes

### Infogami Integration

The OAuth2 implementation must carefully handle Infogami's template system to return proper JSON responses:

1. **Use `delegate.RawText()`**: All JSON endpoints use `delegate.RawText(json_string, content_type="application/json")` to prevent Infogami from wrapping responses in HTML templates.

2. **Handle "Nothing" Objects**: Infogami returns `Nothing` objects instead of raising `AttributeError` for missing attributes. The code checks `type(obj).__name__ == 'Nothing'` to detect these.

3. **User vs Account**: OpenLibrary has two separate user representations:
   - **User** (Infogami document at `/people/username`): Public profile data, displayname
   - **Account** (store object): Private data including email, password hash
   - OAuth2 endpoints retrieve both using `web.ctx.site.get()` and `OpenLibraryAccount.get_by_username()`

### Token-User Association

Tokens are stored in memcache with an associated `user_id` field that contains the full user key (e.g., `/people/username`). This enables proper user lookup when validating tokens, allowing the system to:
1. Retrieve the User document from Infogami
2. Fetch the corresponding Account from the store
3. Return complete user information including email addresses

## Troubleshooting

### Common Issues

1. **Invalid Redirect URI**: Ensure redirect URIs are properly registered for the client
2. **PKCE Mismatch**: Verify code verifier matches the code challenge
3. **Token Expiration**: Handle token expiration and refresh appropriately
4. **CSRF Protection**: Always validate state parameters
5. **"Nothing" Object Errors**: If seeing JSON serialization errors about `Nothing` objects, ensure all user attribute access uses the `safe_get_attr()` helper function or checks for `Nothing` types

### Debugging

The OAuth2 implementation uses minimal logging appropriate for production:
- **ERROR**: System failures and unexpected exceptions
- **WARNING**: Security events (invalid codes, unknown clients, PKCE failures, expired tokens)
- **INFO**: Currently minimal, reserved for critical operational events

All OAuth2 logs use the `openlibrary.oauth2` logger. To see warnings and errors:
```python
import logging
logging.getLogger("openlibrary.oauth2").setLevel(logging.WARNING)
```

**Security Note**: OAuth2 logs do not include sensitive data like tokens, secrets, or full authorization codes. Only token prefixes (first 10 characters) may be logged for debugging purposes.

## References

- [OAuth 2.0 Specification](https://tools.ietf.org/html/rfc6749)
- [OAuth 2.0 for Native Apps](https://tools.ietf.org/html/rfc8252)
- [PKCE Specification](https://tools.ietf.org/html/rfc7636)
- [OpenID Connect](https://openid.net/connect/)