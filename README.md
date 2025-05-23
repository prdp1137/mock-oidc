# Mock OpenID Connect Server

This is a mock implementation of an OpenID Connect (OIDC) server using Flask. It supports `client_credentials`, `authorization_code`, and `refresh_token` grant types. The server also provides endpoints for OpenID configuration and JSON Web Key Set (JWKS).

## Features

- **Authorization Endpoint**: Handles authorization requests and issues authorization codes.
- **Token Endpoint**: Issues access tokens and refresh tokens based on authorization codes, client credentials, and refresh tokens.
- **UserInfo Endpoint**: Provides user information based on access tokens.
- **OAuth 2.0 Dynamic Client Registration**: Full support for RFC 7591 and RFC 7592
  - Client registration endpoint
  - Client configuration management (read, update, delete)
  - Support for both web and native applications
  - Public and confidential client types
- **JWKS Endpoint**: Provides the JSON Web Key Set for token verification.
- **Supports Multiple Grant Types**: Supports `client_credentials`, `authorization_code`, and `refresh_token` grant types.
- **Supports PKCE**: Supports Proof Key for Code Exchange (PKCE) for authorization code flow.
- **Well-Known Configuration**: Provides the OpenID configuration for the server.

## Endpoints

- **Authorization Endpoint**: `/authorize`
- **Token Endpoint**: `/token`
- **UserInfo Endpoint**: `/userinfo`
- **Client Registration Endpoint**: `/register` (POST)
- **Client Configuration Endpoint**: `/register/{client_id}` (GET, PUT, DELETE)
- **Well-Known Configuration**: `/.well-known/openid-configuration`
- **JWKS Endpoint**: `/jwks`

## Setup

### Prerequisites

- Python 3.7+
- Flask
- Flask-SQLAlchemy
- cryptography
- PyJWT

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/prd1137/mock-oidc.git
   cd mock-oidc
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

### Running the Server

1. Run the server:

   ```bash
   python3 run.py
   ```

2. The server will start at `http://localhost:5000`.

## Example Usage

### Authorization Request

Send a GET request to the authorization endpoint:

```http
GET /authorize?response_type=code&client_id=your-client-id&redirect_uri=your-redirect-uri&state=random-state-string
```

### Authorization Request with PKCE

Send a GET request to the authorization endpoint with PKCE parameters:

```http
GET /authorize?response_type=code&client_id=your-client-id&redirect_uri=your-redirect-uri&state=random-state-string&code_challenge=code-challenge&code_challenge_method=S256
```

### Token Request

Send a POST request to the token endpoint to exchange an authorization code for tokens:

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&client_id=your-client-id&client_secret=your-client-secret&code=authorization-code
```

### Token Request with PKCE

Send a POST request to the token endpoint with PKCE parameters:

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&client_id=your-client-id&client_secret=your-client-secret&code=authorization-code&code_verifier=code-verifier&redirect_uri=your-redirect-uri
```

### UserInfo Request

Send a GET request to the userinfo endpoint with the access token:

```http
GET /userinfo
Authorization: Bearer access-token
```

### Client Registration

Send a POST request to the register endpoint to register a new client:

```http
POST /register
Content-Type: application/json

{
  "redirect_uris": "http://localhost:5000/callback"
}
```

### Well-Known Configuration

Retrieve the OpenID configuration:

```http
GET /.well-known/openid-configuration
```

### JWKS Endpoint

Retrieve the JSON Web Key Set:

```http
GET /jwks
```

### Refresh Token

Send a POST request to the token endpoint to refresh an access token:

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&client_id=your-client-id&client_secret=your-client-secret&refresh_token=refresh-token
```

## OAuth 2.0 Dynamic Client Registration

This server implements RFC 7591 (OAuth 2.0 Dynamic Client Registration Protocol) and RFC 7592 (OAuth 2.0 Dynamic Client Registration Management Protocol).

### Quick Start

1. **Register a new client**:
   ```bash
   curl -X POST http://localhost:5000/register \
     -H "Content-Type: application/json" \
     -d '{
       "redirect_uris": ["https://example.com/callback"],
       "client_name": "My App",
       "application_type": "web"
     }'
   ```

2. **Use the returned `client_id` and `client_secret` for OAuth flows**

3. **Manage your client** using the `registration_access_token`:
   ```bash
   # Read client configuration
   curl -X GET http://localhost:5000/register/{client_id} \
     -H "Authorization: Bearer {registration_access_token}"
   
   # Update client configuration
   curl -X PUT http://localhost:5000/register/{client_id} \
     -H "Authorization: Bearer {registration_access_token}" \
     -H "Content-Type: application/json" \
     -d '{"client_name": "Updated App Name"}'
   
   # Delete client
   curl -X DELETE http://localhost:5000/register/{client_id} \
     -H "Authorization: Bearer {registration_access_token}"
   ```

For detailed examples and documentation, see [DYNAMIC_CLIENT_REGISTRATION.md](DYNAMIC_CLIENT_REGISTRATION.md).
```