# Mock OpenID Connect Server

This is a mock implementation of an OpenID Connect (OIDC) server using Flask. It supports `client_credentials`, `authorization_code`, and `refresh_token` grant types. The server also provides endpoints for OpenID configuration and JSON Web Key Set (JWKS).

## Features

- **Authorization Endpoint**: Handles authorization requests and issues authorization codes.
- **Token Endpoint**: Issues access tokens and refresh tokens based on authorization codes, client credentials, and refresh tokens.
- **UserInfo Endpoint**: Provides user information based on access tokens.
- **Client Registration Endpoint**: Allows dynamic registration of clients.
- **JWKS Endpoint**: Provides the JSON Web Key Set for token verification.
- **Supports Multiple Grant Types**: Supports `client_credentials`, `authorization_code`, and `refresh_token` grant types.
- **Supports PKCE**: Supports Proof Key for Code Exchange (PKCE) for authorization code flow.
- **Well-Known Configuration**: Provides the OpenID configuration for the server.

## Endpoints

- **Authorization Endpoint**: `/authorize`
- **Token Endpoint**: `/token`
- **UserInfo Endpoint**: `/userinfo`
- **Client Registration Endpoint**: `/register`
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