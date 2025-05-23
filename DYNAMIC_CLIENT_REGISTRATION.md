# OAuth 2.0 Dynamic Client Registration Protocol Examples

This document provides examples of how to use the OAuth 2.0 Dynamic Client Registration Protocol with this mock OIDC server.

## Overview

The server now supports RFC 7591 (OAuth 2.0 Dynamic Client Registration Protocol) and RFC 7592 (OAuth 2.0 Dynamic Client Registration Management Protocol).

## Endpoints

- **Client Registration**: `POST /register`
- **Client Configuration**: `GET /register/{client_id}`
- **Client Update**: `PUT /register/{client_id}`
- **Client Deletion**: `DELETE /register/{client_id}`

## Examples

### 1. Register a New Client

```bash
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://example.com/callback"],
    "client_name": "My OAuth App",
    "client_uri": "https://example.com",
    "logo_uri": "https://example.com/logo.png",
    "scope": "openid profile email",
    "contacts": ["admin@example.com"],
    "tos_uri": "https://example.com/tos",
    "policy_uri": "https://example.com/privacy",
    "token_endpoint_auth_method": "client_secret_basic",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "application_type": "web"
  }'
```

Response:
```json
{
  "client_id": "abc123...",
  "client_secret": "xyz789...",
  "client_id_issued_at": 1640995200,
  "client_secret_expires_at": 0,
  "redirect_uris": ["https://example.com/callback"],
  "client_name": "My OAuth App",
  "client_uri": "https://example.com",
  "logo_uri": "https://example.com/logo.png",
  "scope": "openid profile email",
  "contacts": ["admin@example.com"],
  "tos_uri": "https://example.com/tos",
  "policy_uri": "https://example.com/privacy",
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "application_type": "web",
  "registration_access_token": "reg_token_123...",
  "registration_client_uri": "http://localhost:5000/register/abc123..."
}
```

### 2. Register a Public Client (Native App)

```bash
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["com.example.app://callback"],
    "client_name": "My Mobile App",
    "application_type": "native",
    "token_endpoint_auth_method": "none",
    "grant_types": ["authorization_code"],
    "response_types": ["code"]
  }'
```

### 3. Read Client Configuration

```bash
curl -X GET http://localhost:5000/register/{client_id} \
  -H "Authorization: Bearer {registration_access_token}"
```

### 4. Update Client Configuration

```bash
curl -X PUT http://localhost:5000/register/{client_id} \
  -H "Authorization: Bearer {registration_access_token}" \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["https://example.com/callback", "https://example.com/callback2"],
    "client_name": "Updated App Name",
    "scope": "openid profile email phone"
  }'
```

### 5. Delete Client

```bash
curl -X DELETE http://localhost:5000/register/{client_id} \
  -H "Authorization: Bearer {registration_access_token}"
```

## Client Metadata Fields

### Required Fields
- `redirect_uris`: Array of redirect URI strings

### Optional Fields
- `client_name`: Human-readable name of the client
- `client_uri`: URL of the client's homepage
- `logo_uri`: URL of the client's logo image
- `scope`: Space-separated list of scope values
- `contacts`: Array of contact email addresses
- `tos_uri`: URL of the client's terms of service
- `policy_uri`: URL of the client's privacy policy
- `jwks_uri`: URL of the client's JSON Web Key Set
- `jwks`: Client's JSON Web Key Set as a JSON object
- `software_id`: Software identifier
- `software_version`: Software version
- `token_endpoint_auth_method`: Authentication method for token endpoint
  - `client_secret_basic` (default)
  - `client_secret_post`
  - `none` (for public clients)
- `grant_types`: Array of grant types the client will use
  - `authorization_code` (default)
  - `refresh_token`
  - `client_credentials`
- `response_types`: Array of response types
  - `code` (default)
- `application_type`: Type of application
  - `web` (default)
  - `native`

## Error Responses

### Invalid Request
```json
{
  "error": "invalid_request",
  "error_description": "Content-Type must be application/json"
}
```

### Invalid Client Metadata
```json
{
  "error": "invalid_client_metadata",
  "error_description": "redirect_uris is required"
}
```

### Invalid Token (for configuration endpoints)
```json
{
  "error": "invalid_token",
  "error_description": "Invalid registration access token"
}
```

## Integration with Well-Known Configuration

The registration endpoint is now advertised in the OpenID Connect Discovery document:

```bash
curl http://localhost:5000/.well-known/openid-configuration
```

Response includes:
```json
{
  "registration_endpoint": "http://localhost:5000/register",
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "none"
  ]
}
```
