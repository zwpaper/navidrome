# OIDC Authentication in Navidrome

This guide explains how to configure OpenID Connect (OIDC) authentication in Navidrome, allowing users to log in using external identity providers like Google, Azure AD, Keycloak, Auth0, and others.

## Features

- **Single Sign-On (SSO)**: Users can log in using their existing accounts from supported OIDC providers
- **Automatic User Creation**: Users are automatically created in Navidrome when they first log in via OIDC
- **Fallback Authentication**: Traditional username/password authentication remains available
- **Security**: Uses standard OAuth2/OIDC flows with proper state validation

## Configuration

### Basic Setup

Add the following configuration to your `navidrome.toml` file:

```toml
[OIDC]
Enabled = true
IssuerURL = "https://your-provider.example.com"
ClientID = "your-client-id"
ClientSecret = "your-client-secret"
RedirectURI = "https://your-navidrome.example.com/auth/oidc/callback"
Scopes = ["openid", "profile", "email", "groups"]
AdminGroup = "ADMIN"
```

### Environment Variables

You can also configure OIDC using environment variables:

```bash
export ND_OIDC_ENABLED=true
export ND_OIDC_ISSUERURL="https://your-provider.example.com"
export ND_OIDC_CLIENTID="your-client-id"
export ND_OIDC_CLIENTSECRET="your-client-secret"
export ND_OIDC_REDIRECTURI="https://your-navidrome.example.com/auth/oidc/callback"
export ND_OIDC_SCOPES="openid,profile,email,groups"
export ND_OIDC_ADMINGROUP="ADMIN"
```

## Provider Examples

### Keycloak

```toml
[OIDC]
Enabled = true
IssuerURL = "https://your-keycloak.example.com/auth/realms/your-realm"
ClientID = "navidrome"
ClientSecret = "your-client-secret"
RedirectURI = "https://your-navidrome.example.com/auth/oidc/callback"
```

### Google

```toml
[OIDC]
Enabled = true
IssuerURL = "https://accounts.google.com"
ClientID = "your-google-client-id.apps.googleusercontent.com"
ClientSecret = "your-google-client-secret"
RedirectURI = "https://your-navidrome.example.com/auth/oidc/callback"
```

### Azure AD

```toml
[OIDC]
Enabled = true
IssuerURL = "https://login.microsoftonline.com/your-tenant-id/v2.0"
ClientID = "your-azure-app-id"
ClientSecret = "your-azure-client-secret"
RedirectURI = "https://your-navidrome.example.com/auth/oidc/callback"
```

### Auth0

```toml
[OIDC]
Enabled = true
IssuerURL = "https://your-domain.auth0.com"
ClientID = "your-auth0-client-id"
ClientSecret = "your-auth0-client-secret"
RedirectURI = "https://your-navidrome.example.com/auth/oidc/callback"
```

## Provider Setup

### General Steps

1. **Create an OIDC Application** in your identity provider
2. **Configure the Redirect URI** to `https://your-navidrome.example.com/auth/oidc/callback`
3. **Note down the Client ID and Client Secret**
4. **Find the Issuer URL** (usually in the provider's documentation)

### Required Scopes

Navidrome requires the following scopes:

- `openid` - Required for OIDC
- `profile` - To get user's name
- `email` - To get user's email address
- `groups` - To grant administrator access based on group membership

## User Management

- **First User**: The first user to log in via OIDC becomes an administrator
- **Subsequent Users**: Regular users by default
- **Administrator Group**: Members of `OIDC.AdminGroup` are granted administrator privileges
- **Username Mapping**: Uses `preferred_username` claim, falls back to `email`
- **User Information**: Name and email are automatically populated from OIDC claims

## Security Considerations

- **HTTPS Required**: Use HTTPS in production for security
- **State Validation**: The implementation includes CSRF protection via state parameter
- **Session Management**: Sessions are managed via JWT tokens with configurable timeouts and refreshed through the identity provider when possible
- **Secure Cookies**: Provider refresh tokens are stored in HTTP-only cookies and marked secure when HTTPS is configured

## Troubleshooting

### Common Issues

1. **"OIDC not enabled"**: Check that `OIDC.Enabled = true` in your configuration
2. **"Invalid state token"**: Ensure cookies are working and the user isn't blocking them
3. **"Failed to exchange authorization code"**: Check your Client ID, Secret, and Redirect URI
4. **"No username found in OIDC claims"**: Your provider might not include `preferred_username` or `email` claims

### Debug Mode

Enable debug logging to see OIDC authentication details:

```toml
LogLevel = "debug"
```

### Logs to Check

- OIDC provider discovery
- Token exchange
- User creation/login
- Cookie setting/retrieval

## API Access

- **Subsonic API**: Continues to work with traditional authentication
- **Web UI**: Supports both OIDC and traditional login
- **Mobile Apps**: Use traditional username/password authentication

## Migration

When enabling OIDC on an existing installation:

- Existing users can continue using traditional authentication
- New users can use OIDC
- No data migration is required
