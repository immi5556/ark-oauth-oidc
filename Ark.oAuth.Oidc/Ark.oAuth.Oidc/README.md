# Ark.oAuth.Oidc

A self-contained OAuth 2.1 and OpenID Connect provider for ASP.NET Core. Add two lines to
`Program.cs`, point any standard OIDC library at the issuer URL, and it configures itself from the
discovery document.

Multi-tenant, runs on SQLite / MySQL / PostgreSQL / SQL Server, and ships its own sign-in, consent
and admin UI. The matching client package is [`Ark.oAuth.Client`](https://www.nuget.org/packages/Ark.oAuth.Client).

## Install

```bash
dotnet new mvc -n MyIdp
cd MyIdp
dotnet add package Ark.oAuth.Oidc
dotnet add package Ark.oAuth.Client
```

## Program.cs

```csharp
using Ark.oAuth;
using Ark.oAuth.Oidc;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddArkOidcServer(builder.Environment);   // the identity provider
builder.Services.AddArkOidcClient(builder.Configuration); // the admin console is itself a client
builder.Services.AddControllersWithViews();

var app = builder.Build();

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();        // must come before UseAuthentication / UseAuthorization
app.UseArkOidcCors();    // only needed if browser-based clients call the token endpoint
app.UseArkAuthData();    // one-time database bootstrap
app.UseArkOidcClient();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");
app.Run();
```

`UseRouting()` has to run before `UseAuthentication()` / `UseAuthorization()`. Without a selected
endpoint the authorization middleware cannot see the `[Authorize]` metadata it is meant to enforce.

## appsettings.json

```jsonc
{
  "ark_oauth_server": {
    "TenantId": "my_idp",              // a client named "<TenantId>_client" is seeded for the admin console
    "BasePath": "",                    // set only if the app is hosted under a sub-path
    "BaseUrl": "https://idp.example.com",
    "Provider": "sqlite",              // sqlite (default) | mysql | postgres | sqlserver
    "UploadPath": "./wwwroot/{0}/",
    "DefaultPw": "<initial password for new users>",
    "Oidc": {
      "EnableDeviceFlow": true,
      "EnablePushedAuthorizationRequests": true,
      "RequirePushedAuthorizationRequests": false,
      "EnableDynamicRegistration": false,
      "RequireRegistrationAccessToken": true,
      "AlwaysRequireConsent": false,
      "SessionLifetimeMinutes": 480,
      "MaxFailedSignIns": 10,
      "LockoutMinutes": 15,
      "CorsOrigins": []                // exact origins of any single-page-application clients
    }
  },
  "ConnectionStrings": {
    "ArkAuthConnection": "Data Source=./data/ark_auth.db"
  }
}
```

On first run the server creates its schema, generates an RSA signing key in-process, seeds the OIDC
scope catalogue and creates an `admin` / `admin` account. **Change that password before exposing
the server.**

Your issuer is `{BaseUrl}/{TenantId}`, and discovery lives at
`{BaseUrl}/{TenantId}/.well-known/openid-configuration`.

## What's supported

| Specification | Status |
|---|---|
| OAuth 2.0 (RFC 6749) | Authorization code, refresh token, client credentials |
| PKCE (RFC 7636) | **Required** for public clients, `S256` only |
| OpenID Connect Core 1.0 | ID tokens, UserInfo, `nonce`, `at_hash`/`c_hash`, `auth_time`, `sid` |
| OIDC Discovery 1.0 | `/.well-known/openid-configuration` |
| AS Metadata (RFC 8414) | `/.well-known/oauth-authorization-server` |
| JWKS (RFC 7517) | `/.well-known/jwks.json`, two-phase key rotation |
| JWT Access Tokens (RFC 9068) | `typ: at+jwt`, `client_id`, `jti`, `scope` |
| Introspection (RFC 7662) | Access and refresh tokens |
| Revocation (RFC 7009) | Revokes the whole refresh-token family |
| Device Grant (RFC 8628) | With `verification_uri_complete` |
| PAR (RFC 9126) | Optional, can be made mandatory |
| Dynamic Registration (RFC 7591/7592) | Optional, off by default |
| RP-Initiated Logout 1.0 | `end_session_endpoint` |
| Issuer Identification (RFC 9207) | `iss` in the authorization response |
| Native Apps (RFC 8252) | Loopback redirect URIs with variable ports |

Deliberately **not** supported: the implicit grant, the hybrid flow, and the resource owner password
credentials grant — all three are removed in OAuth 2.1.

## Endpoints

All paths are relative to the issuer, `{BaseUrl}/{TenantId}`.

| Purpose | Path |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| JWKS | `/.well-known/jwks.json` |
| Authorization | `/oauth2/authorize` |
| Token | `/oauth2/token` |
| UserInfo | `/oauth2/userinfo` |
| Introspection | `/oauth2/introspect` |
| Revocation | `/oauth2/revoke` |
| End session | `/oauth2/logout` |
| Device authorization | `/oauth2/device_authorization` |
| Pushed authorization request | `/oauth2/par` |
| Dynamic registration | `/oauth2/register` |
| Client setup page | `/oauth2/integrate/{client_id}` |

Signed in to the admin console, every registered client has a generated setup page at
`/{tenant_id}/oauth2/integrate/{client_id}` carrying its exact issuer, client ID, scopes, redirect
URIs and copy-paste snippets for the Ark client package, the raw ASP.NET Core handler,
`oidc-client-ts`, Authlib and `go-oidc`.

## Before production

1. Change the `admin` / `admin` password.
2. Set a strong `DefaultPw`.
3. Keep `RequireHttpsMetadata` at `true` on clients.
4. Leave `EnableDynamicRegistration` off unless you need it, and keep
   `RequireRegistrationAccessToken` on if you do.
5. Give confidential clients real secrets and set `token_endpoint_auth_method` accordingly.

## Documentation

Full documentation, flow walkthroughs, the configuration reference and the v1 migration guide are
in the repository: <https://github.com/ir-dev/ark-oauth-oidc>

## License

MIT
