# 🚀 Custom OAuth2 & OpenID Connect Identity Server

# The Order of Middleware is Veery important, to make this oauth client to work seamlessly

sample code preview

```

  using Ark.oAuth;
  using Ark.oAuth.Oidc;
  
  var builder = WebApplication.CreateBuilder(args);
  
  builder.Services.AddArkOidcServer(builder.Environment);
  builder.Services.AddArkOidcClient(builder.Configuration);
  
  // Add services to the container.
  builder.Services.AddControllersWithViews();
  
  var app = builder.Build();
  
  // Configure the HTTP request pipeline.
  if (!app.Environment.IsDevelopment())
  {
      app.UseExceptionHandler("/Home/Error");
      // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
      app.UseHsts();
  }
  
  //app.UseStaticFiles();
  app.UseHttpsRedirection();
  
  app.UseRouting();
  app.UseArkAuthData(); //server
  app.UseArkOidcClient(); //cleint
  app.UseAuthentication();
  app.UseAuthorization();
  
  app.MapStaticAssets();
  app.MapControllerRoute(
      name: "default",
      pattern: "{controller=Home}/{action=Index}/{id?}")
      .WithStaticAssets();
  
  
  app.Run();


```


Welcome to the official documentation for the **ARK Identity Server**, a lightweight OAuth 2.0 and OpenID Connect (OIDC) compliant authorization server designed for secure authentication and token issuance.

This project provides the core components required for building secure authentication flows for web, mobile, and desktop applications.

---

## 🌐 OIDC Discovery Endpoint

All configuration and metadata for this identity server is exposed via the **Well-Known Configuration URL**:

```
https://ark-oidc-server.immanuel.co/auth/oauth/ark_server/v1/.well-known/ark_server_client/openid-configuration
```

You can use this to dynamically configure any compatible OIDC client (e.g., OpenID libraries, Postman, or OAuth2-aware tools).

---

## 📦 Features

- OAuth2 Authorization Code Flow with PKCE
- OpenID Connect (OIDC) Core support
- Token endpoint with JWT access tokens
- Refresh token support
- Dynamic metadata via discovery endpoint
- Configurable client and scope management
- Extensible authentication and user management

---

## ⚙️ Getting Started

### 1. Clone the Repository

```bash
git clone https://your-git-url/ark-identity-server.git
cd ark-identity-server
```

### 2. Build and Run

Ensure you have [.NET 6 or later](https://dotnet.microsoft.com/en-us/download) installed.

```bash
dotnet restore
dotnet build
dotnet run
```

The Identity Server will be available at:

```
https://localhost:5001/
```

---

## 🛠️ Configuration

### 🔑 Registering a Client

To integrate a client with this server, you must register it in the configuration:

```json
{
  "client_id": "my-client-id",
  "client_secret": "my-client-secret",
  "redirect_uris": ["https://myapp.com/signin-oidc"],
  "grant_types": ["authorization_code"],
  "scope": ["openid", "profile", "email"]
}
```

> This can be done via a configuration file, database, or an admin API (depending on your implementation).

---

## 🔐 Authentication Flow (Authorization Code + PKCE)

### 1. Authorize Endpoint

```
GET https://ark-oidc-server.immanuel.co/auth/oauth/ark_server/v1/authorize
```

#### Parameters:

| Name            | Description                              |
|-----------------|------------------------------------------|
| `client_id`     | Your registered client ID                |
| `response_type` | `code`                                   |
| `redirect_uri`  | Must match the registered redirect URI   |
| `scope`         | e.g., `openid profile email`             |
| `state`         | Random state to validate callback        |
| `code_challenge`| PKCE challenge (Base64-encoded SHA256)   |
| `code_challenge_method` | Usually `S256`                   |

---

### 2. Token Endpoint

```
POST https://ark-oidc-server.immanuel.co/auth/oauth/ark_server/v1/token
```

#### Parameters:

| Name             | Description                          |
|------------------|--------------------------------------|
| `grant_type`     | `authorization_code`                 |
| `code`           | The code received from authorization |
| `redirect_uri`   | Must match the original redirect URI |
| `client_id`      | Registered client ID                 |
| `client_secret`  | (if applicable)                      |
| `code_verifier`  | Original PKCE verifier string        |

---

### 3. UserInfo Endpoint

```
GET https://ark-oidc-server.immanuel.co/auth/oauth/ark_server/v1/userinfo
```

Use the access token in the `Authorization: Bearer` header.

---

### 4. Logout Endpoint

```
GET https://ark-oidc-server.immanuel.co/auth/oauth/ark_server/v1/logout
```

Parameters:

- `id_token_hint`: (optional) previously issued ID Token
- `post_logout_redirect_uri`: where to redirect after logout

---

## 🔍 Useful Endpoints Summary

| Purpose         | URL                                                                 |
|----------------|----------------------------------------------------------------------|
| Discovery       | `/.well-known/ark_server_client/openid-configuration`              |
| Authorize       | `/authorize`                                                        |
| Token           | `/token`                                                            |
| UserInfo        | `/userinfo`                                                         |
| Logout          | `/logout`                                                           |
| JWKS            | `/jwks` (if supported for public key validation)                   |

---

## 🧪 Testing with Postman

1. Go to **Authorization > OAuth 2.0**
2. Fill in the following:
   - Auth URL: `https://ark-oidc-server.immanuel.co/auth/oauth/ark_server/v1/authorize`
   - Token URL: `https://ark-oidc-server.immanuel.co/auth/oauth/ark_server/v1/token`
   - Client ID & Secret
   - Scope: `openid profile`
   - Callback URL: `https://oauth.pstmn.io/v1/callback`

3. Click **Get New Access Token**.

---

## 👨‍💻 For Developers

- All core logic (e.g., token issuance, authorization, user handling) is written in C# using ASP.NET Core.
- Authentication is modular — you can plug in your own user store (e.g., database, LDAP).
- JWT tokens are signed using an RSA key pair; keys can be rotated and exposed via the JWKS endpoint.

---

## 🧰 Libraries and Tools

- [.NET 6](https://dotnet.microsoft.com/en-us/)
- [Microsoft.AspNetCore.Authentication](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/)
- [System.IdentityModel.Tokens.Jwt](https://www.nuget.org/packages/System.IdentityModel.Tokens.Jwt)

---

## 📝 License

This project is licensed under the MIT License.

---

## 📫 Need Help?

If you're stuck or need help integrating your application with ARK Identity Server, please open an issue or contact the development team.
