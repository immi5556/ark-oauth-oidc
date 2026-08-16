using Microsoft.AspNetCore.Http;

namespace Ark.oAuth.Oidc.Protocol
{
    /// <summary>
    /// Server-wide switches for the standard OAuth surface. Bound from the
    /// "ark_oauth_server:Oidc" configuration section; every value has a working default,
    /// so the section can be omitted entirely.
    /// </summary>
    public class ArkOidcOptions
    {
        /// <summary>Serve RFC 7591 dynamic client registration. Off by default — it creates clients.</summary>
        public bool EnableDynamicRegistration { get; set; } = false;
        /// <summary>Require an initial access token on /register when dynamic registration is on.</summary>
        public bool RequireRegistrationAccessToken { get; set; } = true;
        public bool EnableDeviceFlow { get; set; } = true;
        public bool EnablePushedAuthorizationRequests { get; set; } = true;
        /// <summary>Refuse plain /authorize requests that did not arrive via PAR.</summary>
        public bool RequirePushedAuthorizationRequests { get; set; } = false;

        public int DeviceCodeLifetimeSeconds { get; set; } = 600;
        public int DevicePollIntervalSeconds { get; set; } = 5;
        public int ParLifetimeSeconds { get; set; } = 90;
        public int SessionLifetimeMinutes { get; set; } = 480;

        /// <summary>Lock an account after this many consecutive failed sign-ins. 0 disables lockout.</summary>
        public int MaxFailedSignIns { get; set; } = 10;
        public int LockoutMinutes { get; set; } = 15;

        /// <summary>Show the consent screen even for first-party clients that did not ask for it.</summary>
        public bool AlwaysRequireConsent { get; set; } = false;
    }

    /// <summary>
    /// Builds every protocol URL for a tenant from a single base, and defines the issuer.
    ///
    /// The issuer is <c>{baseUrl}/{tenant_id}</c> and discovery lives at
    /// <c>{issuer}/.well-known/openid-configuration</c>. That relationship is what lets a stock
    /// OIDC client — ASP.NET Core, Okta's SDKs, Postman, anything — point at the issuer and
    /// configure itself, and it is why the issuer is derived here rather than stored per tenant.
    /// (<see cref="ArkTenant.issuer"/> keeps its legacy value for the v1 compatibility endpoints.)
    /// </summary>
    public class ArkOidcEndpoints
    {
        public string BaseUrl { get; }
        public string TenantId { get; }

        public ArkOidcEndpoints(string baseUrl, string tenantId)
        {
            BaseUrl = baseUrl.TrimEnd('/');
            TenantId = tenantId;
        }

        public string Issuer => $"{BaseUrl}/{TenantId}";

        public string Authorization => $"{Issuer}/oauth2/authorize";
        public string Token => $"{Issuer}/oauth2/token";
        public string UserInfo => $"{Issuer}/oauth2/userinfo";
        public string Jwks => $"{Issuer}/.well-known/jwks.json";
        public string Introspection => $"{Issuer}/oauth2/introspect";
        public string Revocation => $"{Issuer}/oauth2/revoke";
        public string EndSession => $"{Issuer}/oauth2/logout";
        public string DeviceAuthorization => $"{Issuer}/oauth2/device_authorization";
        public string DeviceVerification => $"{Issuer}/oauth2/device";
        public string PushedAuthorizationRequest => $"{Issuer}/oauth2/par";
        public string Registration => $"{Issuer}/oauth2/register";
        public string Discovery => $"{Issuer}/.well-known/openid-configuration";

        /// <summary>
        /// Resolves the public base URL. Prefers the configured BaseUrl so that a server behind a
        /// proxy or load balancer advertises the address clients actually reach, rather than the
        /// internal host from the request.
        /// </summary>
        public static ArkOidcEndpoints For(HttpRequest request, ArkAuthServerConfig config, string tenantId)
        {
            string baseUrl;
            if (!string.IsNullOrWhiteSpace(config.BaseUrl))
            {
                baseUrl = config.BaseUrl!.TrimEnd('/');
                // BaseUrl may or may not already include BasePath; add it only when missing.
                if (!string.IsNullOrWhiteSpace(config.BasePath))
                {
                    var basePath = config.BasePath!.Trim('/');
                    if (!baseUrl.EndsWith($"/{basePath}", StringComparison.OrdinalIgnoreCase))
                        baseUrl = $"{baseUrl}/{basePath}";
                }
            }
            else
            {
                baseUrl = $"{request.Scheme}://{request.Host}";
                var pathBase = request.PathBase.HasValue ? request.PathBase.Value!.Trim('/') : "";
                if (!string.IsNullOrEmpty(pathBase)) baseUrl = $"{baseUrl}/{pathBase}";
                else if (!string.IsNullOrWhiteSpace(config.BasePath)) baseUrl = $"{baseUrl}/{config.BasePath!.Trim('/')}";
            }
            return new ArkOidcEndpoints(baseUrl, tenantId);
        }
    }
}
