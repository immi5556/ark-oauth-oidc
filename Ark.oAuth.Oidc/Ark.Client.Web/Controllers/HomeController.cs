using System.Diagnostics;
using System.Text;
using System.Text.Json;
using Ark.Client.Web.Models;
using Ark.oAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ark.Client.Web.Controllers
{
    public class HomeController : Controller
    {
        private readonly ArkAuthConfig _config;
        private readonly IHttpClientFactory _http;
        private readonly IConfiguration _appConfig;

        // AddArkOidcClient registers the parsed `ark_oauth_client` section as a singleton, so the
        // application reads the same values the handler was configured with rather than a second
        // copy that can drift.
        public HomeController(ArkAuthConfig config, IHttpClientFactory http, IConfiguration appConfig)
        {
            _config = config;
            _http = http;
            _appConfig = appConfig;
        }

        private string RequiredRole => _appConfig["sample:RequiredRole"] ?? "sample.admin";

        // -----------------------------------------------------------------------------------------
        // Public page: a live check of whether this app is registered correctly.
        // -----------------------------------------------------------------------------------------
        public async Task<IActionResult> Index([FromQuery] string? auth_error)
        {
            var authority = _config.ResolveAuthority();
            var origin = $"{Request.Scheme}://{Request.Host}{Request.PathBase}";

            var model = new SetupModel
            {
                Authority = authority,
                ClientId = _config.ClientId ?? "",
                IsConfidential = !string.IsNullOrWhiteSpace(_config.ClientSecret),
                Scopes = _config.ResolveScopes(),
                RoleClaimType = _config.RoleClaimType ?? "role",
                RedirectUri = origin + (_config.CallbackPath ?? "/signin-oidc"),
                PostLogoutRedirectUri = origin + (_config.SignedOutCallbackPath ?? "/signout-callback-oidc"),
                DiscoveryUrl = $"{authority.TrimEnd('/')}/.well-known/openid-configuration",
                IsAuthenticated = User.Identity?.IsAuthenticated == true,
                SignedInAs = User.FindFirst("name")?.Value ?? User.FindFirst("email")?.Value,
                AuthError = auth_error
            };

            await ProbeDiscoveryAsync(model);
            return View(model);
        }

        /// <summary>
        /// Fetches the provider's discovery document, which is exactly what the OIDC handler does
        /// on its first challenge. Doing it here turns "the sign-in button throws" into a readable
        /// message on the page — wrong port, provider not running, self-signed certificate.
        /// </summary>
        private async Task ProbeDiscoveryAsync(SetupModel model)
        {
            if (string.IsNullOrWhiteSpace(model.Authority))
            {
                model.DiscoveryError = "ark_oauth_client:Authority is not set.";
                return;
            }

            try
            {
                var client = _http.CreateClient("downstream");
                using var response = await client.GetAsync(model.DiscoveryUrl);
                var body = await response.Content.ReadAsStringAsync();
                if (!response.IsSuccessStatusCode)
                {
                    model.DiscoveryError = $"the provider answered {(int)response.StatusCode} {response.ReasonPhrase}.";
                    return;
                }

                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;
                string? Str(string name) => root.TryGetProperty(name, out var v) ? v.GetString() : null;

                model.Issuer = Str("issuer");
                model.AuthorizationEndpoint = Str("authorization_endpoint");
                model.TokenEndpoint = Str("token_endpoint");
                model.UserInfoEndpoint = Str("userinfo_endpoint");
                model.EndSessionEndpoint = Str("end_session_endpoint");
                model.JwksUri = Str("jwks_uri");
                if (root.TryGetProperty("scopes_supported", out var scopes) && scopes.ValueKind == JsonValueKind.Array)
                    model.ScopesSupported = scopes.EnumerateArray().Select(s => s.GetString() ?? "").ToList();

                model.DiscoveryOk = true;
            }
            catch (Exception ex)
            {
                model.DiscoveryError = ex.Message;
            }
        }

        // -----------------------------------------------------------------------------------------
        // Protected page: the whole of what it takes to require sign-in.
        // -----------------------------------------------------------------------------------------
        [Authorize]
        public IActionResult Secure() => View();

        /// <summary>
        /// Everything the sign-in produced: the claims on the principal, and the tokens the
        /// handler stored in the (encrypted) authentication cookie.
        /// </summary>
        [Authorize]
        public async Task<IActionResult> Profile()
        {
            var accessToken = await HttpContext.GetArkAccessTokenAsync();
            var idToken = await HttpContext.GetArkIdTokenAsync();
            var refreshToken = await HttpContext.GetArkRefreshTokenAsync();
            var expiresAt = await HttpContext.GetTokenAsync(ArkOidcClient.CookieScheme, "expires_at");

            var roleClaimType = _config.RoleClaimType ?? "role";
            var model = new ProfileModel
            {
                Subject = User.FindFirst("sub")?.Value,
                Name = User.FindFirst("name")?.Value,
                Email = User.FindFirst("email")?.Value ?? User.FindFirst("preferred_username")?.Value,
                Roles = User.FindAll(roleClaimType).Select(c => c.Value).ToList(),
                Claims = User.Claims
                    .Select(c => new KeyValuePair<string, string>(c.Type, c.Value))
                    .OrderBy(c => c.Key, StringComparer.Ordinal)
                    .ToList(),
                HasAccessToken = !string.IsNullOrEmpty(accessToken),
                HasIdToken = !string.IsNullOrEmpty(idToken),
                HasRefreshToken = !string.IsNullOrEmpty(refreshToken),
                AccessTokenPayload = DecodeJwtPayload(accessToken),
                IdTokenPayload = DecodeJwtPayload(idToken),
                RequiredRole = RequiredRole
            };

            if (DateTimeOffset.TryParse(expiresAt, out var parsed)) model.AccessTokenExpiresAt = parsed;

            return View(model);
        }

        /// <summary>
        /// The Ark authorization claims carried in the access token (`ark_claims`) are projected
        /// onto the configured role claim type, so ordinary role checks work against them.
        ///
        /// Grant the claim through Admin console -> Access mapping for this user and this client;
        /// it takes effect on the next sign-in.
        /// </summary>
        [Authorize]
        public IActionResult Roles()
        {
            var roleClaimType = _config.RoleClaimType ?? "role";
            ViewBag.RequiredRole = RequiredRole;
            ViewBag.Granted = User.HasClaim(roleClaimType, RequiredRole);
            ViewBag.Roles = User.FindAll(roleClaimType).Select(c => c.Value).ToList();
            return View();
        }

        /// <summary>
        /// Calls a downstream resource with the signed-in user's access token.
        ///
        /// The provider's own UserInfo endpoint stands in for an API here, but the shape is the
        /// one to copy: build the request, attach the token with WithArkTokenAsync, send it. Do
        /// not read the token out of the cookie yourself and do not cache it — the cookie handler
        /// refreshes it in the background, and a cached copy goes stale.
        /// </summary>
        [Authorize]
        public async Task<IActionResult> Downstream()
        {
            var endpoint = $"{_config.ResolveAuthority().TrimEnd('/')}/oauth2/userinfo";
            var model = new DownstreamModel { Endpoint = endpoint };

            try
            {
                var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
                await request.WithArkTokenAsync(HttpContext);

                var client = _http.CreateClient("downstream");
                using var response = await client.SendAsync(request);
                model.StatusCode = (int)response.StatusCode;
                model.Body = Prettify(await response.Content.ReadAsStringAsync());
            }
            catch (Exception ex)
            {
                model.Error = ex.Message;
            }

            return View(model);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error() =>
            View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });

        // -----------------------------------------------------------------------------------------
        // Display helpers. Neither is a security boundary.
        // -----------------------------------------------------------------------------------------

        /// <summary>
        /// Renders a JWT payload for the page. It deliberately does not validate the token —
        /// validation already happened in the handler, and re-checking a signature here would
        /// suggest an application is supposed to inspect its own access token, which it is not.
        /// </summary>
        private static string? DecodeJwtPayload(string? jwt)
        {
            if (string.IsNullOrEmpty(jwt)) return null;
            var parts = jwt.Split('.');
            if (parts.Length < 2) return "(not a JWT — the provider issued an opaque token)";

            try
            {
                var payload = parts[1].Replace('-', '+').Replace('_', '/');
                payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
                return Prettify(Encoding.UTF8.GetString(Convert.FromBase64String(payload)));
            }
            catch
            {
                return "(could not decode)";
            }
        }

        private static string Prettify(string json)
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                return JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true });
            }
            catch
            {
                return json;
            }
        }
    }
}
