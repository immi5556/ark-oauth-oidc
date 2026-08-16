using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Ark.oAuth.Oidc.Protocol;

namespace Ark.oAuth.Oidc.Endpoints
{
    /// <summary>
    /// Token introspection (RFC 7662), revocation (RFC 7009) and RP-initiated logout
    /// (OIDC RP-Initiated Logout 1.0).
    /// </summary>
    [Route("{tenant_id}/oauth2")]
    public class OidcTokenManagementController : ArkOidcControllerBase
    {
        private readonly ArkClientAuthenticator _clientAuth;
        private readonly ArkGrantStore _grants;
        private readonly ArkTokenService _tokens;
        private readonly DataAccess _da;

        public OidcTokenManagementController(ArkDataContext ctx, IConfiguration config,
            ArkClientAuthenticator clientAuth, ArkGrantStore grants, ArkTokenService tokens, DataAccess da)
            : base(ctx, config)
        {
            _clientAuth = clientAuth;
            _grants = grants;
            _tokens = tokens;
            _da = da;
        }

        // -----------------------------------------------------------------
        // Introspection (RFC 7662)
        // -----------------------------------------------------------------

        [HttpPost("introspect")]
        [Consumes("application/x-www-form-urlencoded")]
        public async Task<IActionResult> Introspect([FromRoute] string tenant_id)
        {
            NoStore();
            return await ProtectAsync(async () =>
            {
                var tenant = await ResolveTenantAsync(tenant_id);
                var ep = Endpoints(tenant.tenant_id);

                // §2.1: the endpoint requires client authentication, otherwise it is an oracle
                // that lets anyone test captured tokens.
                var auth = await _clientAuth.AuthenticateAsync(Request, tenant.tenant_id, ep.Introspection);
                if (auth.Method == "none")
                    throw OAuthException.InvalidClient("the introspection endpoint requires client authentication.");

                var token = Request.Form["token"].ToString();
                if (string.IsNullOrWhiteSpace(token))
                    throw OAuthException.InvalidRequest("token is required.");

                var hint = Request.Form["token_type_hint"].ToString();

                // §2.2: an unknown or expired token is not an error — it is simply not active.
                var inactive = new Dictionary<string, object> { ["active"] = false };

                if (hint != "refresh_token")
                {
                    var result = await _tokens.ValidateAsync(token, tenant, ep.Issuer);
                    if (result.IsValid)
                    {
                        var id = result.ClaimsIdentity;
                        var body = new Dictionary<string, object> { ["active"] = true };
                        void Copy(string claim, string? outName = null)
                        {
                            var v = id?.FindFirst(claim)?.Value;
                            if (!string.IsNullOrEmpty(v)) body[outName ?? claim] = v!;
                        }
                        Copy("sub"); Copy("scope"); Copy("client_id"); Copy("iss"); Copy("jti"); Copy("sid");
                        if (long.TryParse(id?.FindFirst("exp")?.Value, out var exp)) body["exp"] = exp;
                        if (long.TryParse(id?.FindFirst("iat")?.Value, out var iat)) body["iat"] = iat;
                        if (long.TryParse(id?.FindFirst("nbf")?.Value, out var nbf)) body["nbf"] = nbf;
                        var aud = id?.FindFirst("aud")?.Value;
                        if (!string.IsNullOrEmpty(aud)) body["aud"] = aud!;
                        body["token_type"] = "Bearer";
                        body["username"] = id?.FindFirst("sub")?.Value ?? "";
                        return Ok(body);
                    }
                }

                if (hint != "access_token")
                {
                    var refresh = await _grants.FindRefreshTokenAsync(token);
                    if (refresh != null && !refresh.revoked && refresh.consumed_at == null
                        && refresh.expires_at > DateTime.UtcNow)
                    {
                        return Ok(new Dictionary<string, object>
                        {
                            ["active"] = true,
                            ["sub"] = refresh.subject,
                            ["client_id"] = refresh.client_id,
                            ["scope"] = refresh.scope ?? "",
                            ["token_type"] = "refresh_token",
                            ["exp"] = ArkTokenService.ToUnix(refresh.expires_at),
                            ["iat"] = ArkTokenService.ToUnix(refresh.created_at),
                            ["iss"] = ep.Issuer
                        });
                    }
                }

                return Ok(inactive);
            }, _da, "introspect");
        }

        // -----------------------------------------------------------------
        // Revocation (RFC 7009)
        // -----------------------------------------------------------------

        [HttpPost("revoke")]
        [Consumes("application/x-www-form-urlencoded")]
        public async Task<IActionResult> Revoke([FromRoute] string tenant_id)
        {
            NoStore();
            return await ProtectAsync(async () =>
            {
                var tenant = await ResolveTenantAsync(tenant_id);
                var ep = Endpoints(tenant.tenant_id);
                var auth = await _clientAuth.AuthenticateAsync(Request, tenant.tenant_id, ep.Revocation);

                var token = Request.Form["token"].ToString();
                if (string.IsNullOrWhiteSpace(token))
                    throw OAuthException.InvalidRequest("token is required.");

                // Revoking a refresh token kills its whole rotation family.
                var revoked = await _grants.RevokeRefreshTokenAsync(token, auth.Client.client_id);

                if (!revoked)
                {
                    // An access token is a self-contained JWT and cannot be withdrawn, but
                    // revoking the session behind it stops any further tokens being minted.
                    var result = await _tokens.ValidateAsync(token, tenant, ep.Issuer);
                    if (result.IsValid)
                    {
                        var sid = result.ClaimsIdentity?.FindFirst("sid")?.Value;
                        if (!string.IsNullOrEmpty(sid)) await _grants.RevokeSessionAsync(sid!);
                    }
                }

                _da.Log("revoke", $"{tenant.tenant_id}/oauth2/revoke", "token revocation processed",
                    $"client: {auth.Client.client_id}");

                // §2.2: an unknown token is still a success — the caller's goal is already met.
                return Ok();
            }, _da, "revoke");
        }

        // -----------------------------------------------------------------
        // RP-initiated logout
        // -----------------------------------------------------------------

        [HttpGet("logout")]
        [HttpPost("logout")]
        public async Task<IActionResult> EndSession([FromRoute] string tenant_id)
        {
            NoStore();
            var tenant = await ResolveTenantAsync(tenant_id);

            string? Param(string name) =>
                Request.Query[name].FirstOrDefault()
                ?? (Request.HasFormContentType ? Request.Form[name].FirstOrDefault() : null);

            var idTokenHint = Param("id_token_hint");
            var postLogoutRedirectUri = Param("post_logout_redirect_uri");
            var state = Param("state");
            var clientId = Param("client_id");

            // Identify the client from the hint when one was not named explicitly.
            if (string.IsNullOrEmpty(clientId) && !string.IsNullOrEmpty(idTokenHint))
            {
                try
                {
                    var parsed = new JsonWebTokenHandler().ReadJsonWebToken(idTokenHint);
                    clientId = parsed.Audiences.FirstOrDefault();
                }
                catch { /* an unreadable hint simply yields no client */ }
            }

            // End the session first, so logout still happens even if the redirect is rejected.
            var sessionId = Request.Cookies[OidcAuthorizeController.SessionCookie];
            if (!string.IsNullOrEmpty(sessionId))
            {
                await _grants.RevokeSessionAsync(sessionId!);
                Response.Cookies.Delete(OidcAuthorizeController.SessionCookie, new CookieOptions
                {
                    Path = string.IsNullOrEmpty(Request.PathBase) ? "/" : Request.PathBase.Value!
                });
            }

            _da.Log("logout", $"{tenant.tenant_id}/oauth2/logout", "session ended", $"client: {clientId}");

            if (!string.IsNullOrEmpty(postLogoutRedirectUri))
            {
                var client = await Ctx.clients.AsNoTracking().FirstOrDefaultAsync(c =>
                    c.tenant_id.ToLower() == tenant.tenant_id.ToLower() &&
                    c.client_id.ToLower() == (clientId ?? "").ToLower());

                // Only redirect to a URI the client registered — otherwise this is an open redirect.
                if (client != null && RedirectUriValidator.Matches(client.EffectivePostLogoutRedirectUris, postLogoutRedirectUri!))
                {
                    var target = postLogoutRedirectUri!;
                    if (!string.IsNullOrEmpty(state))
                        target += (target.Contains('?') ? "&" : "?") + $"state={Uri.EscapeDataString(state!)}";
                    return Redirect(target);
                }
            }

            return View("~/Views/Oidc/LoggedOut.cshtml", new OidcErrorPageModel
            {
                Brand = new OidcBrandModel
                {
                    HostLogo = ServerConfig.EmailConfig?.host_logo,
                    HostName = ServerConfig.EmailConfig?.host_company_display ?? "Identity Provider",
                    PrivacyUrl = ServerConfig.EmailConfig?.privacy_policy_url,
                    TermsUrl = ServerConfig.EmailConfig?.terms_url
                },
                Error = "signed_out",
                Description = "You have been signed out."
            });
        }
    }
}
