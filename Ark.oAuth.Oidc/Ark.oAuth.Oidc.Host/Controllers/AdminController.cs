using Ark.oAuth;
using Ark.oAuth.Oidc;
using Ark.oAuth.Oidc.Protocol;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc.Host.Controllers
{
    /// <summary>
    /// The admin console.
    ///
    /// Replaces the v1 console that lived at /oauth/{tenant}/v1/server/{client}/manage inside the
    /// server package. The screen keeps the same job — tenants, clients, users, claims and the
    /// per-user-per-client access mapping — but it is a host concern rather than part of the
    /// protocol surface, so it lives here, and every URL it hands out is a current one:
    ///
    ///   * management API   /api/oauth/v1/...
    ///   * client setup     /{tenant}/oauth2/integrate/{client_id}
    ///   * discovery        /{tenant}/.well-known/openid-configuration
    ///   * sign-out         the end_session_endpoint, via the standard OIDC handler
    ///
    /// Identity comes off the authenticated principal, built by the OIDC handler from the ID
    /// token and UserInfo. The v1 console read it from a separate /userinfo call whose result it
    /// then had to trust.
    /// </summary>
    [Authorize]
    public class AdminController : Controller
    {
        private readonly DataAccess _da;
        private readonly IConfiguration _config;

        public AdminController(DataAccess da, IConfiguration config)
        {
            _da = da;
            _config = config;
        }

        private ArkAuthServerConfig ServerConfig =>
            _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>()
            ?? throw new ApplicationException("the 'ark_oauth_server' configuration section is missing.");

        /// <summary>Convenience entry point: sends the operator to their own tenant's console.</summary>
        [HttpGet("/admin")]
        public IActionResult Index() => RedirectToAction(nameof(Manage), new { tenant_id = ServerConfig.TenantId });

        [HttpGet("/{tenant_id}/admin")]
        public async Task<IActionResult> Manage([FromRoute] string tenant_id)
        {
            var ser = ServerConfig;
            var tenant = await _da.GetTenant(tenant_id);
            if (tenant == null) return NotFound($"unknown tenant '{tenant_id}'.");

            var endpoints = ArkOidcEndpoints.For(Request, ser, tenant.tenant_id);

            // Everything the page fetches is relative to the app root, which is not necessarily
            // "/" — it is whatever the app is mounted under. Reading it from PathBase keeps the
            // console working under a sub-path without a second setting to keep in step.
            ViewBag.AppRoot = Request.PathBase.HasValue ? Request.PathBase.Value!.TrimEnd('/') : "";

            ViewBag.Tenant = tenant;
            ViewBag.TenantId = tenant.tenant_id;
            ViewBag.Issuer = endpoints.Issuer;
            ViewBag.Discovery = endpoints.Discovery;
            ViewBag.Jwks = endpoints.Jwks;
            ViewBag.HostLogo = ser.EmailConfig?.host_logo ?? "";
            ViewBag.HostName = ser.EmailConfig?.host_company_display ?? ser.EmailConfig?.host_company_name ?? "Identity Provider";

            var name = User.FindFirst("name")?.Value;
            var email = User.FindFirst("email")?.Value ?? User.FindFirst("preferred_username")?.Value;
            ViewBag.UserName = string.IsNullOrWhiteSpace(name) ? (email ?? "signed in") : name;
            ViewBag.UserEmail = email ?? "";

            return View();
        }
    }
}
