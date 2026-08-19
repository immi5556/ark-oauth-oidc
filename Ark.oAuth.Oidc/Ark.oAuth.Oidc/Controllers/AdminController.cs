using Ark.oAuth.Oidc.Protocol;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc.Controllers
{
    /// <summary>
    /// The v2 admin console — tenants, clients, users, scopes, claims and the per-user-per-client
    /// access mapping — served from inside this package.
    ///
    /// It used to live in the sample host, which meant the only way to get a console with a
    /// NuGet reference was to copy a controller, a view, a stylesheet and 800 lines of JavaScript
    /// out of this repository and keep them in step by hand. Everything it needs now ships in the
    /// assembly: the view sets <c>Layout = null</c> and brings its own shell, and
    /// <see cref="Asset"/> serves the stylesheet and script as embedded resources, so a host that
    /// references the package gets /{tenant}/admin with no wiring at all.
    ///
    /// It replaces the v1 console at /oauth/{tenant}/v1/server/{client}/manage, which is still
    /// served for existing deployments. Every URL this one hands out is a current one:
    ///
    ///   * management API   /api/oauth/v1/...
    ///   * client setup     /{tenant}/oauth2/integrate/{client_id}
    ///   * discovery        /{tenant}/.well-known/openid-configuration
    ///
    /// Identity comes off the authenticated principal, built by the host's OIDC handler from the
    /// ID token and UserInfo. The v1 console read it from a separate /userinfo call whose result
    /// it then had to trust.
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
            var appRoot = Request.PathBase.HasValue ? Request.PathBase.Value!.TrimEnd('/') : "";
            ViewBag.AppRoot = appRoot;

            ViewBag.Tenant = tenant;
            ViewBag.TenantId = tenant.tenant_id;
            ViewBag.Issuer = endpoints.Issuer;
            ViewBag.Discovery = endpoints.Discovery;
            ViewBag.Jwks = endpoints.Jwks;
            // The same two marks the sign-in page shows, in the same order, so the console and
            // the pages it configures read as one product rather than two. The client mark here
            // is the configured default — the per-client ones are drawn against their own rows.
            ViewBag.HostLogo = ser.EmailConfig?.host_logo ?? "";
            ViewBag.ClientLogo = ser.EmailConfig?.client_logo ?? "";
            ViewBag.HostName = ser.EmailConfig?.host_company_display ?? ser.EmailConfig?.host_company_name ?? "Identity Provider";
            ViewBag.ConsoleCss = AssetUrl(appRoot, CssAsset);
            ViewBag.ConsoleJs = AssetUrl(appRoot, JsAsset);

            // The console's session is the host's authentication cookie, and only the host can
            // drop it. With no route configured, end_session at least ends the session at the IdP
            // and lands on its signed-out page — no post_logout_redirect_uri, because the endpoint
            // honours only URIs the client registered and would ignore anything passed here.
            var signOut = ser.Admin?.SignOutUrl;
            ViewBag.SignOutUrl = string.IsNullOrWhiteSpace(signOut) ? endpoints.EndSession : signOut;

            var name = User.FindFirst("name")?.Value;
            var email = User.FindFirst("email")?.Value ?? User.FindFirst("preferred_username")?.Value;
            ViewBag.UserName = string.IsNullOrWhiteSpace(name) ? (email ?? "signed in") : name;
            ViewBag.UserEmail = email ?? "";

            return View();
        }

        // ------------------------------------------------------------------ static assets

        public const string CssAsset = "ark-admin.css";
        public const string JsAsset = "ark-admin.js";

        /// <summary>
        /// The two files the console is built from, as embedded resources.
        ///
        /// An allow-list rather than a name-to-resource translation: the route segment is
        /// attacker-supplied, and every string in this assembly's manifest — the migration
        /// scripts included — is one resource lookup away from a caller who can shape it.
        /// </summary>
        private static readonly Dictionary<string, (string Resource, string ContentType)> Assets =
            new(StringComparer.OrdinalIgnoreCase)
            {
                [CssAsset] = ("Ark.oAuth.Oidc.wwwroot.css.ark-admin.css", "text/css; charset=utf-8"),
                [JsAsset] = ("Ark.oAuth.Oidc.wwwroot.js.ark-admin.js", "text/javascript; charset=utf-8")
            };

        /// <summary>The package version, used to bust the cache of the URLs below on upgrade.</summary>
        private static readonly string AssetVersion =
            typeof(AdminController).Assembly.GetName().Version?.ToString() ?? "1";

        /// <summary>
        /// The console's stylesheet and script, at a stable path a host page can link to as well —
        /// see <see cref="AssetUrl"/>.
        ///
        /// Anonymous: this is the same static CSS and JavaScript for every caller and holds
        /// nothing worth authenticating for. Behind <c>[Authorize]</c> an expired session would
        /// answer the stylesheet request with the sign-in page, at which point the console renders
        /// unstyled instead of redirecting.
        /// </summary>
        [AllowAnonymous]
        [HttpGet("/ark-admin/asset/{file}")]
        [ResponseCache(Duration = 31536000, Location = ResponseCacheLocation.Any)]
        public IActionResult Asset([FromRoute] string file)
        {
            if (!Assets.TryGetValue(file ?? "", out var asset)) return NotFound();

            var stream = typeof(AdminController).Assembly.GetManifestResourceStream(asset.Resource);
            if (stream == null) return NotFound();

            return File(stream, asset.ContentType);
        }

        /// <summary>
        /// Absolute-path URL for one of the console assets, version-stamped.
        ///
        /// Public because the assets carry the shell styling (top bar, panels, buttons, the
        /// landing layout) that a host's own pages sit inside — the sample host links its layout
        /// here rather than keeping a second copy of the same stylesheet.
        /// </summary>
        public static string AssetUrl(string appRoot, string file) =>
            $"{(appRoot ?? "").TrimEnd('/')}/ark-admin/asset/{file}?v={AssetVersion}";
    }
}
