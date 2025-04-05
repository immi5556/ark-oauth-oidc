using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding.Validation;
using MySqlX.XDevAPI;
using System.Runtime.ConstrainedExecution;

namespace Ark.oAuth.Oidc.Controllers
{
    [Route("oauth")]
    public class ServerController : Controller
    {
        TokenServer _ts;
        DataAccess _da;
        IConfiguration _config;
        public ServerController(TokenServer ts, DataAccess da, IConfiguration config)
        {
            _ts = ts;
            _da = da;
            _config = config;
        }
        [Route("signin-oidc/{client_id}/claims")]
        public async Task<dynamic> GetClaimsByCode([FromRoute] string client_id, [FromQuery] string code)
        {
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            ViewBag.IsError = false;
            client_id = string.IsNullOrEmpty(client_id) ? ser.ClientId : client_id;
            var cc = await _da.GetClient(client_id);
            ViewBag.client_url = $"{Request.Scheme}://{Request.Host}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}")}/oauth/v1/.well-known/{client_id}/openid-configuration";
            return View();
        }
        [Route("connect/authorize")]
        public IActionResult Index([FromQuery] string client_id)
        {
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            ViewBag.IsError = false;
            client_id = string.IsNullOrEmpty(client_id) ? ser.ClientId : client_id;
            ViewBag.client_url = $"{Request.Scheme}://{Request.Host}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}")}/oauth/v1/.well-known/{client_id}/openid-configuration";
            return View();
        }
        [HttpPost]
        [Route("connect/authorize")]
        public async Task<IActionResult> Index([FromForm] string Username, [FromForm] string Password,
            [FromQuery] string response_type,
            [FromQuery] string client_id,
            [FromQuery] string redirect_uri,
            [FromQuery] string scope,
            [FromQuery] string state,
            [FromQuery] string code_challenge,
            [FromQuery] string code_challenge_method)
        {
            ViewBag.IsError = false;
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            ViewBag.client_url = $"{Request.Scheme}://{Request.Host}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}")}/v1/.well-known/{client_id}/openid-configuration";
            try
            {
                var cc = await _da.GetClient(client_id);
                if (cc == null) throw new ApplicationException("invalid_client");
                if (cc.redirect_url.ToLower().Trim() != redirect_uri.ToLower().Trim()) throw new ApplicationException("invalid_redirect_uri");
                var tkn = await _ts.BuildAsymmetric_AccessToken(cc, code_challenge);
                await _da.UpsertPkceCode(tkn.Item1, cc, code_challenge, code_challenge, code_challenge_method, state, scope, "", tkn.Item2, redirect_uri, response_type);
                return Redirect($"{cc.redirect_url}?token={tkn.Item1}");
            }
            catch (Exception ex)
            {
                ViewBag.IsError = true;
                ViewBag.msg = ex.Message;
            }
            return View();
        }
        [Authorize]
        [Route("v1/server/manage")]
        public IActionResult Manage()
        {
            ViewBag.IsError = false;
            return View();
        }

        [Route("v1/.well-known/{client_id}/openid-configuration")]
        public async Task<dynamic> Wellknown([FromRoute] string client_id)
        {
            var cc = await _da.GetClient(client_id);
            var ser = _config.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
            return new
            {
                code_challenge_methods_supported = new List<string>() { "S256" },
                grant_types_supported = new List<string>() { "authorization_code", "client_credentials", "refresh_token" },
                response_types_supported = new List<string>() { "code" },
                client_config_section = new
                {
                    ark_oauth_client = new
                    {
                        Issuer = cc.issuer,
                        Audience = cc.audience,
                        RsaPublic = cc.rsa_public,
                        RedirectUri = cc.redirect_url,
                        AuthServerUrl = $"{Request.Scheme}://{Request.Host}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}/oauth")}",
                        ClientId = cc.client_id,
                        Domain = cc.domain,
                        ExpireMins = cc.expire_mins
                    }
                }
            };
        }
    }
}