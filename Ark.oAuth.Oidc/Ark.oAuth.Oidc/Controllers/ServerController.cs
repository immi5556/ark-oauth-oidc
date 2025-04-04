using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc.Controllers
{
    [Area("auth")]
    [Route("auth/server")]
    public class ServerController : Controller
    {
        ArkSetting _setting;
        TokenServer _tokenserver;
        public ServerController(ArkSetting setting,
            TokenServer tokenserver)
        {
            _setting = setting;
            _tokenserver = tokenserver;
        }
        [Route("")]
        public IActionResult Index()
        {
            return View();
        }
    }
}
