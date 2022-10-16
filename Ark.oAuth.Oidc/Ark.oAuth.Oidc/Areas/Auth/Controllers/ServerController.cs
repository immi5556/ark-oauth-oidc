using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc.Areas.Auth.Controllers
{
    [Area("auth")]
    [Route("auth/server")]
    public class ServerController : Controller
    {
        [Route("")]
        public IActionResult Index()
        {
            return View();
        }
    }
}
