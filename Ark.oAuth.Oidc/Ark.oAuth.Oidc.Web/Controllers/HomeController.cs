using Ark.oAuth.Oidc.Web.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;

namespace Ark.oAuth.Oidc.Web.Controllers
{
    public class HomeController : Controller
    {
        ArkDataContext _ctx;

        public HomeController(ArkDataContext ctx)
        {
            _ctx = ctx;
        }

        public IActionResult Index()
        {
            //ViewBag.claims = _ctx.oidc_claims.ToList();
            var ss = _ctx.Database.GenerateCreateScript();
            Console.WriteLine(ss);
            return View();
        }

        public IActionResult User()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}