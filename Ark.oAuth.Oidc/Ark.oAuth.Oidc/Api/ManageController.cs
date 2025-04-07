using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc
{
    [Authorize]
    [Route("api/oauth")]
    [ApiController]
    public class ManageController : ControllerBase
    {
        [Route("{tenant_id}/v1/tenant/list")]
        public async Task<dynamic> TenantList([FromServices] DataAccess da)
        {
            return new
            { 
                error = false,
                msg = "tenatns list loaded.",
                data = await da.GetTenants() 
            };
        }
        //[Route("{tenant_id}/v1/tenant/list")]
        //public async Task<dynamic> TenantList([FromServices] DataAccess da)
        //{
        //    return new
        //    {
        //        error = false,
        //        msg = "tenatns list loaded.",
        //        data = await da.GetTenants()
        //    };
        //}
    }
}
