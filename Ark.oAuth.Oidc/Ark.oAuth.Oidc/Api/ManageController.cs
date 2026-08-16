using Bogus;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc
{
    [Authorize]
    [Route("api/oauth")]
    [ApiController]
    public class ManageController : ControllerBase
    {
        [Route("v1/tenant/list")]
        public async Task<dynamic> TenantList([FromServices] DataAccess da)
        {
            return new
            {
                error = false,
                msg = "tenatns list loaded.",
                data = await da.GetTenants()
            };
        }
        [HttpPost]
        [Route("v1/tenant/upsert")]
        public async Task<dynamic> TenantUpdate([FromServices] DataAccess da, [FromServices] ArkUtil util, [FromBody] ArkTenant tenant)
        {
            if (string.IsNullOrEmpty(tenant.rsa_private))
            {
                dynamic dd = await util.GetKeys();
                tenant.rsa_private = dd.private_key;
                tenant.rsa_public = dd.public_key;
            }
            await da.UpsertTenant(tenant);
            return new
            {
                error = false,
                msg = "tenants updated successfully.",
                data = tenant
            };
        }
        [Route("v1/client/list")]
        public async Task<dynamic> ClientList([FromServices] DataAccess da)
        {
            return new
            {
                error = false,
                msg = "clients list loaded.",
                data = await da.GetClients()
            };
        }
        [HttpPost]
        [Route("v1/client/upsert")]
        public async Task<dynamic> ClientUpdate([FromServices] DataAccess da, [FromBody] ArkClient client)
        {
            try
            {
                await da.UpsertClient(client);
                da.Log("client_upsert", $"{client.client_id}", "Client updated success", $"deails : d: {client.display}, ci: {client.client_id}, name: {client.name}, do: {client.domain}, ru: {client.redirect_url}, em: {client.expire_mins}");
                return new
                {
                    error = false,
                    msg = "clients updated.",
                    data = client
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "v1/client/upsert", $"{client?.client_id}/client/upsert", $"deails : d: {client?.display}, ci: {client?.client_id}, name: {client?.name}, do: {client?.domain}, ru: {client?.redirect_url}, em: {client?.expire_mins}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = client
                };
            }
        }
        [HttpPost]
        [Route("v1/client/delete")]
        public async Task<dynamic> ClientDelete([FromServices] DataAccess da, [FromBody] ArkClient client)
        {
            try
            {
                await da.DeleteClient(client);
                da.Log("client_delete", $"{client.client_id}", "Client deleted success", $"details : d: {client.display}, ci: {client.client_id}, name: {client.name}, do: {client.domain}, ru: {client.redirect_url}, em: {client.expire_mins}");
                return new
                {
                    error = false,
                    msg = "clients deleted.",
                    data = client
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "v1/client/delete", $"{client?.client_id}/v1/client/delete", $"deails : d: {client?.display}, ci: {client?.client_id}, name: {client?.name}, do: {client?.domain}, ru: {client?.redirect_url}, em: {client?.expire_mins}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = client
                };
            }
        }
        [Route("v1/claim/list")]
        public async Task<dynamic> ClaimsList([FromServices] DataAccess da)
        {
            return new
            {
                error = false,
                msg = "claims list loaded.",
                data = await da.GetClaims()
            };
        }
        [HttpPost]
        [Route("v1/claim/upsert")]
        public async Task<dynamic> ClaimUpdate([FromServices] DataAccess da, [FromBody] ArkClaim claim)
        {
            try
            {
                await da.UpsertClaim(claim);
                return new
                {
                    error = false,
                    msg = "claims updated.",
                    data = claim
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = claim
                };
            }
        }
        [Route("v1/user/list")]
        public async Task<dynamic> UserList([FromServices] DataAccess da)
        {
            return new
            {
                error = false,
                msg = "users list loaded.",
                data = await da.GetUsers()
            };
        }
        [Route("v1/user/list/client/claims/mapping/{email}/{ten_id}")]
        public async Task<dynamic> UserClientCLaimsList([FromRoute] string email, [FromRoute] string ten_id, [FromServices] DataAccess da)
        {
            return new
            {
                error = false,
                msg = $"users mapping list loaded.",
                data = await da.GetUsersClientClaims(email, ten_id)
            };
        }
        [HttpPost]
        [Route("v1/user/client/claims/upsert")]
        public async Task<dynamic> UserClaimsUpdate([FromServices] DataAccess da, [FromBody] ArkUserClientClaim us_cl)
        {
            try
            {
                await da.UpsertUsersClientClaims(us_cl);
                da.Log("user_cl_cl_upsert", "v1/user/client/claims/upsert", "user client claims updated", $"deails : e: {us_cl?.email}, ci: {us_cl?.client_id}, claims: {us_cl?.claims_}");
                return new
                {
                    error = false,
                    msg = "user client claims updated.",
                    data = us_cl
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "user_cl_cl_upsert", "v1/user/client/claims/upsert", $"deails : e: {us_cl?.email}, ci: {us_cl?.client_id}, claims: {us_cl?.claims_}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = us_cl
                };
            }
        }
        [HttpPost]
        [Route("v1/user/client/claims/delete")]
        public async Task<dynamic> UserClaimsDelete([FromServices] DataAccess da, [FromBody] ArkUserClientClaim us_cl)
        {
            try
            {
                await da.DeleteUsersClientClaims(us_cl);
                da.Log("user_cl_cl_delete", "v1/user/client/claims/delete", "delete client claims updated", $"deails : e: {us_cl?.email}, ci: {us_cl?.client_id}, claims: {us_cl?.claims_}");
                return new
                {
                    error = false,
                    msg = "user client claims mapping deleted.",
                    data = us_cl
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "user_cl_cl_delete", "v1/user/client/claims/elete", $"deails : e: {us_cl?.email}, ci: {us_cl?.client_id}, claims: {us_cl?.claims_}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = us_cl
                };
            }
        }
        [HttpPost]
        [Route("v1/user/upsert")]
        public async Task<dynamic> UserUpdate([FromServices] DataAccess da, [FromBody] ArkUser user)
        {
            try
            {
                await da.UpsertUser(user);
                da.Log("user_upsert", "v1/user/upsert", "user updated", $"deails : e: {user?.email}, name: {user?.name}, rm: {user?.reset_mode}");
                return new
                {
                    error = false,
                    msg = "user updated.",
                    data = user
                };
            }
            catch (Exception ex)
            {
                da.LogError(ex, "user_upsert", "v1/user/upsert", $"deails : e: {user?.email}, name: {user?.name}, rm: {user?.reset_mode}");
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = user
                };
            }
        }
        [HttpPost]
        [Route("v1/user/pw/reset/init")]
        public async Task<dynamic> UserPasswordResetInit([FromServices] DataAccess da, [FromBody] ArkUser user)
        {
            try
            {
                var dd = await da.UserResetPw(user);
                return new
                {
                    error = !(dd.emailed ?? false),
                    msg = (dd.emailed ?? false) ? "user reset password request initiated." : "user reset password request failed",
                    data = user
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = user
                };
            }
        }
        [HttpPost]
        [Route("v1/service/pw/reset")]
        public async Task<dynamic> ServiceUserRegenerateToken([FromServices] DataAccess da, [FromServices] TokenServer ts, [FromBody] ArkUserClientClaim us_cl)
        {
            try
            {
                ArkUser user = await da.GetUser(us_cl.email);
                ArkTenant tnt = await da.GetTenant(us_cl.tenant_id);
                user.hash_pw = (await ts.BuildAsymmetric_AccessToken(tnt, new System.Security.Claims.Claim[] { new System.Security.Claims.Claim("service_role", "service_role") }, 525600)).Item1;
                var dd = await da.UserResetPw(user);
                return new
                {
                    msg = "service account token reset completed.",
                    data = user
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    error = true,
                    msg = $"{ex.Message}",
                    data = us_cl
                };
            }
        }
        [Route("onboard/full")]
        public async Task<dynamic> OnboardFull([FromServices] Onboard onb,
            [FromQuery] string ten_id,
            [FromQuery] string client_id,
            [FromQuery] string suffix,
            [FromQuery] string client_base_url,
            [FromQuery] string client_relative_url,
            [FromQuery] string claim_keys, //"claim1, claim2"
            [FromQuery] string user_email,
            [FromQuery] string user_suffix,
            [FromQuery] string user_type)
        {
            try
            {
                await onb.FullSet(ten_id,
                    client_id,
                    suffix,
                    client_base_url,
                    client_relative_url,
                    (claim_keys ?? "").Split(',').Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).ToList(),
                    user_email,
                    user_suffix,
                    user_type);
                return new
                {
                    error = false,
                    msg = $"onboarded client {client_id} to tenant {ten_id}"
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    error = true,
                    msg = $"{ex.Message}"
                };
            }
        }
        [Route("onboard/user")]
        public async Task<dynamic> OnboardUser([FromServices] Onboard onb,
            [FromQuery] string ten_id,
            [FromQuery] string client_id,
            [FromQuery] string claim_keys, //"claim1, claim2"
            [FromQuery] string user_email,
            [FromQuery] string user_pw,
            [FromQuery] string full_name,
            [FromQuery] string user_type)
        {
            try
            {
                await onb.UserOnboard(ten_id,
                    client_id,
                    (claim_keys ?? "").Split(',').Where(t => !string.IsNullOrWhiteSpace(t)).Select(t => t.Trim()).ToList(),
                    user_email,
                    user_pw,
                    full_name,
                    user_type);
                return new
                {
                    error = false,
                    msg = $"onboarded user {user_email} to client_id: {client_id}."
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    error = true,
                    msg = $"{ex.Message}"
                };
            }
        }
    }
}
