/*********************
 * Migration script
 * 1. up url        : api/migration/v1/up/Ark.oAuth.Oidc.Migration.Sql.up.00001_sql.sql
 *    rollback url  : api/migration/v1/down/Ark.oAuth.Oidc.Migration.Sql.up.00001_sql.sql 
 *    details: base start with - adding client_logo column
 *********************/
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc.Api
{
    [Route("api/migration")]
    [ApiController]
    public class MigrationController : ControllerBase
    {
        [Route("v1/{action}/{name}")]
        public async Task<dynamic> ExexuteMigration([FromServices] DataAccess da, [FromRoute] string action, [FromRoute] string name)
        {
            //name: "Ark.oAuth.Oidc.Migration.Sql.up.00001_sql.sql"; //embedded file name
            //api/migration/v1/Ark.oAuth.Oidc.Migration.Sql.up.00001_sql.sql
            try
            {
                if (action.ToLower().Trim() == "up") new MigrationScript().Migrate(da, name);
                if (action.ToLower().Trim() == "down") new MigrationScript().Rollback(da, name);
                return new
                {
                    error = false,
                    msg = $"migration {name} execcuted."
                };
            }
            catch (Exception ex)
            {
                return new
                {
                    error = true,
                    msg = $"migration {name} failed. {ex.ToString()}"
                };
            }
        }
    }
}
