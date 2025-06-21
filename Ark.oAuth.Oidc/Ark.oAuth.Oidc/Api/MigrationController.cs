/*********************
 * Migration script
 * 1. up url        : auth/api/migration/v1/sql?action=up&name=Ark.oAuth.Oidc.Migration.Sql.up.00001_sql.sql
 *    rollback url  : auth/api/migration/v1/sql?action=down&name=Ark.oAuth.Oidc.Migration.Sql.down.00001_sql.sql
 *    details: base start with - adding client_logo column
 * 2. up url        : auth/api/migration/v1/sql/?action=up&name=Ark.oAuth.Oidc.Migration.Sql.up.00002_sql.sql
 *    rollback url  : auth/api/migration/v1/sql/?action=down&name=Ark.oAuth.Oidc.Migration.Sql.down.00002_sql.sql
 *    details: created new ark_status table to get user retry attempt
 *********************/
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc
{
    [Route("api/migration")]
    [ApiController]
    public class MigrationController : ControllerBase
    {
        //[Route("v1/{action}/sql/{name}")]
        [Route("v1/sql")]
        [HttpGet]
        public async Task<dynamic> ExexuteMigration([FromServices] DataAccess da, [FromQuery] string action, [FromQuery] string name)
        //public async Task<dynamic> ExexuteMigration([FromServices] DataAccess da)
        {
            //name: "Ark.oAuth.Oidc.Migration.Sql.up.00001_sql.sql"; //embedded file name
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
