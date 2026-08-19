/*********************
 * Migration script
 * 1. up url        : auth/api/migration/v1/sql?action=up&name=00001_sql.sql
 *    rollback url  : auth/api/migration/v1/sql?action=down&name=00001_sql.sql
 *    details: base start with - adding client_logo column
 * 2. up url        : auth/api/migration/v1/sql/?action=up&name=00002_sql.sql
 *    rollback url  : auth/api/migration/v1/sql/?action=down&name=00002_sql.sql
 *    details: created new ark_status table to get user retry attempt
 *
 * Since 2.1.1 these run by themselves: AddArkOidcServer's bootstrap applies every script the
 * database has not had yet and records it in ark_schema_history, so this endpoint is only needed
 * to roll one back, or to drive a provider whose scripts are not embedded here. See
 * ArkSchemaUpdater.
 *********************/
using Microsoft.AspNetCore.Mvc;

namespace Ark.oAuth.Oidc
{
    [Route("api/migration")]
    [ApiController]
    public class MigrationController : ControllerBase
    {
        [Route("v1/sql")]
        [HttpGet]
        public async Task<dynamic> ExexuteMigration([FromServices] DataAccess da, [FromQuery] string action, [FromQuery] string name)
        {
            //name: "00001_sql.sql"; //file name inside Migration/{provider}/{up|down}
            try
            {
                // The result is read now. Both calls catch their own exceptions and report through
                // a bool, so ignoring it meant a failed migration answered "executed." — which is
                // how a database ends up one script behind while its operator believes otherwise.
                var runner = new MigrationScript();
                var verb = (action ?? "").ToLower().Trim();
                var ok = verb switch
                {
                    "up" => runner.Migrate(da, name),
                    "down" => runner.Rollback(da, name),
                    _ => throw new ApplicationException($"unknown action '{action}' - use 'up' or 'down'.")
                };
                return new
                {
                    error = !ok,
                    msg = ok
                        ? $"migration {name} executed."
                        : $"migration {name} failed. {runner.Error}"
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
        [Route("v1/embeded/list")]
        [HttpGet]
        public async Task<dynamic> GetEmbeds()
        {
            return new
            {
                msg = "list of embedded resource",
                list = MigrationScript.GetEmbeddedResources()
            };
        }
    }
}