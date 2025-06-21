using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Migrations;
using Mysqlx.Expr;

namespace Ark.oAuth.Oidc
{
    public class MigrationScript
    {
        public static string[] GetEmbeddedResources()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            var nn = assembly.GetManifestResourceNames();
            return nn;
        }
        public static string ReadEmbeddedResource(string resourceName)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            using (Stream stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream == null)
                {
                    Console.WriteLine($"Error: Embedded resource '{resourceName}' not found.");
                    Console.WriteLine("Available resources:");
                    foreach (string name in assembly.GetManifestResourceNames())
                    {
                        Console.WriteLine($"- {name}");
                    }
                    return null;
                }
                using (StreamReader reader = new StreamReader(stream))
                {
                    return reader.ReadToEnd();
                }
            }
        }
        public void Rollback(DataAccess da, string name)
        {
            try
            {
                Down(da, name); //Ark.oAuth.Oidc.Migration.Sql.down.00001_sql.sql - rollback embedded name
            }
            catch { }
        }
        public bool Migrate(DataAccess da, string name)
        {
            try
            {
                //name = "Ark.oAuth.Oidc.Migration.Sql.up.00001_sql.sql"; //embedded file name
                Up(da, name);
                da.Log("migrattion_failed", $"{name}", $"migration successful", "");
                return true;
            }
            catch (Exception exp)
            {
                da.LogError(exp, "migrattion_failed", $"{name}", $"migration files with exception.");
                return false;
            }
        }
        string sqlScript;
        protected async Task Up(DataAccess da, string name)
        {
            var pn = da.GetCtx().Database.ProviderName;
            switch (pn)
            {
                case "Microsoft.EntityFrameworkCore.SqlServer":
                    sqlScript = ReadEmbeddedResource(name);
                    break;
                case "Npgsql.EntityFrameworkCore.PostgreSQL":
                    sqlScript = ReadEmbeddedResource(name);
                    break;
                case "MySql.EntityFrameworkCore":
                    sqlScript = ReadEmbeddedResource(name);
                    break;
                case "Microsoft.EntityFrameworkCore.Sqlite":
                    sqlScript = ReadEmbeddedResource(name);
                    break;
                default:
                    throw new NotSupportedException($"Up failed: {pn}, {name}");
            }
            await da.ExecuteRaw(sqlScript);
        }

        protected async Task Down(DataAccess da, string name)
        {
            var pn = da.GetCtx().Database.ProviderName;
            switch (pn)
            {
                case "Microsoft.EntityFrameworkCore.SqlServer":
                    sqlScript = File.ReadAllText("Migrations/SqlScripts/SqlServer_AddCustomFunction.sql");
                    break;
                case "Npgsql.EntityFrameworkCore.PostgreSQL":
                    sqlScript = File.ReadAllText("Migrations/SqlScripts/SqlServer_AddCustomFunction.sql");
                    break;
                case "MySql.EntityFrameworkCore":
                    sqlScript = File.ReadAllText("Migrations/SqlScripts/SqlServer_AddCustomFunction.sql");
                    break;
                case "Microsoft.EntityFrameworkCore.Sqlite":
                    throw new NotSupportedException(
                        $"Dropping user-defined functions via raw SQL is not applicable for SQLite. " +
                        $"Active Provider: {pn}"
                    );
                default:
                    throw new NotSupportedException($"Down failed: {pn}, {name}");
            }
            await da.ExecuteRaw(sqlScript);
        }
    }
}
