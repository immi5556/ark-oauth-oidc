using Microsoft.EntityFrameworkCore;
using System.Reflection;
using ark.net.util;

namespace Ark.oAuth.Oidc
{
    public class EmbeddedResourceUnpacker
    {
        /// <summary>
        /// Examines the Foundation DLL and creates files on disk for each of them
        /// </summary>
        /// <returns></returns>
        public async Task UnpackFiles(IWebHostEnvironment env)
        {
            // We only need to do this in Development mode.  The assumption being that the developer will have unpacked the correct Foundation
            // version and these files will be committed to source control etc, just like normal files
            if (!env.IsDevelopment()) return;

            var foundationAssembly = typeof(Ark.oAuth.Oidc.EmbeddedResourceUnpacker).GetTypeInfo().Assembly;
            var assemblyName = foundationAssembly.GetName().Name;

            // Iterate over each embedded resource
            var names = foundationAssembly.GetManifestResourceNames();
            foreach (var name in names)
            {
                var ext = System.IO.Path.GetExtension(name);
                var filePath = System.IO.Path.GetFileNameWithoutExtension(name);
                // Embedded files are prefixed with the full namespace of the assembly, so your file is stored at wwwroot/foundation.css, then
                // Here, we strip the assembly name from the start - note the following '.' too
                filePath = filePath.Replace(assemblyName + ".", "");

                // Parse file path
                filePath = filePath.Replace('.', Path.DirectorySeparatorChar) + ext;

                // Reset files - order is important!!
                // filePath = this.ResetFileExtension(filePath, ".cshtml");
                // filePath = this.ResetFileExtension(filePath, ".min.css");
                // filePath = this.ResetFileExtension(filePath, ".css");
                // filePath = this.ResetFileExtension(filePath, ".d.ts");
                // filePath = this.ResetFileExtension(filePath, ".min.js");
                // filePath = this.ResetFileExtension(filePath, ".js");
                // filePath = this.ResetFileExtension(filePath, ".otf");
                // filePath = this.ResetFileExtension(filePath, ".eot");
                // filePath = this.ResetFileExtension(filePath, ".svg");
                // filePath = this.ResetFileExtension(filePath, ".ttf");
                // filePath = this.ResetFileExtension(filePath, ".woff");
                // filePath = this.ResetFileExtension(filePath, ".png");
                // filePath = this.ResetFileExtension(filePath, ".jpg");
                // filePath = this.ResetFileExtension(filePath, ".gif");
                // filePath = this.ResetFileExtension(filePath, ".ico");
                // filePath = this.ResetFileExtension(filePath, ".html");

                // Now prepend the root path of this application, on disk
                filePath = System.IO.Path.Combine(env.ContentRootPath, filePath);
                var directory = System.IO.Path.GetDirectoryName(filePath);
                System.IO.Directory.CreateDirectory(directory);
                // Copy
                using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
                {
                    using (var file = new FileStream(filePath, FileMode.Create, FileAccess.ReadWrite))
                    {
                        resource.CopyTo(file);
                    }
                }
            }
        }

        /// <summary>
        /// Helper routine
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="requiredExtension"></param>
        /// <returns></returns>
        private string ResetFileExtension(string fileName, string requiredExtension)
        {
            var encodedExtension = requiredExtension.Replace(".", "\\");
            if (!fileName.EndsWith(encodedExtension)) return fileName;
            fileName = fileName.Substring(0, fileName.Length - encodedExtension.Length) + requiredExtension;
            return fileName;
        }
    }
    public static class ArkExtn
    {
        // Database initialisation only ever needs to happen once per process. Previously this
        // ran on every single request — opening a scope, querying pending migrations and
        // probing the connection before the real work could start.
        private static int _dataInitialized;

        public static void UseArkAuthData(this IApplicationBuilder builder)
        {
            builder.Use(async (context, next) =>
            {
                if (Interlocked.CompareExchange(ref _dataInitialized, 1, 0) != 0)
                {
                    await next();
                    return;
                }
                using (var scope = builder.ApplicationServices.CreateScope())
                {
                    try
                    {
                        var dbContext = scope.ServiceProvider.GetRequiredService<ArkDataContext>();
                        if (dbContext.Database.GetPendingMigrations().Any())
                        {
                            dbContext.Database.Migrate();
                        }
                        else if (!dbContext.Database.CanConnect())
                        {
                            dbContext.Database.EnsureCreated();
                            var conf = scope.ServiceProvider.GetRequiredService<IConfiguration>();
                            var ser = conf.GetSection("ark_oauth_server").Get<ArkAuthServerConfig>() ?? throw new ApplicationException("server config missing");
                            var htp = scope.ServiceProvider.GetService<IHttpContextAccessor>();
                            var util = scope.ServiceProvider.GetRequiredService<ArkUtil>();
                            // Signing keys are generated here, in this process. They used to be
                            // fetched from an external HTTPS service, which put the tenant's
                            // private key on the wire and on someone else's machine.
                            var (publicKey, privateKey) = Protocol.ArkCrypto.GenerateRsaKeyPair();
                            var baseurl = !string.IsNullOrEmpty(ser.BaseUrl) ? ser.BaseUrl : $"{htp.HttpContext.Request.Scheme}://{htp.HttpContext.Request.Host}";
                            var domain = new Uri(baseurl).Host;
                            //1st time -> create client for server to manage users
                            var tt = new ArkTenant()
                            {
                                tenant_id = ser.TenantId,
                                name = ser.TenantId,
                                display = $"{ser.TenantId} Admin Console",
                                audience = $"{baseurl}/ark/oauth/v1/aud",
                                issuer = $"{baseurl}/ark/oauth/v1/iss",
                                expire_mins = 480,
                                rsa_private = privateKey,
                                rsa_public = publicKey,
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss")
                            };
                            dbContext.tenants.Add(tt);
                            dbContext.signing_keys.Add(new ArkSigningKey()
                            {
                                // kid == tenant_id keeps tokens verifiable by clients that were
                                // configured against the pre-JWKS key layout
                                kid = ser.TenantId,
                                tenant_id = ser.TenantId,
                                alg = "RS256",
                                usage = "sig",
                                public_key = publicKey,
                                private_key = privateKey,
                                status = "active",
                                created_at = DateTime.UtcNow
                            });
                            foreach (var sc in Protocol.ArkClaimsService.DefaultScopes())
                                dbContext.scopes.Add(sc);
                            var cll = new ArkClient()
                            {
                                tenant_id = ser.TenantId,
                                client_id = $"{ser.TenantId}_client", //same as server id
                                display = $"{ser.TenantId} Client App (Display)",
                                domain = $"{domain}",
                                expire_mins = 480,
                                name = $"{ser.TenantId} name",
                                redirect_relative = $"{(ser.BasePath.AnyNull() ? "" : $"/{ser.BasePath}")}/oauth/{ser.TenantId}/v1/server/{ser.TenantId}_client/manage",
                                //redirect_relative = $"/auth/oauth/{ser.TenantId}/v1/server/{{0}}/manage",
                                redirect_url = $"{baseurl}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}/")}oauth/{ser.TenantId}/v1/client/{ser.TenantId}_client/callback",
                                //redirect_url = $"{baseurl}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}/")}oauth/{ser.TenantId}/v1/client/{{0}}/callback",
                                logout_url = $"{baseurl}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}/")}oauth/{ser.TenantId}/v1/client/{ser.TenantId}_client/logoff",
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),

                                // standard registration metadata for the admin console client.
                                // It runs in a browser, so it is public and must use PKCE.
                                client_name = $"{ser.TenantId} Admin Console",
                                application_type = "web",
                                token_endpoint_auth_method = "none",
                                require_pkce = true,
                                refresh_token_rotation = true,
                                is_active = true,
                                grant_types = new List<string>() { "authorization_code", "refresh_token" },
                                response_types = new List<string>() { "code" },
                                scopes = new List<string>() { "openid", "profile", "email", "offline_access" },
                                redirect_uris = new List<string>()
                                {
                                    // the v1 callback, kept so existing deployments keep working
                                    $"{baseurl}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}/")}oauth/{ser.TenantId}/v1/client/{ser.TenantId}_client/callback",
                                    // the standard callback used by the ASP.NET Core OIDC handler
                                    $"{baseurl}/signin-oidc"
                                },
                                post_logout_redirect_uris = new List<string>()
                                {
                                    $"{baseurl}/{(string.IsNullOrEmpty(ser.BasePath) ? "" : $"{ser.BasePath}/")}oauth/{ser.TenantId}/v1/client/{ser.TenantId}_client/logoff",
                                    $"{baseurl}/signout-callback-oidc"
                                }
                            };
                            dbContext.clients.Add(cll);
                            var lls = new List<string>()
                            {
                                "sub",
                                "iss",
                                "aud",
                                "exp",
                                "iat",
                                "name",
                                "family_name",
                                "given_name",
                                "email",
                                "email_verified",
                                "gender",
                                "phone_number",
                                "address"
                            };
                            foreach (var item in lls)
                            {
                                dbContext.claims.Add(new ArkClaim() { key = item, display = item });
                            }
                            //admin user
                            dbContext.users.Add(new ArkUser()
                            {
                                //claims = lls,
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                                //client_id = $"{ser.TenantId}_client",
                                email = "admin",
                                emailed = false,
                                hash_pw = util.HashPasswordPBKDF2("admin"),
                                reset_mode = false,
                                type = "user",
                                name = "Admin User"
                            });
                            dbContext.user_client_claims.Add(new ArkUserClientClaim()
                            {
                                claims = lls,
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                                client_id = $"{cll.id}",
                                tenant_id = $"{ser.TenantId}",
                                email = "admin"
                            });
                            var ts = scope.ServiceProvider.GetRequiredService<TokenServer>();
                            //service user service_user
                            dbContext.users.Add(new ArkUser()
                            {
                                //claims = lls,
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                                //client_id = $"{ser.TenantId}_client",
                                email = $"service_account_{ser.TenantId}",
                                emailed = false,
                                hash_pw = (await ts.BuildAsymmetric_AccessToken(tt, new System.Security.Claims.Claim[] { new System.Security.Claims.Claim("service_role", "service_role") }, 525600)).Item1, // secret
                                reset_mode = false,
                                type = "service",
                                name = "Service Account (Default)"
                            });
                            dbContext.user_client_claims.Add(new ArkUserClientClaim()
                            {
                                claims = new List<string>() { "service_role" },
                                at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss"),
                                client_id = $"{cll.id}",
                                tenant_id = $"{ser.TenantId}",
                                email = $"service_account_{ser.TenantId}"
                            });
                            dbContext.SaveChanges();
                        }
                    }
                    catch (Exception ex)
                    {
                        // Log error
                        throw new Exception("Database initialization failed", ex);
                    }
                }
                await next();
            });
        }
        //all server config is taken from database
        public static void AddArkOidcServer(this IServiceCollection services, IWebHostEnvironment environment)
        {
            var unpack = new EmbeddedResourceUnpacker();
            var task = unpack.UnpackFiles(environment);
            Task.WaitAll(task);
            services.AddDbContext<ArkDataContext>();
            services.AddScoped<DataAccess>();
            services.AddScoped<TokenServer>();
            services.AddSingleton<ArkUtil>();
            services.AddScoped<Onboard>();

            // standard OAuth 2.1 / OIDC protocol services
            services.AddMemoryCache();
            services.AddHttpClient("ark-oidc", c => c.Timeout = TimeSpan.FromSeconds(10));
            services.AddScoped<Protocol.ArkKeyService>();
            services.AddScoped<Protocol.ArkClaimsService>();
            services.AddScoped<Protocol.ArkTokenService>();
            services.AddScoped<Protocol.ArkGrantStore>();
            services.AddScoped<Protocol.ArkClientAuthenticator>();

            // the interactive endpoints render Razor views shipped inside this package
            services.AddControllersWithViews();
            services.AddAntiforgery(o => o.Cookie.Name = "ark_idp_csrf");
        }
    }
    public static class ExtnUtil
    {
        public static byte[] ToByteArray(this string x) => Convert.FromBase64String(x);
        public static string ToHex(this byte[] x) => BitConverter.ToString(x).Replace("-", "").ToLower();
    }
}
