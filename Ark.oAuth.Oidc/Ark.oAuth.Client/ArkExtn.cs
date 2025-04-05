using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace Ark.oAuth
{
    public class ArkAuthConfig
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string RsaPublic { get; set; }
        public string RedirectUri { get; set; }
        public string RedirectRelative { get; set; }
        public string AuthServerUrl { get; set; }
        public string ClientId { get; set; }
        public string Domain { get; set; }
        public int ExpireMins { get; set; } = 480;
    }
    public static class ArkExtn
    {
        static ArkAuthConfig LoadConfig(IConfiguration configuration)
        {
            return configuration.GetSection("ark_oauth_client").Get<ArkAuthConfig>() ?? throw new ApplicationException("config missing");
        }
        //All client config is taken from app settings
        public static void AddArkOidcClient(this IServiceCollection services, IConfiguration configuration)
        {
            services
                .AddAuthentication(Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme)
            //    .AddAuthentication(options =>
            //{
            //    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            //    //options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            //})
            .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false; // Set to true in production
                options.SaveToken = true;
                // Enable detailed logging in your token validation
                options.IncludeErrorDetails = true;
                var jwt = LoadConfig(configuration);
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwt.Issuer,
                    ValidateAudience = true,
                    ValidAudience = jwt.Audience,
                    ValidateLifetime = true,
                    IssuerSigningKeyResolver = (string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters) =>
                    {
                        List<SecurityKey> keys = new List<SecurityKey>();
                        //if (!config.app_list.ContainsKey(kid)) throw new SecurityTokenInvalidSignatureException("Unable to validate signature, invalid token with 'kid' value.");
                        //var app = config.app_list[kid];
                        var pub_conf_key = jwt.RsaPublic;
                        var publicKey = Convert.FromBase64String(pub_conf_key);
                        RSA rsa = RSA.Create();
                        rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                        keys.Add(new RsaSecurityKey(rsa));
                        return keys;
                    },
                    ValidateIssuerSigningKey = true,
                    //AudienceValidator = (IEnumerable<string> issuer, SecurityToken securityToken, TokenValidationParameters validationParameters) =>
                    //{
                    //    return true;
                    //},
                    //IssuerValidator = (string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters) =>
                    //{
                    //    return issuer;
                    //},
                    //LifetimeValidator = (DateTime? notBefore, DateTime? expires, SecurityToken securityToken, TokenValidationParameters validationParameters) =>
                    //{
                    //    if (notBefore.HasValue && DateTime.UtcNow > notBefore.Value
                    //    && expires.HasValue && DateTime.UtcNow < expires.Value)
                    //        return true;
                    //    return false;
                    //},
                    ClockSkew = TimeSpan.FromMinutes(1)
                };
                options.Events = new JwtBearerEvents
                {
                    //No token (should trigger OnChallenge)
                    //Invalid token (should trigger OnAuthenticationFailed)
                    //Valid token (should trigger OnMessageReceived → OnTokenValidated)
                    OnAuthenticationFailed = ctx =>
                    {
                        //https://localhost:5001/connect/authorize?response_type=code
                        //&client_id=webapp
                        //&redirect_uri=https://localhost:5002/signin-oidc
                        //&scope=openid profile email api1
                        //&state=random_state_value
                        //&code_challenge=your_code_challenge
                        //&code_challenge_method=S256
                        var state = ctx.Request.Query.ContainsKey("state") ? ctx.Request.Query["state"][0] : "";
                        var code_challenge = ctx.Request.Query.ContainsKey("code_challenge") ? ctx.Request.Query["code_challenge"][0] : "";
                        var ff = $"{jwt.AuthServerUrl}/connect/authorize?response_type=code&client_id={jwt.ClientId}&redirect_uri={jwt.RedirectUri}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256&err=invalid_token";
                        ctx.Response.Redirect($"{ff}");
                        return Task.CompletedTask;
                    },
                    OnForbidden = ctx =>
                    {
                        var ff = $"err=access_denied";
                        ctx.Response.Redirect($"/auth?{ff}");
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = ctx =>
                    {
                        Console.WriteLine("correct token");
                        return Task.CompletedTask;
                    },
                    OnChallenge = ctx =>
                    {
                        //if (ctx.AuthenticateFailure != null || ctx.Error != null || ctx.ErrorUri != null)
                        //{
                        //its no tken, so inititate auth process
                        ctx.HandleResponse();
                        var state = ctx.Request.Query.ContainsKey("state") ? ctx.Request.Query["state"][0] : "";
                        var code_challenge = PkceHelper.GenerateCodeChallenge($"JESUSmyLORD_{ark.net.util.DateUtil.CurrentTimeStamp()}");
                        var ff = $"{jwt.AuthServerUrl}/connect/authorize?response_type=code&client_id={jwt.ClientId}&redirect_uri={jwt.RedirectUri}&state={state}&code_challenge={code_challenge}&code_challenge_method=S256&err=token_error";
                        ctx.Response.Redirect($"{ff}");
                        //}
                        return Task.CompletedTask;
                    },
                    OnMessageReceived = msg =>
                    {
                        Console.WriteLine(msg);
                        return Task.CompletedTask;
                    }
                };
            });

            services.AddHttpContextAccessor();
        }

        public static void UseArkOidcClient(this IApplicationBuilder builder)
        {
            builder.Use(async (context, next) =>
            {
                if (context.Request.Query.ContainsKey("err") && !string.IsNullOrEmpty(context.Request.Query["err"]) && (context.Request.Query["err"] == "access_denied" || context.Request.Query["err"] == "invalid_token"))
                {
                    CookieOptions option = new CookieOptions();
                    option.Expires = DateTime.Now.AddDays(-1);
                    option.Secure = true;
                    option.IsEssential = true;
                    context.Response.Cookies.Append("ark_oauth_tkn", string.Empty, option);
                    context.Response.Cookies.Delete("ark_oauth_tkn");
                }
                var token = context.Request.Cookies[$"ark_oauth_tkn"];
                if (!string.IsNullOrEmpty(token))
                {
                    context.Request.Headers.Add("Authorization", "Bearer " + token);
                }
                await next();
            });
        }
    }
    public static class PkceHelper
    {
        public static string GenerateCodeVerifier()
        {
            var randomBytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);
            return Base64UrlEncode(randomBytes);
        }

        public static string GenerateCodeChallenge(string codeVerifier)
        {
            using var sha256 = SHA256.Create();
            var challengeBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(codeVerifier));
            return Base64UrlEncode(challengeBytes);
        }

        private static string Base64UrlEncode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }
    }
}