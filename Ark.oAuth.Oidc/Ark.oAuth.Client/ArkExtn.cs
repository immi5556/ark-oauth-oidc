using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace Ark.oAuth
{
    public class ArkConfig
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string RsaPublic { get; set; }
        public string RedirectUri { get; set; }
        public string AuthServerUrl { get; set; }
        public string Domain { get; set; }
    }
    public static class ArkExtn
    {
        static ArkConfig LoadConfig(IConfiguration configuration)
        {
            return configuration.GetSection("Jwt").Get<ArkConfig>() ?? throw new ApplicationException("config missing");
        }
        public static void AddArkOidc(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = false; // Set to true in production
                options.SaveToken = true;
                var jwt = LoadConfig(configuration);
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    ValidateIssuer = true,
                    ValidIssuer = jwt.Issuer,
                    ValidateAudience = true,
                    ValidAudience = jwt.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero,
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
                    }
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
                        var ff = $"{jwt.AuthServerUrl}/connect/authorize?response_type=code&client_id=webapp&redirect_uri=https://localhost:5002/signin-oidc&err=invalid_token";
                        ctx.Response.Redirect($"/auth?{ff}");
                        return Task.CompletedTask;
                    },
                    OnForbidden = async ctx =>
                    {
                        var ff = $"err=access_denied";
                        ctx.Response.Redirect($"/auth?{ff}");
                    },
                    OnTokenValidated = async ctx =>
                    {
                        Console.WriteLine("correct token");
                    },
                    OnChallenge = async ctx =>
                    {
                        ctx.HandleResponse();
                        var ff = $"err=token_error";
                        ctx.Response.Redirect($"/auth?{ff}");
                    }
                };
            });
        }
    }
}