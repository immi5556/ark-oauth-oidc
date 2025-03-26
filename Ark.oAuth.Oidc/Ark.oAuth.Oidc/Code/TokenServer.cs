using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Ark.oAuth.Oidc
{
    public class TokenServer
    {
        ArkSetting _setting;
        public TokenServer(ArkSetting setting)
        {
            _setting = setting;
        }
        public async Task<ArkJwt> Verify(string project_id, string code, string verifier)
        {
            try
            {
                using (var ctx = GetCtx())
                {
                    var tkn = ctx.pkce_code_flow.Where(t => t.code == code && t.project_id == project_id).Select(t => t).FirstOrDefault();
                    if (tkn == null) throw new ApplicationException("invalid_code");
                    //TO DO: Immi -> fix this at session scope not at user lvel.
                    //if (tkn.code_challenge.ToSha256Hash() != verifier) throw new ApplicationException($"invalid_verifier");
                    return await Task.FromResult(new ArkJwt() { id_token = tkn.id_token, expires_in = tkn.expires_at.ToString() });
                }
            }
            catch (Exception ex)
            {
                return await Task.FromResult(new ArkJwt() { error = new ArkError() { code = ex.Message } });
            }
        }
        public ArkError ValidateRefreshToken(string refresh_roken, string project_id)
        {
            using (var ctx = GetCtx())
                if (ctx.pkce_code_flow.FirstOrDefault(t => t.refresh_token == refresh_roken && t.project_id == project_id) == null) throw new ApplicationException("invalid_access_token");
            return null;
        }
        public ArkJwt Validate(PkceCodeFlow flow)
        {
            try
            {
                var prj = ValidateProject(flow);
                ValidateClient(flow, prj);
                return new ArkJwt() { id_token = flow.id_token, expires_in = flow.expires_at.ToString() };
            }
            catch (Exception ex)
            {
                return new ArkJwt() { error = new ArkError() { message = ex.Message } };
            }
        }
        ArkDataContext GetCtx()
        {
            //if (!_setting.is_server) throw new ApplicationException($"invalid_data_access_to_server_token_service");
            //if (string.IsNullOrEmpty(_setting.oidc_server.connection_string)) throw new ApplicationException($"invalid_config_connection_string");
            var optbld = new Microsoft.EntityFrameworkCore.DbContextOptionsBuilder<ArkDataContext>();
            //optbld.UseNpgsql(_setting.oidc_server.connection_string);
            ArkDataContext ctx = new ArkDataContext(optbld.Options);
            ctx.ChangeTracker.AutoDetectChangesEnabled = false;
            ctx.ChangeTracker.QueryTrackingBehavior = QueryTrackingBehavior.NoTracking;
            return ctx;
        }
        ArkProject GetProject(string project_id)
        {
            project_id = (project_id ?? "").ToLower();
            using (var conctx = GetCtx())
            {
                var proj = conctx.oidc_project.ToList().Find(t => t.project_id == project_id);
                if (proj == null) throw new ApplicationException($"invalid_project_data_id: {project_id}");
                return proj;
            }
        }
        ArkProject ValidateProject(PkceCodeFlow flow)
        {
            if (flow == null) throw new ApplicationException("invalid_parameters");
            return GetProject(flow.project_id);
        }
        ArkApp GetClient(string project_id, string client_id)
        {
            var proj = GetProject(project_id);
            return GetClient(proj, client_id);
        }
        ArkApp GetClient(ArkProject proj, string client_id)
        {
            //client_id = (client_id ?? "").ToLower();
            //if (proj.micro_services == null || proj.micro_services.Count == 0) throw new ApplicationException($"app association error in project: {proj.project_id}");
            //var app = proj.micro_services.Find(t => t.client_id == client_id);
            //if (app == null) throw new ApplicationException("invalid_app_assocation_client_id");
            //return app;
            return null;
        }
        ArkProject ValidateClient(PkceCodeFlow flow, ArkProject proj)
        {
            var app = GetClient(proj, flow.client_id);
            ValidateRedirctUri(flow, app);
            ValidateAudience(flow, proj);
            return proj;
        }
        void ValidateRedirctUri(PkceCodeFlow flow, ArkApp client)
        {
            if (client == null) throw new ApplicationException("invalid_app_assocation_client_id_sent");
            if (client.redirect_uri != flow.redirect_uri) throw new ApplicationException($"invalid_client_redirect_uri: {client.redirect_uri} <> {flow.redirect_uri}");
        }
        void ValidateAudience(PkceCodeFlow flow, ArkProject proj)
        {
            if (string.IsNullOrEmpty(proj.audience)) throw new ApplicationException($"invalid_audience_setting_client: {proj.project_id}");
            if (proj.audience != flow.audience) throw new ApplicationException($"invalid_audience_request : {flow.audience}");
        }
        public void InsertPkceFlow(PkceCodeFlow flow)
        {
            using (var ctx = GetCtx())
            {
                ctx.pkce_code_flow.Add(flow);
                ctx.SaveChanges();
            }
        }
        public void BuildAsymmetricToken_IdToken(User user, PkceCodeFlow flow)
        {
            var proj = GetProject(user.context.active_project);
            if (string.IsNullOrEmpty(proj.rsa_private_key)) throw new ApplicationException("client_cert_missing.");
            //TO DO: Immi -> comment this client logic validatio & move expiration to service accont level
            var client = proj.apps.Find(t => t.client_id == flow.client_id);
            if (client == null) throw new ApplicationException("invalid_key_client_missing");
            client.expiration_mins = client.expiration_mins <= 0 ? 30 : client.expiration_mins;
            //flow.id_token = BuildToken(flow, proj.issuer, client.expiration_mins, proj.rsa_private_key, user.GetIdClaims());
            //flow.access_token = BuildToken(flow, proj.issuer, client.expiration_mins, proj.rsa_private_key, user.GetAccessClaims());
            flow.refresh_token = flow.code;
        }
        string BuildToken(PkceCodeFlow flow, string issuer, int exiration_mins,
            string rsa_key, Claim[] claims)
        {
            //var privateKey = rsa_key.ToByteArray();
            var privateKey = new byte[] { };
            using RSA rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(privateKey, out _);
            var signCreds = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
            var now = DateTime.UtcNow;
            var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();
            flow.expires_at = now.AddMinutes(exiration_mins);
            var jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                audience: flow.audience,
                issuer: issuer,
                claims: claims,
                notBefore: now,
                expires: flow.expires_at,
                signingCredentials: signCreds
            );
            jwt.Header.Add("kid", flow.project_id);
            string token = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(jwt);
            return token;
        }
        public void BuildAsymmetric_AccessToken(ServiceAccount acct, PkceCodeFlow flow)
        {
            var proj = GetProject(acct.project_id);
            if (string.IsNullOrEmpty(proj.rsa_private_key)) throw new ApplicationException("client_cert_missing.");
            using (var ctx = GetCtx())
            {
                var acc = ctx.service_accounts.Where(r => r.client_id == acct.client_id && r.client_secret == acct.client_secret).FirstOrDefault();
                if (acc == null || string.IsNullOrEmpty(acc.account_id)) throw new ApplicationException("invalid client_id or secret provided.");
                //flow.access_token = BuildToken(flow, proj.issuer, acct.expiration_mins <= 0 ? 30 : acct.expiration_mins, proj.rsa_private_key,  acct.GetAccessClaims());
                flow.access_token = BuildToken(flow, proj.issuer, acct.expiration_mins <= 0 ? 30 : acct.expiration_mins, proj.rsa_private_key, null);
                flow.refresh_token = flow.code;
            }
        }
        public string BuildSymmetricToken(ServiceAccount acct, PkceCodeFlow flow)
        {
            var proj = GetProject(acct.project_id);
            var client = proj.apps.Find(t => t.client_id == flow.client_id);
            if (client == null) throw new ApplicationException("client_account_missing");
            client.expiration_mins = client.expiration_mins <= 0 ? 187200 : client.expiration_mins;
            var securityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(acct.client_secret));
            var now = DateTime.UtcNow;
            var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();
            flow.expires_at = now.AddMinutes(client.expiration_mins);
            var jwt = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                audience: proj.audience, // same as flow.audience
                issuer: proj.issuer,
                claims: new Claim[] {
                    new Claim(JwtRegisteredClaimNames.Iat, unixTimeSeconds.ToString(), ClaimValueTypes.Integer64),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.NameId, acct.account_id),
                    //new Claim("plants", Newtonsoft.Json.JsonConvert.SerializeObject(acct.plants)),
                    new Claim("active_service", acct.client_id),
                    new Claim("active_project", acct.project_id)
                },
                notBefore: now,
                expires: flow.expires_at,
                signingCredentials: new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature)
            );
            jwt.Header.Add("kid", proj.project_id);
            string token = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(jwt);
            flow.access_token = token;
            return token;
        }
        public async Task<dynamic> GetDiscovery_v2(string project_id, string client_id)
        {
            var proj = GetProject(project_id);
            var client = proj.apps.Find(t => t.client_id == (client_id ?? "").ToLower());
            if (client == null || client.grant_type == "code")
            {
                return new
                {
                    issuer = proj.issuer,
                    authorize_endpoint = string.Format(proj.authorize_endpoint, project_id),
                    token_endpoint = string.Format(proj.token_endpoint, project_id),
                    userinfo_endpoint = string.Format(proj.issuer, project_id),
                    introspection_endpoint = string.Format(proj.introspection_endpoint, project_id),
                    jwk_uri = string.Format(proj.jwk_uri, project_id),
                    scopes = new List<string>()
                    {
                        "name_id",
                        "iss",
                        "aud",
                        "exp",
                        "iat",
                        "jti",
                        "email",
                        "name",
                        "role",
                    },
                    response_types_supported = new List<string>()
                    {
                        "code",
                        "id_token",
                        "token id_token"
                    },
                    token_endpoint_auth_methods_supported = new List<string>()
                    {
                        "client_secret_basic"
                    }
                };
            }
            else if (client.grant_type == "client_credentials")
            {
                return new
                {
                    issuer = proj.issuer,
                    authorize_endpoint = string.Format(proj.authorize_endpoint, project_id),
                    token_endpoint = string.Format(proj.token_endpoint, project_id),
                    userinfo_endpoint = string.Format(proj.issuer, project_id),
                    introspection_endpoint = string.Format(proj.introspection_endpoint, project_id),
                    jwks_uri = string.Format(proj.jwk_uri, project_id),
                    scopes_supported = new List<string>()
                    {
                        "base",
                        "id_token",
                        "view_mode",
                        "auth_admin"
                    },
                    claims_supported = new List<string>()
                    {
                        "name_id",
                        "iss",
                        "aud",
                        "exp",
                        "iat",
                        "jti",
                        "email",
                        "name",
                        "role",
                        "plants",
                        "services",
                        "plant_roles",
                        "scheduler-unschedule",
                        "scheduler-throughput",
                        "scheduler-qcshot",
                        "scheduler-changeovertype",
                        "scheduler-mixingarea",
                        "scheduler-scheduledate",
                        "scheduler-publish",
                        "scheduler-draganddrop",
                        "scheduler-frozenzone",
                        "scheduler-pomanager-poselect",
                        "scheduler-pomanager-fgdate",
                        "scheduler-pomanager-rmdate",
                        "scheduler-pomanager-scantoselect",
                        "scheduler-pomanager-runengine",
                        "scheduler-pomanager-tablesorting",
                        "authconsole-manageusers",
                        "authconsole-manageserviceaccounts",
                        "authconsole-manageprojects",
                        "authconsole-manageservices"
                    },
                    response_types_supported = new List<string>()
                    {
                        "code",
                        "id_token",
                        "token id_token"
                    },
                    token_endpoint_auth_methods_supported = new List<string>()
                    {
                        "client_secret_basic"
                    },
                    code_challenge_methods_supported = new List<string>()
                    {
                        "s256"
                    },
                    http_logout_supported = false,
                };
            }
            else
            {
                return await Task.FromResult(new ArkError() { message = "unsupported grant_type requested." });
            }
        }
        public async Task<dynamic> GetDiscovery(string project_id, string client_id)
        {
            var proj = GetProject(project_id);
            var client = GetClient(proj, client_id);
            if (client.grant_type == "code")
            {
                return new
                {
                    issuer = proj.issuer,
                    authorize_endpoint = string.Format(proj.authorize_endpoint, project_id),
                    token_endpoint = string.Format(proj.token_endpoint, project_id),
                    userinfo_endpoint = string.Format(proj.issuer, project_id),
                    introspection_endpoint = string.Format(proj.introspection_endpoint, project_id),
                    jwk_uri = string.Format(proj.jwk_uri, project_id),
                    scopes = new List<string>()
                    {
                        "email",
                        "plant",
                        "role",
                        "first_name",
                        "last_name"
                    },
                    response_types_supported = new List<string>()
                    {
                        "code",
                        "id_token",
                        "token id_token"
                    },
                    token_endpoint_auth_methods_supported = new List<string>()
                    {
                        "client_secret_basic"
                    }
                };
            }
            else if (client.grant_type == "client_credentials")
            {
                return new
                {
                    issuer = proj.issuer,
                    authorize_endpoint = string.Format(proj.authorize_endpoint, project_id),
                    token_endpoint = string.Format(proj.token_endpoint, project_id),
                    userinfo_endpoint = string.Format(proj.issuer, project_id),
                    introspection_endpoint = string.Format(proj.introspection_endpoint, project_id),
                    jwk_uri = string.Format(proj.jwk_uri, project_id),
                    scopes = new List<string>()
                    {
                        "email",
                        "plant",
                        "role",
                        "first_name",
                        "last_name"
                    },
                    response_types_supported = new List<string>()
                    {
                        "code",
                        "id_token",
                        "token id_token"
                    },
                    token_endpoint_auth_methods_supported = new List<string>()
                    {
                        "client_secret_basic"
                    }
                };
            }
            else
            {
                return await Task.FromResult(new ArkError() { message = "unsupported grant_type requested." });
            }
        }
        public async Task<dynamic> GetPublicKey(string project_id)
        {
            var keys = new List<dynamic>();
            using (var ctx = GetCtx())
            {
                ctx.oidc_project.ToList().ForEach(t =>
                {
                    using RSA rsa = RSA.Create();
                    //rsa.ImportSubjectPublicKeyInfo(t.rsa_public_key.ToByteArray(), out _);
                    var rsakey = new RsaSecurityKey(rsa);
                    rsakey.KeyId = t.project_id;
                    var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(rsakey);
                    keys.Add(new
                    {
                        alg = jwk.Alg ?? "RS256",
                        e = jwk.E,
                        n = jwk.N,
                        kid = jwk.Kid,
                        kty = jwk.Kty,
                        use = jwk.Use ?? "sig"
                    });
                });
            }
            return await Task.FromResult(new { keys });
        }

        public async Task<List<string>> GetCredsAccesToken(string project_id, string client_id)// get generated access_token for client_creds services
        {
            project_id = (project_id ?? "").ToLower();
            client_id = (client_id ?? "").ToLower();
            using (var ctx = GetCtx())
            {
                var lst = ctx.service_accounts.Where(t => t.project_id == project_id && t.client_id == client_id);
                return await Task.FromResult(lst.Select(t => t.access_token).ToList());
            }
        }
        public List<ArkScope> GetUserClaims(User user)
        {
            using (var ctx = GetCtx())
            {
                var res = ctx.users.Find(user.email);
                if (res == null) throw new ApplicationException("Invalid token sent.");
                var user_scopes = (res.scopes ?? new List<ArkScope>()).Where(t => !string.IsNullOrEmpty(t.scope_id)).Select(t => t.scope_id.ToLower()).ToList();
                var role_scopes = ctx.client_role_scopes.Where(tt => tt.role == user.context.active_role).Select(t => t).ToList();
                var role_sids = role_scopes.SelectMany(t => t.scopes).Select(t => t.scope_id);
                user_scopes.AddRange(role_sids);
                var scopes = ctx.oidc_scopes
                        .Where(t => !string.IsNullOrEmpty(t.scope_id) && user_scopes.Contains(t.scope_id.ToLower()))
                        //.Include(m => m.claims) // nested error
                        .Select(t => t).ToList();
                return scopes;
            }
        }
    }
}
