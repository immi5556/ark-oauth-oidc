using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Mysqlx.Expr;
using MySqlX.XDevAPI;

namespace Ark.oAuth.Oidc
{
    public class DataAccess
    {
        ArkDataContext _ctx;
        ArkUtil _util;
        public DataAccess(ArkDataContext ctx, ArkUtil util)
        {
            _ctx = ctx;
            _util = util;
        }
        public ArkDataContext GetCtx()
        {
            return _ctx; 
        }
        public async Task<ArkTenant?> GetTenant(string tenant_id)
        {
            return await _ctx.tenants.FirstOrDefaultAsync(t => t.tenant_id.ToLower().Trim() == (tenant_id ?? "").ToLower().Trim());
        }
        public async Task<List<ArkTenant>> GetTenants()
        {
            return await _ctx.tenants.ToListAsync();
        }
        public async Task<ArkClient?> GetClient(string tenant_id, string client_id) //cmposite key
        {
            return await _ctx.clients.FirstOrDefaultAsync(t => t.tenant_id.ToLower().Trim() == (tenant_id ?? "").ToLower().Trim() &&  t.client_id.ToLower().Trim() == (client_id ?? "").ToLower().Trim());
        }
        public async Task<ArkTenant> UpsertTenant(ArkTenant tenant)
        {
            if (string.IsNullOrWhiteSpace(tenant?.tenant_id)) throw new ApplicationException("tenant_id is required.");
            tenant.tenant_id = tenant.tenant_id.Trim();
            // name/display/issuer/audience are NOT NULL columns, and the console adds a blank row
            // for the operator to fill in — so anything left empty is defaulted here rather than
            // failing the insert with a constraint violation the operator cannot act on.
            var root = $"{_util.ServerConfig.BaseUrl}{(string.IsNullOrWhiteSpace(_util.ServerConfig.BasePath) ? "" : $"/{_util.ServerConfig.BasePath.Trim('/')}")}";
            tenant.name = string.IsNullOrWhiteSpace(tenant.name) ? tenant.tenant_id : tenant.name.Trim();
            tenant.display = string.IsNullOrWhiteSpace(tenant.display) ? tenant.name : tenant.display.Trim();
            tenant.issuer = string.IsNullOrWhiteSpace(tenant.issuer) ? $"{root}/ark/oauth/v1/iss" : tenant.issuer.Trim();
            tenant.audience = string.IsNullOrWhiteSpace(tenant.audience) ? $"{root}/ark/oauth/v1/aud" : tenant.audience.Trim();
            if (tenant.expire_mins <= 0) tenant.expire_mins = 480;

            var tt = await _ctx.tenants.FirstOrDefaultAsync(t => t.tenant_id == tenant.tenant_id);

            // rsa_public/rsa_private are NOT NULL. A caller that omits them means "leave the key
            // alone" — never "rotate it", which would invalidate every token and JWKS entry the
            // tenant has already issued — so an existing pair is carried over and a new tenant
            // gets a freshly minted one.
            if (string.IsNullOrEmpty(tenant.rsa_private) || string.IsNullOrEmpty(tenant.rsa_public))
            {
                if (tt != null && !string.IsNullOrEmpty(tt.rsa_private))
                {
                    tenant.rsa_private = tt.rsa_private;
                    tenant.rsa_public = tt.rsa_public;
                }
                else
                {
                    var (pub, priv) = Protocol.ArkCrypto.GenerateRsaKeyPair();
                    tenant.rsa_private = priv;
                    tenant.rsa_public = pub;
                }
            }

            if (tt == null)
            {
                tenant.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.tenants.Add(tenant);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                tenant.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.tenants.Update(tenant);
            }
            await _ctx.SaveChangesAsync();
            return tenant;
        }
        public async Task<List<ArkClient>> GetClients()
        {
            return await _ctx.clients.ToListAsync();
        }
        public async Task<ArkClient> UpsertClient(ArkClient client)
        {
            if (string.IsNullOrEmpty((client?.id ?? "").Trim())) client.id = null;
            await NormaliseClient(client);
            var tt = (await _ctx.clients.FirstOrDefaultAsync(t => t.id.ToLower() == (client.id ?? "").ToLower())) ?? (await _ctx.clients.FirstOrDefaultAsync(t => t.tenant_id.ToLower() == (client.tenant_id ?? "").ToLower() && t.client_id.ToLower() == (client.client_id ?? "").ToLower()));
            if (tt == null)
            {
                client.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.clients.Add(client);
            }
            else
            {
                client.id = tt.id;
                _ctx.ChangeTracker.Clear();
                client.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.clients.Update(client);
            }
            await _ctx.SaveChangesAsync();
            return client;
        }
        /// <summary>
        /// Fills in the v1 single-valued columns a client row still requires from the RFC 7591
        /// metadata the console actually edits.
        ///
        /// name, display, domain, redirect_url and logout_url are NOT NULL, but the client drawer
        /// posts null for every text box left blank — so registering a client the standard way
        /// (client_name + redirect_uris, no legacy fields) failed on
        /// "NOT NULL constraint failed: clients.name" with nothing on screen to say which box to
        /// fill. Deriving them keeps both styles of payload valid and keeps the two
        /// representations consistent, which is what EffectiveRedirectUris et al. assume.
        /// </summary>
        async Task NormaliseClient(ArkClient client)
        {
            if (string.IsNullOrWhiteSpace(client?.client_id)) throw new ApplicationException("client_id is required.");
            if (string.IsNullOrWhiteSpace(client.tenant_id)) throw new ApplicationException("tenant_id is required.");
            client.client_id = client.client_id.Trim();
            client.tenant_id = client.tenant_id.Trim();

            // A missing tenant otherwise surfaces as a bare "FOREIGN KEY constraint failed".
            if (await GetTenant(client.tenant_id) == null)
                throw new ApplicationException($"unknown tenant '{client.tenant_id}' - create the tenant first.");

            var label = new[] { client.client_name, client.display, client.name, client.client_id }
                .FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? client.client_id;
            client.client_name = string.IsNullOrWhiteSpace(client.client_name) ? label : client.client_name;
            client.name = string.IsNullOrWhiteSpace(client.name) ? label : client.name;
            client.display = string.IsNullOrWhiteSpace(client.display) ? label : client.display;

            // The plural forms win when populated, so fall back to the first of each list.
            client.redirect_url = string.IsNullOrWhiteSpace(client.redirect_url)
                ? (client.redirect_uris.FirstOrDefault(u => !string.IsNullOrWhiteSpace(u)) ?? "")
                : client.redirect_url.Trim();
            client.logout_url = string.IsNullOrWhiteSpace(client.logout_url)
                ? (client.post_logout_redirect_uris.FirstOrDefault(u => !string.IsNullOrWhiteSpace(u)) ?? "")
                : client.logout_url.Trim();

            if (string.IsNullOrWhiteSpace(client.domain))
            {
                var source = new[] { client.redirect_url, client.logout_url, client.client_uri, _util.ServerConfig.BaseUrl }
                    .FirstOrDefault(u => !string.IsNullOrWhiteSpace(u));
                client.domain = Uri.TryCreate(source, UriKind.Absolute, out var uri) ? uri.Host : "";
            }

            if (client.expire_mins <= 0) client.expire_mins = 480;
        }
        public async Task<ArkClient> DeleteClient(ArkClient client)
        {
            if (string.IsNullOrEmpty(client.id)) return client; //added on the UI, delete before even saving
            var tt = await _ctx.clients.FirstOrDefaultAsync(t => t.id.ToLower() == client.id.ToLower());
            if (tt == null)
            {
                
            }
            else
            {
                _ctx.clients.Remove(tt);
            }
            await _ctx.SaveChangesAsync();
            return client;
        }
        public async Task<List<ArkClaim>> GetClaims()
        {
            return await _ctx.claims.ToListAsync();
        }
        public async Task<ArkClaim?> GetClaim(string key)
        {
            return await _ctx.claims.FirstOrDefaultAsync(t => t.key.ToLower().Trim() == key.ToLower().Trim());
        }
        public async Task<ArkClaim> UpsertClaim(ArkClaim claim)
        {
            var tt = await _ctx.claims.FirstOrDefaultAsync(t => t.key == claim.key);
            if (tt == null)
            {
                _ctx.claims.Add(claim);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                _ctx.claims.Update(claim);
            }
            await _ctx.SaveChangesAsync();
            return claim;
        }
        public async Task<ArkClaim> DeleteClaim(ArkClaim claim)
        {
            var tt = await _ctx.claims.FirstOrDefaultAsync(t => t.key == claim.key);
            if (tt != null)
            {
                _ctx.claims.Remove(tt);
                await _ctx.SaveChangesAsync();
            }
            return claim;
        }
        public async Task<List<ArkScope>> GetScopes()
        {
            return await _ctx.scopes.ToListAsync();
        }
        public async Task<ArkScope> UpsertScope(ArkScope scope)
        {
            if (string.IsNullOrWhiteSpace(scope?.name)) throw new ApplicationException("empty scope name");
            scope.name = scope.name.Trim();
            var tt = await _ctx.scopes.FirstOrDefaultAsync(t => t.name == scope.name);
            if (tt == null)
            {
                _ctx.scopes.Add(scope);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                _ctx.scopes.Update(scope);
            }
            await _ctx.SaveChangesAsync();
            return scope;
        }
        public async Task<ArkScope> DeleteScope(ArkScope scope)
        {
            var tt = await _ctx.scopes.FirstOrDefaultAsync(t => t.name == (scope.name ?? "").Trim());
            if (tt == null) return scope; // added on the UI, deleted before ever being saved
            // Removing a protocol scope (openid, offline_access) breaks the authorization and
            // token endpoints for every client on the deployment, so it is refused here rather
            // than left as a one-click way to take the server down.
            if (tt.is_protocol) throw new ApplicationException($"'{tt.name}' is a protocol scope and cannot be deleted.");
            _ctx.scopes.Remove(tt);
            await _ctx.SaveChangesAsync();
            return scope;
        }
        public async Task<List<ArkUser>> GetUsers()
        {
            return await _ctx.users.ToListAsync();
        }
        public async Task<ArkUser> GetUser(string email)
        {
            return await _ctx.users.FirstOrDefaultAsync(t => t.email == email);
        }
        public async Task<dynamic> GetUserInfo(string email, string tenant_id, string client_id)
        {
            var cc = await GetClient(tenant_id, client_id);
            var usr = await _ctx.users.FirstOrDefaultAsync(t => t.email.ToLower() == (email ?? "").ToLower());
            var clms = await GetUsersClientClaims(email, tenant_id);
            return new
            {
                claims = clms.Find(t => t.client_id?.ToLower() == cc.id.ToLower())?.claims,
                client_guid = cc.id,
                client_id = cc.client_id,
                client_name = cc.name,
                user = new
                {
                    usr.email, usr.name, usr.type
                }
            };
        }
        public async Task<List<ArkUserClientClaim>> GetUsersClientClaims(string email, string tenatn_id)
        {
            return await _ctx.user_client_claims.Where(t1 =>
                    (email ?? "").ToLower() == (t1.email ?? "").ToLower() && (tenatn_id ?? "").ToLower() == (t1.tenant_id ?? "").ToLower()).ToListAsync();
        }
        public async Task<ArkUserClientClaim> UpsertUsersClientClaims(ArkUserClientClaim us_cl)
        {
            if (string.IsNullOrEmpty((us_cl?.id ?? "").Trim())) us_cl.id = null;
            var tt = (await _ctx.user_client_claims.FirstOrDefaultAsync(t => (t.id ?? "").ToLower().Trim() == (us_cl.id ?? "").ToLower().Trim())) 
                ?? (await _ctx.user_client_claims.FirstOrDefaultAsync(t => 
                                (t.tenant_id ?? "").ToLower().Trim() == (us_cl.tenant_id ?? "").ToLower().Trim() 
                            &&  (t.client_id ?? "").ToLower().Trim() == (us_cl.client_id ?? "").ToLower().Trim() 
                            &&  (t.email ?? "").ToLower().Trim() == (us_cl.email ?? "").ToLower().Trim()));
            if (tt == null)
            {
                us_cl.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.user_client_claims.Add(us_cl);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                us_cl.id = tt.id;
                us_cl.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.user_client_claims.Update(us_cl);
            }
            await _ctx.SaveChangesAsync();
            return us_cl;
        }
        public async Task<ArkUserClientClaim> DeleteUsersClientClaims(ArkUserClientClaim us_cl)
        {
            if (string.IsNullOrEmpty(us_cl?.id)) return us_cl; //added on the UI, delete before even saving
            var tt = await _ctx.user_client_claims.FirstOrDefaultAsync(t => t.id.ToLower() == us_cl.id.ToLower());
            if (tt == null)
            {

            }
            else
            {
                _ctx.user_client_claims.Remove(tt);
            }
            await _ctx.SaveChangesAsync();
            return us_cl;
        }
        /// <summary>
        /// A login identifier is either an email address or a plain username.
        ///
        /// The sign-in screen has always posted a free-text "Username", and the bootstrap seed
        /// creates `admin` and `service_account_{tenant}` — neither of which is an email. Only
        /// account *creation* insisted on an address, so those accounts could not be reproduced
        /// through the console. Usernames are kept to characters that survive a URL path segment
        /// unescaped, since they travel in the claims-mapping routes.
        /// </summary>
        static bool IsValidLoginId(string id) =>
            ark.net.util.EmailUtil.IsValidFormat(id) ||
            System.Text.RegularExpressions.Regex.IsMatch(id, @"^[a-z0-9][a-z0-9._-]{1,63}$");

        public async Task<ArkUser> UpsertUser(ArkUser user)
        {
            if (string.IsNullOrEmpty(user?.email)) throw new ApplicationException("a username or email is required.");
            user.email = user.email.ToLower().Trim();
            if (!IsValidLoginId(user.email))
                throw new ApplicationException("invalid username - use an email address, or 2-64 characters of letters, digits, dot, dash or underscore.");
            if (string.IsNullOrWhiteSpace(user.name)) user.name = user.email;
            if (string.IsNullOrWhiteSpace(user.type)) user.type = "user";
            var tt = await _ctx.users.FirstOrDefaultAsync(t => t.email == user.email);
            if (tt == null)
            {
                user.hash_pw = string.IsNullOrEmpty(user.hash_pw) ? _util.HashPasswordPBKDF2(_util.ServerConfig.DefaultPw) : user.hash_pw; //default pw
                user.ref_uid = Guid.NewGuid().ToString();
                user.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");

                // Only an address can be sent an activation link. A username account has no
                // mailbox, so it starts on the configured default password instead of being
                // parked in reset_mode waiting for a mail that can never arrive.
                if (ark.net.util.EmailUtil.IsValidFormat(user.email))
                {
                    user.reset_mode = true;
                    // Creating the account is the operation being asked for; a template that
                    // cannot be read or an SMTP host that is down must not roll it back. The
                    // account is left in reset_mode and `emailed` false, which is what
                    // "Reset password" in the console retries.
                    try
                    {
                        string email_content = await _util.GetActivationEmail(_util.ServerConfig.TenantId, user.ref_uid);
                        user.emailed = await _util.SendMail(user.email, email_content, $"{_util.ServerConfig.EmailConfig?.subject} Activation Link", this);
                    }
                    catch (Exception ex)
                    {
                        LogError(ex, "user_activation_email", user.email, "activation email could not be built or sent; account still created");
                        user.emailed = false;
                    }
                }
                else
                {
                    user.reset_mode = false;
                    user.emailed = false;
                }
                _ctx.users.Add(user);
            }
            else
            {
                _ctx.ChangeTracker.Clear();
                user.id = tt.id;
                user.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.users.Update(user);
            }
            await _ctx.SaveChangesAsync();
            return user;
        }
        public async Task<ArkUser> UserResetPw(ArkUser user)
        {
            var login_id = (user?.email ?? "").ToLower().Trim();
            var uu = await _ctx.users.FirstOrDefaultAsync(t => t.email == login_id)
                ?? throw new ApplicationException($"unknown user '{login_id}'.");
            // A reset link can only be delivered to an address; a username account has no mailbox.
            if (!ark.net.util.EmailUtil.IsValidFormat(uu.email))
                throw new ApplicationException($"'{uu.email}' is a username, not an email address - it has no mailbox to send a reset link to. Set a new password directly instead.");

            var tnt = await _ctx.tenants.FirstOrDefaultAsync();
            _ctx.ChangeTracker.Clear();
            uu.reset_mode = true;
            uu.ref_uid = Guid.NewGuid().ToString();
            string email_content = await _util.GetActivationEmail(tnt.tenant_id, uu.ref_uid);
            uu.emailed = await _util.SendMail(uu.email, email_content, $"{_util.ServerConfig.EmailConfig?.subject} Reset Password", this);
            uu.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
            _ctx.users.Update(uu);
            await _ctx.SaveChangesAsync();
            return uu;
        }
        public async Task<bool> UpdatePassword(string uq_refid, string pw)
        {
            var uu = await _ctx.users.FirstOrDefaultAsync(t => t.ref_uid == uq_refid);
            if (uu == null) throw new ApplicationException("invalid reference id, pls contact support.");
            else if (uu.reset_mode.HasValue && uu.reset_mode.Value)
            {
                _ctx.ChangeTracker.Clear();
                uu.reset_mode = false;
                uu.hash_pw = _util.HashPasswordPBKDF2(pw);
                uu.at = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss");
                _ctx.users.Update(uu);
                await _ctx.SaveChangesAsync();
            }
            else throw new ApplicationException("reset request expired, pls contact support.");
            return true;
        }
        public async Task<ArkUser> ValidateUserCreds(string un, string pw, string client, string tenant_id)
        {
            var usr = _ctx.users.FirstOrDefault(t => t.email.ToLower() == un.ToLower());
            if (usr == null) throw new ApplicationException("invalid creds");
            var clnt = _ctx.clients.FirstOrDefault(t => (t.client_id ?? "").ToLower() == (client ?? "").ToLower() && (t.tenant_id ?? "").ToLower() == (tenant_id ?? "").ToLower());
            if (clnt == null) throw new ApplicationException("invalid creds client");
            var usr_cl_cl = _ctx.user_client_claims.FirstOrDefault(t => t.email == un && (t.client_id ?? "").ToLower() == (clnt.id ?? "").ToLower() && (t.tenant_id ?? "").ToLower() == (tenant_id ?? "").ToLower());
            if (usr_cl_cl == null) throw new ApplicationException("invalid creds client.");
            if (!_util.VerifyPasswordPBKDF2(pw, usr.hash_pw))
            {
                await UpdateStatus(un, retry: "increment");
                throw new ApplicationException("invalid creds.");
            }
            else
            {
                await UpdateStatus(un, retry: "reset");
            }
            return usr;
        }
        public async Task<PkceCodeFlow?> GetPkceCode(string code, bool invalidate = false)
        {
            var tt = await _ctx.pkce_code_flow.FirstOrDefaultAsync(t => t.code == code && !t.inactivate);
            if (invalidate)
            {
                tt.inactivate = true;
                _ctx.pkce_code_flow.Update(tt);
                await _ctx.SaveChangesAsync();
            }
            return tt;
        }
        public async Task UpsertPkceCode(string token, ArkTenant tenant, string code, string code_challenge, string code_challenge_method, string state, string scopes, string claims, DateTime expires_at, string redirect_uri, string response_type)
        {
            _ctx.pkce_code_flow.Add(new PkceCodeFlow()
            {
                access_token = token,
                audience = tenant.audience,
                client_id = tenant.tenant_id,
                code = code,
                code_challenge = code_challenge,
                code_challenge_method = code_challenge_method,
                state = state,
                refresh_token = Guid.NewGuid().ToString(),
                scopes = scopes,
                claims = claims,
                expires_at = expires_at,
                created_at = DateTime.UtcNow,
                redirect_uri = redirect_uri,
                response_type = response_type
            });
            await _ctx.SaveChangesAsync();
        }
        public async Task ExecuteRaw(string sql)
        {
            _ctx.Database.ExecuteSqlRaw(sql);
        }
        public async Task EnsureCreatedAsync()
        {
            await _ctx.Database.EnsureCreatedAsync();
        }
        public void Log(string? ref_key, string? ref_val, string? message, string? details, string? log_type = "trace")
        {
            try
            {
                if (!_util.IsTraceEnabled) return;
                _ctx.audit_trace.Add(new ArkAudit()
                {
                    ref_key = ref_key,
                    ref_val = ref_val,
                    log_type = log_type,
                    message = message,
                    details = details,
                    by = "ark_admin",
                    ip = "",
                    at = DateTime.UtcNow
                });
                _ctx.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
        public void LogError(Exception exp, string? ref_key, string? ref_val, string? message)
        {
            try
            {
                _ctx.audit_trace.Add(new ArkAudit()
                {
                    ref_key = ref_key,
                    ref_val = ref_val,
                    log_type = "error",
                    message = message,
                    details = exp.ToString(),
                    by = "ark_admin",
                    ip = "",
                    at = DateTime.UtcNow
                });
                _ctx.ChangeTracker.Clear();
                _ctx.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
        public async Task UpdateStatus(string email, string retry = "reset")
        {
            try
            {
                var tt = await _ctx.auth_status.FirstOrDefaultAsync(t => (t.email ?? "").ToLower().Trim() == (email ?? "").ToLower().Trim());
                var rtt = (tt?.retry_count ?? 0);
                var retry_cnt = retry == "reset" ? 0 : retry == "increment" ? ++rtt : 0;
                if (tt == null)
                    _ctx.auth_status.Add(new ArkAuthStatusTrace()
                    {
                        email = email,
                        retry_count = retry_cnt,
                        complex_policy = true,
                        ip = "IP",
                        at = DateTime.UtcNow
                    });
                else
                {
                    _ctx.ChangeTracker.Clear();
                    tt.retry_count = retry_cnt;
                    tt.at = DateTime.UtcNow;
                    _ctx.auth_status.Update(tt);
                }
                _ctx.SaveChanges();
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
    }
}
