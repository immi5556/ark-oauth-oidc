using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace Ark.oAuth.Oidc
{
    public class ArkTenant
    {
        string _tenant_id;
        [Key]
        public string tenant_id { get => (_tenant_id ?? "").ToLower(); set => _tenant_id = value; } // tenant mapping (tenant_id)
        public string display { get; set; }
        public int seq { get; set; }
        public bool is_default { get; set; }
        public bool status { get; set; } = true;
    }
    public class ArkProject
    {
        string _project_id;
        [Key]
        public string project_id { get => (_project_id ?? "").ToLower(); set => _project_id = value; }
        public string tenant_id { get; set; }
        [ForeignKey("tenant_id")]
        public virtual ArkTenant tenant { get; set; }
        //[Column(TypeName = "jsonb")]
        [NotMapped]
        public List<ArkApp> apps { get; set; } // server side: list of redirect_uri allowed
        public int seq { get; set; }
        public string authorize_endpoint { get; set; } //client & server config
        public string token_endpoint { get; set; } //client & server config
        public string userinfo_endpoint { get; set; }
        public string introspection_endpoint { get; set; }
        public string jwk_uri { get; set; }
        public string rsa_private_key { get; set; }
        public string display { get; set; } //client & server config
        public string rsa_public_key { get; set; } //client & server config
        string _audience; //client & server config
        public string audience { get => (_audience ?? "").ToLower(); set => _audience = value; }
        public string issuer { get; set; } //client & server config
    }
    public class ArkApp
    {
        string _client_id;
        public string client_id { get => (_client_id ?? "").ToLower(); set => _client_id = value; } //micro services - uniquename (onboarding)
        string _redirect_uri;
        public string redirect_uri { get => (_redirect_uri ?? "").ToLower(); set => _redirect_uri = value; }
        string _base_url;
        public string base_url { get => (_base_url ?? "").ToLower(); set => _base_url = value; }
        string _grant_type;
        public string grant_type { get => (_grant_type ?? "").ToLower(); set => _grant_type = value; }
        string _tenant_id;
        public string tenant_id { get => (_tenant_id ?? "").ToLower(); set => _tenant_id = value; }
        public int expiration_mins { get; set; }
        public string client_secret { get; set; }
        public string display { get; set; }
        public bool is_debug { get; set; }
    }
    public class PkceCodeFlow
    {
        [Key]
        public string code { get; set; }
        string _project_id;
        public string project_id { get => (_project_id ?? "").ToLower(); set => _project_id = value; }
        string _client_id;
        public string client_id { get => (_client_id ?? "").ToLower(); set => _client_id = value; }
        public string client_secret { get; set; }
        string _redirect_uri;
        public string redirect_uri { get => (_redirect_uri ?? "").ToLower(); set => _redirect_uri = value; }
        string _scope;
        public string scope { get => (_scope ?? "").ToLower(); set => _scope = value; }
        string _audience;
        public string audience { get => (_audience ?? "").ToLower(); set => _audience = value; }
        string _response_type;
        public string response_type { get => (_response_type ?? "").ToLower(); set => _response_type = value; }
        public string code_challenge { get; set; }
        string _code_challenge_method;
        public string code_challenge_method { get => (_code_challenge_method ?? "").ToLower(); set => _code_challenge_method = value; }
        public string state { get; set; }
        public string id_token { get; set; }
        public bool inactivate { get; set; }
        public string access_token { get; set; }
        public string refresh_token { get; set; }
        public DateTime expires_at { get; set; }
        public DateTime created_at { get; set; } = DateTime.UtcNow;
    }
    public class ServiceAccount
    {
        [Key]
        public string account_id { get; set; }
        public string project_id { get; set; }
        [ForeignKey("project_id")]
        public virtual ArkProject project { get; set; }
        public string client_secret { get; set; }
        public int expiration_mins { get; set; } = 525600;
        public string access_token { get; set; }
        public string client_id { get; set; }
        [Column(TypeName = "jsonb")]
        //public List<UserPlant> plants { get; set; }
        //[Column(TypeName = "jsonb")]
        public List<ArkScope> scopes { get; set; }
        [Column(TypeName = "jsonb")]
        public List<ArkClaim> claims { get; set; }
        public bool is_active { get; set; } = true;
    }
    public class ArkClaim
    {
        [Key]
        public string claim_id { get; set; }
        public string description { get; set; }
        public string type { get; set; }
        public List<ArkScope> scopes { get; set; }
    }
    public class ArkScope
    {
        public string scope_id { get; set; }
        public string description { get; set; }
        public string claim_id { get; set; }
        [ForeignKey("claim_id")]
        public virtual ArkClaim claims { get; set; }
    }
    public class User
    {
        string _email;
        [Key]
        public string email { get { return (_email ?? "").ToLower(); } set { _email = (value ?? "").ToLower(); } }
        public string password { get; set; }
        public string full_name { get; set; }
        //[Column(TypeName = "jsonb")]
        //public List<UserPlant> plants { get; set; }
        //[Column(TypeName = "jsonb")]
        //[NotMapped]
        //public List<UserClient> clients { get; set; }
        //[Column(TypeName = "jsonb")]
        //public List<string> projects { get; set; }
        [Column(TypeName = "jsonb")]
        public List<ArkScope> scopes { get; set; }
        [Column(TypeName = "jsonb")]
        public List<ArkClaim> claims { get; set; }
        public bool is_active { get; set; } = true;
        [NotMapped]
        public UserContext context { get; set; }
    }
    public class UserContext
    {
        string _active_project;
        public string active_project { get { return (_active_project ?? "").ToLower(); } set { _active_project = value; } }
        string _active_plant;
        public string active_plant { get { return (_active_plant ?? "").ToLower(); } set { _active_plant = value; } }
        string _active_client;
        public string active_client { get { return (_active_client ?? "").ToLower(); } set { _active_client = value; } }
        string _active_role;
        public string active_role { get { return (_active_role ?? "").ToLower(); } set { _active_role = value; } }
    }
    //public class UserClient
    //{
    //    string _email;
    //    public string email { get { return (_email ?? "").ToLower(); } set { _email = (value ?? "").ToLower(); } }
    //    string _client_id;
    //    public string client_id { get => (_client_id ?? "").ToLower(); set => _client_id = (value ?? "").ToLower(); }
    //    string _role;
    //    public string role { get => (_role ?? "").ToLower(); set => _role = (value ?? "").ToLower(); }
    //    public bool is_default { get; set; }
    //}
    public class UserRequest
    {
        string _email;
        [Key]
        public string email { get { return (_email ?? "").ToLower(); } set { _email = (value ?? "").ToLower(); } }
        public string password { get; set; }
        public string full_name { get; set; }
        public string user_message { get; set; }
        public string approver_message { get; set; }
        public string validation_id { get; set; }
        public string status { get; set; } //Initiated, ReInitiated, Verified, PwdGenerated, Approved/Rejected 
        //[Column(TypeName = "jsonb")]
        //public List<UserPlant> plants { get; set; }
        //[Column(TypeName = "jsonb")]
        //public List<UserClient> clients { get; set; }
        //[Column(TypeName = "jsonb")]
        //public List<string> projects { get; set; }
        [Column(TypeName = "jsonb")]
        public List<ArkScope> scopes { get; set; }
        [Column(TypeName = "jsonb")]
        public List<ArkClaim> claims { get; set; }
        public DateTime requested_at { get; set; } = DateTime.UtcNow;
        public DateTime? verified_at { get; set; }
        public DateTime? acted_at { get; set; }
        public string acted_by { get; set; }
        public string activate_url { get; set; }
        public bool is_active { get; set; } = true;
        [NotMapped]
        public UserContext context { get; set; }
    }
    public class ClientRoleScope
    {
        string _client;
        public string client { get => (_client ?? "").ToLower(); set => _client = (value ?? "").ToLower(); }
        string _role;
        public string role { get => (_role ?? "").ToLower(); set => _role = (value ?? "").ToLower(); }
        [Column(TypeName = "jsonb")]
        public List<ArkScope> scopes { get; set; }
        [Column(TypeName = "jsonb")]
        public List<ArkClaim> claims { get; set; }
    }
    public class CertKeys
    {
        public string rsa_public_key { get; set; } //client config - for kid based verification
    }
}
