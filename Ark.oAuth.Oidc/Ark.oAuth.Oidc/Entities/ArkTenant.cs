using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.ComponentModel.DataAnnotations.Schema;
using System.ComponentModel.DataAnnotations;

namespace Ark.oAuth.Oidc.Entities
{
    public class ArkTenant
    {
        string _tenant_id;
        [Key]
        public string tenant_id { get => (_tenant_id ?? "").ToLower(); set => _tenant_id = value; } // tenant mapping (tenant_id)
        [Column(TypeName = "jsonb")]
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
    public class CertKeys
    {
        public string rsa_public_key { get; set; } //client config - for kid based verification
    }
}
