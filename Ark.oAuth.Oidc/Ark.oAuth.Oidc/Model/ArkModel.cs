namespace Ark.oAuth.Oidc
{
    public class ArkSetting
    {
        public bool is_server { get; set; }
        public bool is_client { get { return oidc_client != null; } }
        public ArkProject oidc_client { get; set; }
    }
    public class ArkJwt
    {
        string _email = null;
        public string email
        {
            get
            {
                if (string.IsNullOrEmpty(_email) && !string.IsNullOrEmpty(id_token))
                {
                    var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
                    var decodedValue = handler.ReadJwtToken(id_token);
                    if (decodedValue != null) _email = decodedValue.Claims.First(tt => tt.Type == "email").Value;
                }
                return _email ?? "";
            }
            set
            {
                _email = value;
            }
        }
        public string code { get; set; }
        public string access_token { get; set; }
        public string expires_in { get; set; }
        public string refresh_token { get; set; }
        public string id_token { get; set; }
        public string project_id { get; set; }
        public ArkError error { get; set; }
    }
    public class ArkError
    {
        public string code { get; set; }
        public string message { get; set; }
        public List<ArkErr> errors { get; set; } = new List<ArkErr>();
    }
    public class ArkErr
    {
        public string message { get; set; }
        public string domain { get; set; }
        public string reason { get; set; }
    }
    public class ArkSession
    {
        public string session_id { get; set; }
        public string project_id { get; set; } //actually: environment or plnat based hosting - but spread already
        string _client_id;
        public string client_id { get => (_client_id ?? "").ToLower(); set => _client_id = value; }  // each micro services
        string _role;
        public string role { get => (_role ?? "").ToLower(); set => _role = (value ?? "").ToLower(); } // role at each micro service level
        string _plant;
        public string plant { get => (_plant ?? "").ToLower(); set => _plant = value; } // factory
        public string av_token { get; set; } // access token
        public string code { get; set; } // pkce code
        string _email;
        public string email { get => (_email ?? "").ToLower(); set => _email = value; }
        public string state { get; set; }
        public string code_challenge { get; set; }
        string _code_challenge_method;
        public string code_challenge_method { get => (_code_challenge_method ?? "").ToLower(); set => _code_challenge_method = value; }
        public ArkProject client_config { get; set; }
        public ArkError error { get; set; }
    }
}
