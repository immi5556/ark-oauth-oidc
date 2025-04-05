namespace Ark.oAuth.Oidc
{
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
    public class ArkAuthServerConfig
    {
        public string ClientId { get; set; }
        public string BasePath { get; set; }
    }
    public class ArkAuthContext
    {
        IHttpContextAccessor _http;
        public ArkAuthContext(IHttpContextAccessor http)
        {
            _http = http;
            ip = _http.HttpContext.Request.Cookies["ark_oauth_ip"] ?? "";
            user_id = _http.HttpContext.Request.Cookies["ark_oauth_email"] ?? "";
            var cid = (_http.HttpContext.Request.RouteValues["client_id"] ?? "").ToString().ToLower();
            client_id = string.IsNullOrEmpty(cid)
                ? (_http.HttpContext.Request.Query.ContainsKey("client_id") && _http.HttpContext.Request.Query["client_id"].Count > 0 ? (_http.HttpContext.Request.Query["client_id"][0] ?? "").ToString().ToLower() : "")
                : cid;
        }
        public string client_id { get; private set; }
        public string? user_id { get; private set; } //mob or email (opt 1: mob, opt 2: email)
        public string? ip { get; set; }
    }
}
