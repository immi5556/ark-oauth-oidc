namespace Ark.Client.Web.Models
{
    /// <summary>
    /// What the home page needs to tell an operator whether this app is correctly registered.
    ///
    /// The values on the left are read from local configuration; the values on the right come
    /// from the provider's own discovery document. Registration problems are almost always a
    /// mismatch between the two — a redirect URI that was typed slightly differently, an
    /// Authority pointing at the wrong tenant — and printing both side by side turns a generic
    /// "invalid_client" into something you can act on.
    /// </summary>
    public class SetupModel
    {
        public string Authority { get; set; } = "";
        public string ClientId { get; set; } = "";
        public bool IsConfidential { get; set; }
        public List<string> Scopes { get; set; } = new();
        public string RoleClaimType { get; set; } = "role";

        /// <summary>The absolute redirect URI this app will send. Register it exactly.</summary>
        public string RedirectUri { get; set; } = "";
        public string PostLogoutRedirectUri { get; set; } = "";

        public bool DiscoveryOk { get; set; }
        public string? DiscoveryError { get; set; }
        public string DiscoveryUrl { get; set; } = "";
        public string? Issuer { get; set; }
        public string? AuthorizationEndpoint { get; set; }
        public string? TokenEndpoint { get; set; }
        public string? UserInfoEndpoint { get; set; }
        public string? EndSessionEndpoint { get; set; }
        public string? JwksUri { get; set; }
        public List<string> ScopesSupported { get; set; } = new();

        /// <summary>Set when the issuer in the discovery document is not the configured Authority.</summary>
        public bool IssuerMismatch => DiscoveryOk &&
            !string.Equals(Issuer?.TrimEnd('/'), Authority.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);

        /// <summary>Scopes this app asks for that the provider does not advertise.</summary>
        public List<string> UnsupportedScopes => DiscoveryOk && ScopesSupported.Count > 0
            ? Scopes.Where(s => !ScopesSupported.Contains(s, StringComparer.OrdinalIgnoreCase)).ToList()
            : new List<string>();

        public bool IsAuthenticated { get; set; }
        public string? SignedInAs { get; set; }

        /// <summary>Populated from ?auth_error= when a sign-in callback failed.</summary>
        public string? AuthError { get; set; }

        /// <summary>The tenant segment of the Authority, used to build admin console links.</summary>
        public string TenantId
        {
            get
            {
                var trimmed = Authority.TrimEnd('/');
                var slash = trimmed.LastIndexOf('/');
                return slash > 0 && slash < trimmed.Length - 1 ? trimmed[(slash + 1)..] : "";
            }
        }

        public string AdminConsoleUrl
        {
            get
            {
                var trimmed = Authority.TrimEnd('/');
                var slash = trimmed.LastIndexOf('/');
                return slash > 0 ? $"{trimmed[..slash]}/{TenantId}/admin" : trimmed + "/admin";
            }
        }

        public string IntegrationPageUrl => $"{Authority.TrimEnd('/')}/oauth2/integrate/{ClientId}";
    }

    public class ProfileModel
    {
        public string? Subject { get; set; }
        public string? Name { get; set; }
        public string? Email { get; set; }
        public List<string> Roles { get; set; } = new();
        public List<KeyValuePair<string, string>> Claims { get; set; } = new();

        public bool HasAccessToken { get; set; }
        public bool HasRefreshToken { get; set; }
        public bool HasIdToken { get; set; }
        public DateTimeOffset? AccessTokenExpiresAt { get; set; }
        public string? AccessTokenPayload { get; set; }
        public string? IdTokenPayload { get; set; }
        public string RequiredRole { get; set; } = "";
    }

    public class DownstreamModel
    {
        public string Endpoint { get; set; } = "";
        public int StatusCode { get; set; }
        public string? Body { get; set; }
        public string? Error { get; set; }
    }

    public class ErrorViewModel
    {
        public string? RequestId { get; set; }
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
    }
}
