using Ark.oAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc;

namespace Ark.Client.Web.Controllers
{
    /// <summary>
    /// Sign-in and sign-out.
    ///
    /// Three lines of real work, because the protocol is handled by the OpenID Connect handler
    /// that <c>AddArkOidcClient</c> configured. There is no authorization URL to build here, no
    /// PKCE verifier to store, no <c>state</c> to remember and no code to exchange — issuing a
    /// challenge is enough.
    /// </summary>
    public class AccountController : Controller
    {
        /// <summary>
        /// Starts an interactive sign-in.
        ///
        /// Hitting an [Authorize] action does exactly this on your behalf, so an explicit
        /// "Sign in" link is only needed when the user is choosing to authenticate from a page
        /// that is otherwise public.
        /// </summary>
        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            // Only ever redirect back to somewhere inside this application. Echoing an arbitrary
            // returnUrl makes the sign-in endpoint an open redirect, which is a phishing primitive.
            var target = Url.IsLocalUrl(returnUrl) ? returnUrl! : "/";
            return Challenge(new AuthenticationProperties { RedirectUri = target }, ArkOidcClient.OidcScheme);
        }

        /// <summary>
        /// RP-initiated logout.
        ///
        /// Signing out of both schemes is deliberate: the cookie scheme drops the local session,
        /// and the OIDC scheme redirects to the provider's end_session_endpoint so the session at
        /// the identity provider ends too. Dropping only the cookie leaves the user signed in at
        /// the provider, and the next sign-in completes without a prompt — which looks like a
        /// broken logout.
        ///
        /// POST-only with an antiforgery token, so a third-party page cannot sign the user out
        /// by embedding an image or a link.
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Logout()
        {
            return SignOut(
                new AuthenticationProperties { RedirectUri = "/" },
                ArkOidcClient.CookieScheme,
                ArkOidcClient.OidcScheme);
        }

        /// <summary>Ends the local session only, leaving the provider session intact.</summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult LocalLogout()
        {
            return SignOut(
                new AuthenticationProperties { RedirectUri = "/" },
                ArkOidcClient.CookieScheme);
        }
    }
}
