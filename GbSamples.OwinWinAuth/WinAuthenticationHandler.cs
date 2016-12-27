using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;

namespace GbSamples.OwinWinAuth
{
    // Created by the factory in the WinAuthenticationMiddleware class.
    internal class WinAuthenticationHandler : AuthenticationHandler<WinAuthenticationOptions>
    {
        private IIdentity _ntlmIdentity;

        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            if (!string.IsNullOrEmpty(Request.User.Identity.Name))
            {
                if (Options.CallbackPath.Value == Request.Path.Value)
                {
                    var properties = Options.StateDataFormat.Unprotect(Request.Query["state"]);
                    return Task.FromResult(CreateTicket((ClaimsIdentity)Request.User.Identity, properties));
                }

                if (HasNTLMAuthHeader(Request.Headers))
                {
                    _ntlmIdentity = Request.User.Identity;
                }
            }

            return Task.FromResult<AuthenticationTicket>(null);
        }

        protected override async Task ApplyResponseCoreAsync()
        {
            if (Response.StatusCode == 200 && Options.CallbackPath.Value == Request.Path.Value)
            {
                var ticket = await AuthenticateAsync();

                if (ticket != null)
                {
                    SignInAndRedirect(ticket);
                    return;
                }
            }

            if (Response.StatusCode == 401 && HasNTLMAuthHeader(Request.Headers) && _ntlmIdentity != null)
            {
                var challenge = GetChallenge();

                if (challenge != null)
                {
                    var ticket = CreateTicket((ClaimsIdentity)_ntlmIdentity, challenge.Properties);
                    SignInAndRedirect(ticket);
                    return;
                }
            }

            await base.ApplyResponseCoreAsync();
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                if (HasNegotiateAuthHeader(Request.Headers) && Options.CallbackPath.Value != Request.Path.Value)
                {
                    var challenge = GetChallenge();

                    if (challenge != null)
                    {
                        var stateString = Options.StateDataFormat.Protect(challenge.Properties);
                        Response.Redirect(WebUtilities.AddQueryString(Request.PathBase + Options.CallbackPath.Value, "state", stateString));
                    }
                }
            }

            return Task.FromResult<object>(null);
        }

        public override Task<bool> InvokeAsync()
        {
            return Task.FromResult(Options.CallbackPath.Value == Request.Path.Value);
        }

        private void SignInAndRedirect(AuthenticationTicket ticket)
        {
            Context.Authentication.SignIn(ticket.Properties, ticket.Identity);
            Response.Redirect(ticket.Properties.RedirectUri);
        }

        private AuthenticationResponseChallenge GetChallenge()
        {
            var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
                if (string.IsNullOrEmpty(challenge.Properties.RedirectUri))
                    challenge.Properties.RedirectUri = Request.Uri.ToString();

            return challenge;
        }

        private AuthenticationTicket CreateTicket(ClaimsIdentity user, AuthenticationProperties props)
        {
            var identity = new ClaimsIdentity(Options.SignInAsAuthenticationType);

            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Name, null, Options.AuthenticationType));
            identity.AddClaims(user.Claims);

            return new AuthenticationTicket(identity, props);
        }

        private static bool HasNTLMAuthHeader(IHeaderDictionary headers)
        {
            return headers.Any(
                 h => h.Key.ToLowerInvariant() == "authorization" &&
                 h.Value[0].ToLowerInvariant().StartsWith("ntlm "));
        }

        private static bool HasNegotiateAuthHeader(IHeaderDictionary headers)
        {
            return headers.Any(
                 h => h.Key.ToLowerInvariant() == "authorization" &&
                 h.Value[0].ToLowerInvariant().StartsWith("negotiate"));
        }
    }
}