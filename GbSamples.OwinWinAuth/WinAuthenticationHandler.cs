using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;

namespace GbSamples.OwinWinAuth
{
    // Created by the factory in the WinAuthenticationMiddleware class.
    class WinAuthenticationHandler : AuthenticationHandler<WinAuthenticationOptions>
    {
        protected override Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            if (Options.CallbackPath.Value == Request.Path.Value)
            {
                if (string.IsNullOrEmpty(Context.Request.User.Identity.Name))
                {
                    Context.Response.StatusCode = 401;
                    Options.AlreadySet = false;
                    return Task.FromResult<AuthenticationTicket>(null);
                }

                var identity = new ClaimsIdentity(Options.SignInAsAuthenticationType);

                identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, Context.Request.User.Identity.Name, null,
                    Options.AuthenticationType));

                identity.AddClaims((Context.Request.User.Identity as ClaimsIdentity).Claims);

                var properties = Options.StateDataFormat.Unprotect(Request.Query["state"]);

                return Task.FromResult(new AuthenticationTicket(identity, properties));
            }
            return Task.FromResult<AuthenticationTicket>(null);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

                if (challenge != null)
                {
                    if (Options.AuthenticationType == "Win" && !Options.AlreadySet)
                    {
                        Options.AlreadySet = true;
                        return Task.FromResult<object>(null);
                    }

                    var state = challenge.Properties;

                    if (string.IsNullOrEmpty(state.RedirectUri))
                    {
                        state.RedirectUri = Request.Uri.ToString();
                    }

                    var stateString = Options.StateDataFormat.Protect(state);

                    Response.Redirect(WebUtilities.AddQueryString(Options.CallbackPath.Value, "state", stateString));
                }
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath.Value == Request.Path.Value)
            {
                if (string.IsNullOrEmpty(Context.Request.User.Identity.Name))
                {
                    Response.StatusCode = 401;
                    return false;
                }

                var ticket = await AuthenticateAsync();

                if (ticket != null)
                {
                    Context.Authentication.SignIn(ticket.Properties, ticket.Identity);

                    Response.Redirect(ticket.Properties.RedirectUri);

                    return true;
                }
            }
            return false;
        }
    }
}
