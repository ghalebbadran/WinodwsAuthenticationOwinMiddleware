using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;
using Owin;

namespace GbSamples.OwinWinAuth
{
    // One instance is created when the application starts.
    public class WinAuthenticationMiddleware : AuthenticationMiddleware<WinAuthenticationOptions>
    {
        public WinAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, WinAuthenticationOptions options)
            : base(next, options)
        {
            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }
            if (options.StateDataFormat == null)
            {
                var dataProtector = app.CreateDataProtector(typeof(WinAuthenticationMiddleware).FullName,
                    options.AuthenticationType);

                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }
        }

        // Called for each request, to create a handler for each request.
        protected override AuthenticationHandler<WinAuthenticationOptions> CreateHandler()
        {
            return new WinAuthenticationHandler();
        }
    }
}