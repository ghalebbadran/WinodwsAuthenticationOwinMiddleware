using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace GbSamples.OwinWinAuth
{
    public class WinAuthenticationOptions : AuthenticationOptions
    {
        public WinAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            Description.Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/windowsAuth");
            AuthenticationMode = AuthenticationMode.Active;
        }

        public PathString CallbackPath { get; set; }

        public PathString IdentityServerPath { get; set; }
        
        public string UserName { get; set; }

        public string UserId { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public bool AlreadySet { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }
    }
}
