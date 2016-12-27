using Microsoft.Owin;
using Microsoft.Owin.Security;

namespace GbSamples.OwinWinAuth
{
    public class WinAuthenticationOptions : AuthenticationOptions
    {
        internal const string DefaultAuthenticationType = "windows";

        public WinAuthenticationOptions()
            : base(DefaultAuthenticationType)
        {
            Caption = DefaultAuthenticationType;
            CallbackPath = new PathString("/windows-auth");
            AuthenticationMode = AuthenticationMode.Active;
        }

        public PathString CallbackPath { get; set; }

        public string SignInAsAuthenticationType { get; set; }

        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }
    }
}