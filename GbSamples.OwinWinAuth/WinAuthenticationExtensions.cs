using Owin;

namespace GbSamples.OwinWinAuth
{
    public static class WinAuthenticationExtensions
    {
        public static IAppBuilder UseWinAuthentication(this IAppBuilder app, WinAuthenticationOptions options)
        {
            return app.Use(typeof(WinAuthenticationMiddleware), app, options);
        }
    }
}
