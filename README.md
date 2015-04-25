To use windows authenticaiton functionlaity, do the following:
1- Install the NUGET package "Install-Package GbSamples.OwinWinAuth" OR downlaod the source code and reference the DLL.
2- Register the middleware in the startup file by adding the following code;
 app.UseWinAuthentication(new WinAuthenticationOptions()
            {
                SignInAsAuthenticationType = "Win"
            });
