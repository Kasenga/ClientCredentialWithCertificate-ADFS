/* 
 * May 2020 - Kasenga Kapansa, revised Sept 2020
 * https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Client-credential-flows
 * https://github.com/Kasenga/ClientCredentialWithCertificate-ADFS/edit/master/Program.cs
 */

using System.Security.Cryptography.X509Certificates;
using Microsoft.Identity.Client;
using System;
using System.Threading.Tasks;
using System.Linq;


namespace getADFSToken
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                RunAsync().GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message);
                Console.ResetColor();
            }

            Console.WriteLine("Press any key to exit");
            Console.ReadKey();
        }

        private static async Task RunAsync()
        {
            //AD FS OIDC coordinates
            string tenantID = "adfs";                                           //Leave this as-is
            string clientID = "ClientID";                                       //Change " ClientID" to client_id from your AD FS app registration
            string clientSecret = "ClientSecret";                               //Change "ClientSecret" to the value you generated from you AD FS app registration
            string[] scopes = new string[] { "https://daemon-webapi/" };        //Change "https://daemon-webapi/" to your resource or API URI
            string authority = "https://adfs.contoso.com/" + tenantID;          //Change "adfs.contoso.com" to your AD FS service name

            /*Create Confidential Client ...
            Source  - https://docs.microsoft.com/en-us/azure/active-directory/develop/scenario-daemon-app-configuration?tabs=dotnet
                    - https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Client-credential-flows
            
            Even if this is a console application here, a daemon application is a confidential client application
            */

            IConfidentialClientApplication app;
            app = null;
            try
            {
                //We found a cert ... create the confidential client ...
                app = ConfidentialClientApplicationBuilder.Create(clientID)
                    .WithClientSecret(clientSecret)
                    .WithAuthority(new Uri(authority))
                    .Build();
            }
            catch (Exception e)
            {
                Console.WriteLine("Ran into an error while trying to create a confidential client using a certificate.\n" + e.Message);
            }

            //Request access token ...
            Console.WriteLine("Requesting access token from " + authority);
            AuthenticationResult result = null;

            result = await app.AcquireTokenForClient(scopes)
                    .ExecuteAsync();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Token acquired: \n" + result.AccessToken);
            Console.ResetColor();
            Console.WriteLine("Done!");
        }
    }
}
