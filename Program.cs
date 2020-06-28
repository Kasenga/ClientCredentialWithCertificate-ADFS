/*
 The MIT License (MIT)

Copyright (c) 2015 Microsoft Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/* 
 * May 2020 - Kasenga Kapansa
 * https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Client-credential-flows
 * 
 */

using System.Security.Cryptography.X509Certificates;
using Microsoft.Identity.Client;
using System;
using System.Threading.Tasks;
using System.Linq;


namespace ClientCredentialWithCertificate
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
            string tenantID = "adfs";                                       //Leave this as-is
            string clientID = "<client_id>";                                //Change "<client_id>" to client_id from your AD FS app registration
            string certificateName = "cn=SelfSignedCert";                   //Change "SelfSignedCert" to the what you have in $displayName from the Powershell script
            string[] scopes = new string[] { "https://daemon-webapi/" };    //Change "https://daemon-webapi/" to your resource or API URI
            string authority = "https://adfs.contoso.com/" + tenantID;      //Change "adfs.contoso.com" to your AD FS service name

            /*Create Confidential Client ...
            Source  - https://docs.microsoft.com/en-us/azure/active-directory/develop/scenario-daemon-app-configuration?tabs=dotnet
                    - https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/Client-credential-flows
            
            Even if this is a console application here, a daemon application is a confidential client application
            */

            IConfidentialClientApplication app;
            app = null;
            try
            {
                //Obtain certificate from cert store ..
                X509Certificate2 certificate = ReadCertificate(certificateName);
                
                if (certificate != null)
                {
                    //We found a cert ... create the confidential client ...
                    app = ConfidentialClientApplicationBuilder.Create(clientID)
                        .WithCertificate(certificate)
                        .WithAuthority(new Uri(authority))
                        .Build();
                    Console.WriteLine("Confidential client created using certificate: " + certificate.Subject);
                }
                else
                {
                    Console.WriteLine("Not able to find or load certificate");
                }
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

        /*
         * Source: https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2?view=netcore-3.1
         */
        private static X509Certificate2 ReadCertificate(string certificateName)
        {
            if (string.IsNullOrWhiteSpace(certificateName))
            {
                throw new ArgumentException("certificateName should not be empty. Please set the CertificateName setting in the appsettings.json", "certificateName");
            }
            X509Certificate2 cert = null;
            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certCollection = store.Certificates;

                // Find unexpired certificates.
                X509Certificate2Collection currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
                if (currentCerts != null)
                {
                    // From the collection of unexpired certificates, find the ones with the correct name.
                    X509Certificate2Collection signingCert = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certificateName, false);

                    // Return the first certificate in the collection, has the right name and is current.
                    cert = signingCert.OfType<X509Certificate2>().OrderByDescending(c => c.NotBefore).FirstOrDefault();

                    if (cert == null)
                    {
                        /*In the event that we don't find the named certificate, list the certs that are in this store.
                         * Cleary this is for testing and demo purposes only - in production, you don't want to list all the certs
                         * you have in your cert store :)
                         */ 
                        Console.WriteLine("Was not able to find the certificate, '" + certificateName + "', in the store you specified.");
                        Console.WriteLine("Store: ," + StoreLocation.CurrentUser + ", Name: " + StoreName.My);

                        Console.WriteLine("Found the following certs, instead:");
                        foreach (var crt in currentCerts)
                        {
                            Console.WriteLine("Thumbprint: " + crt.Thumbprint);
                            Console.WriteLine("Subject: " + crt.Subject);
                            Console.WriteLine("Friendly Name: " + crt.FriendlyName);
                            Console.WriteLine("Private Key: " + crt.PrivateKey);
                            Console.WriteLine("Cert hash: " + crt.GetCertHash());
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Cannot find any certificates in this store: " + StoreLocation.CurrentUser + "," + StoreName.My);
                }
            }
            return cert;
        }
    }
}
