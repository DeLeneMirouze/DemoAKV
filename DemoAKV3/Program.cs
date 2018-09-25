using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using DemoAKV3.Utils;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest.Azure;

namespace DemoAKV3
{
    class Program
    {
        static void Main(string[] args)
        {
            string baseVaultAddress = "https://amethystevault.vault.azure.net";

            //KeyVaultClient keyVaultClient = new KeyVaultClient(
            //        new KeyVaultClient.AuthenticationCallback(GetAccessToken));

            CertificateAccesTokenService cts = new CertificateAccesTokenService();
            KeyVaultClient keyVaultClient = new KeyVaultClient(
                    new KeyVaultClient.AuthenticationCallback(cts.GetAccessToken));

            Console.WriteLine("Liste des secrets du vault");
            IPage<SecretItem> items = keyVaultClient
                .GetSecretsAsync(baseVaultAddress)
                .Result;

            foreach (SecretItem item in items)
            {
                string name= item.Identifier.Name;
                SecretBundle s = keyVaultClient
                    .GetSecretAsync(baseVaultAddress, name)
                    .Result;
          
                Console.WriteLine("{0}: {1}", name, s.Value);
            }
            Console.WriteLine();

            Console.WriteLine("Lecture d'un secret");
            SecretBundle secret = keyVaultClient
                .GetSecretAsync(baseVaultAddress + "/secrets/password")
                .Result;

            //SecretBundle secret = keyVaultClient
            //    .GetSecretAsync(vaultAddress, "password", version)
            //    .Result;

            Console.WriteLine(secret.Value);
        }

        private static async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            AuthenticationContext context = new AuthenticationContext(authority, TokenCache.DefaultShared);

            string clientId = ConfigurationManager.AppSettings["AuthClientId"];
            string clientSecret = ConfigurationManager.AppSettings["AuthClientSecret"];
            ClientCredential credential = new ClientCredential(clientId, clientSecret);

            AuthenticationResult authResult = await context
                .AcquireTokenAsync(resource, credential)
                .ConfigureAwait(false);
       
            return authResult.AccessToken;
        }

        //private static async Task<string> GetAccessToken2(string authority, string resource, string scope)
        //{
        //    string clientId = ConfigurationManager.AppSettings["AuthClientId"];
        //    string thumbprint = ConfigurationManager.AppSettings["Thumbprint"];
        //    var token = await GetAccessTokenFromCertificate(clientId, thumbprint, authority, resource).ConfigureAwait(false);

        //    return token;
        //}


        //private static Dictionary<string, X509Certificate2> loadedCertificatePfx = new Dictionary<string, X509Certificate2>();
        //private static object _lockInitCertificate = new object();

        //private static X509Certificate2 FindCertificateByThumbprint(string thumbprint, StoreLocation storeLocation)
        //{
        //    using (var store = new X509Store(StoreName.My, storeLocation))
        //    {
        //        store.Open(OpenFlags.ReadOnly);

        //        // Don't validate certs, since the test root isn't installed.
        //        var col = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);

        //        if (col == null || col.Count == 0)
        //        {
        //            return null;
        //        }
        //        else
        //        {
        //            return col[0];
        //        }
        //    }
        //}

        //private static X509Certificate2 InitializeForCertificate(string thumprint)
        //{
        //    X509Certificate2 certificatePfx;

        //    loadedCertificatePfx.TryGetValue(thumprint, out certificatePfx);
        //    if (certificatePfx == null)
        //    {
        //        lock (_lockInitCertificate)
        //        {
        //            loadedCertificatePfx.TryGetValue(thumprint, out certificatePfx);
        //            if (certificatePfx == null)
        //            {
        //                certificatePfx = FindCertificateByThumbprint(thumprint, StoreLocation.CurrentUser);

        //                //If certificate is not found in User store then try in the Machine store
        //                if (certificatePfx == null)
        //                {
        //                    certificatePfx = FindCertificateByThumbprint(thumprint, StoreLocation.LocalMachine);
        //                }

        //                if (certificatePfx != null)
        //                {
        //                    loadedCertificatePfx.Add(thumprint, certificatePfx);
        //                }
        //            }
        //        }
        //    }
        //    return (certificatePfx);
        //}

        //private static async Task<string> GetAccessTokenFromCertificate(string clientId, string thumprint, string authority, string resource)
        //{
        //    X509Certificate2 certificate = InitializeForCertificate(thumprint);
        //    var clientAssertionCertificate = new ClientAssertionCertificate(clientId, certificate);
        //    AuthenticationContext authenticationContext = new AuthenticationContext(authority, TokenCache.DefaultShared);

        //    var result = await authenticationContext.AcquireTokenAsync(resource, clientAssertionCertificate).ConfigureAwait(false);
        //    return result.AccessToken;
        //}
    }
}
