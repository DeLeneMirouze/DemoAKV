using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
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

            KeyVaultClient keyVaultClient = new KeyVaultClient(
                    new KeyVaultClient.AuthenticationCallback(GetAccessToken));

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
    }
}
