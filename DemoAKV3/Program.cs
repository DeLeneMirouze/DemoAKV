using System;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using DemoAKV3.Utils;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using Microsoft.Rest.Azure;

namespace DemoAKV3
{
    class Program
    {
        static void Main(string[] args)
        {
            string baseVaultAddress = "https://amethystevault.vault.azure.net";

            // Azure AD
            //KeyVaultClient keyVaultClient = new KeyVaultClient(
            //        new KeyVaultClient.AuthenticationCallback(GetAccessToken));

            // Certificat
            CertificateAccesTokenService cts = new CertificateAccesTokenService();
            KeyVaultClient keyVaultClient = new KeyVaultClient(
                    new KeyVaultClient.AuthenticationCallback(cts.GetAccessToken));

            #region Secret
            Console.WriteLine("Liste des secrets du vault");
            IPage<SecretItem> items = keyVaultClient
                .GetSecretsAsync(baseVaultAddress)
                .Result;

            foreach (SecretItem item in items)
            {
                string name = item.Identifier.Name;
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
            #endregion

            #region Key
            string keyName = "keyDemo";
            string identifiant = baseVaultAddress + "/keys/" + keyName;

            // proxy 
            KeyBundle key = keyVaultClient
                .GetKeyAsync(baseVaultAddress, keyName)
                .Result;

            // encode un message
            byte[] byteMessage = Encoding.Default.GetBytes("Salut le monde!");
            KeyOperationResult result = keyVaultClient
                .EncryptAsync(identifiant, JsonWebKeyEncryptionAlgorithm.RSAOAEP, byteMessage)
                .Result;
            string encoded = Convert.ToBase64String(result.Result);

            Console.WriteLine("Message encodé: {0}", encoded);

            // décode le message
            byteMessage = Convert.FromBase64String(encoded);
            result = keyVaultClient
                .DecryptAsync(identifiant, JsonWebKeyEncryptionAlgorithm.RSAOAEP, byteMessage)
                .Result;

            string message = Encoding.Default.GetString(result.Result);
            Console.WriteLine("Après décodage: {0}", message);
            #endregion

            #region Certificate
            // proxy 
            CertificateBundle cert = keyVaultClient
                .GetCertificateAsync(baseVaultAddress, "TestCertificate")
                .Result;

            Console.WriteLine(cert.X509Thumbprint.ToHexString());

            // proxy
            SecretBundle cert2 = keyVaultClient
                .GetSecretAsync(baseVaultAddress + "/secrets/TestCertificate")
                .Result;

            byte[] privateKeyBytes = Convert.FromBase64String(cert2.Value);
            X509Certificate2 pfx = new X509Certificate2(privateKeyBytes, (string)null, X509KeyStorageFlags.MachineKeySet);

            Console.WriteLine(pfx.Thumbprint);
            #endregion
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
