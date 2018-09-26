#region using
using System;
using System.Configuration;
using System.Runtime.Caching;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.KeyVault.WebKey;
using MyVault.AccessToken; 
#endregion

namespace MyVault
{
    /// <summary>
    /// Service d'accès à un vault
    /// </summary>
    public class Vault : IVault
    {
        protected KeyVaultClient KeyVaultClient;

        #region Controlleur
        readonly IAccessTokenService _accessTokenService;
        readonly MemoryCache _memoryCache;
        readonly string _vaultAddress;
        readonly string _encryptionAlgorithm = JsonWebKeyEncryptionAlgorithm.RSAOAEP;

        /// <summary>
        /// Contrôleur avec un IAccessTokenService
        /// </summary>
        /// <param name="accessTokenService">Fournisseur de jeton d'authentification au Key Vault</param>
        public Vault(IAccessTokenService accessTokenService)
        {
            _vaultAddress = ConfigurationManager.AppSettings["keyvault.address"];

            _memoryCache = MemoryCache.Default;
            _accessTokenService = accessTokenService;
            KeyVaultClient = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(_accessTokenService.GetAccessToken));
        }
        #endregion

        #region GetSecretAsync
        /// <summary>
        /// Lecture d'un secret
        /// </summary>
        /// <param name="secretName">Nom du secret</param>
        /// <returns></returns>
        public async Task<string> GetSecretAsync(string secretName)
        {
            string secret = _memoryCache.Get(secretName) as string;

            if (string.IsNullOrEmpty(secret))
            {
                secret = (await KeyVaultClient.GetSecretAsync(_vaultAddress, secretName)
                    .ConfigureAwait(false))
                    .Value;
                _memoryCache.Set(secretName, secret, new CacheItemPolicy());
            }
            return secret;
        }
        #endregion

        #region Decrypt
        /// <summary>
        /// Décrypte un message
        /// </summary>
        /// <param name="keyName">Nom de la clef de décryptage</param>
        /// <param name="message">Message à décrypter</param>
        /// <returns></returns>
        public async Task<string> Decrypt(string keyName, string message)
        {
            byte[] byteMessage = Convert.FromBase64String(message);
            KeyOperationResult result = await KeyVaultClient.DecryptAsync(
                    GetKeyUrl(keyName), 
                    _encryptionAlgorithm, 
                    byteMessage)
                .ConfigureAwait(false);

            return Encoding.Default.GetString(result.Result);
        }
        #endregion

        #region EncryptAsync
        /// <summary>
        /// Encrypte un message
        /// </summary>
        /// <param name="keyName">Nom de la clef d'encryptage</param>
        /// <param name="message">Message à encrypter</param>
        /// <returns></returns>
        public async Task<string> EncryptAsync(string keyName, string message)
        {
            byte[] byteMessage = Encoding.Default.GetBytes(message);
            KeyOperationResult result = await KeyVaultClient.EncryptAsync(
                    GetKeyUrl(keyName), 
                    _encryptionAlgorithm, 
                    byteMessage)
                .ConfigureAwait(false);

            return Convert.ToBase64String(result.Result);
        }
        #endregion

        #region GetKeyAsync
        public async Task<JsonWebKey> GetKeyAsync(string keyName)
        {
            JsonWebKey key = new JsonWebKey();

            key = _memoryCache.Get(keyName) as JsonWebKey;
            if (key == null)
            {
                key = (await KeyVaultClient.GetKeyAsync(_vaultAddress, keyName)
                    .ConfigureAwait(false))
                    .Key;
            }

            return key;
        }
        #endregion

        #region GetKeyUrl (private)
        /// <summary>
        /// Url vers une key
        /// </summary>
        /// <param name="keyName">Nom de la key</param>
        /// <returns></returns>
        private string GetKeyUrl(string keyName)
        {
            return string.Join("/", _vaultAddress, "keys", keyName);
        }
        #endregion
    }
}
