#region using
using System.Collections.Generic;
using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using MyVault.Utils; 
#endregion

namespace MyVault.AccessToken
{
    /// <summary>
    /// Obtient un jeton d'accès vers un Azure Key Vault à partir d'un certificat
    /// </summary>
    public sealed class CertificateAccessTokenService : IAccessTokenService
    {
        #region Constructeur
        readonly string _clientId;
        readonly string _thumbprint;
        readonly string _tenant;

        /// <summary>
        /// Constructeur
        /// </summary>
        public CertificateAccessTokenService()
        {
            _clientId = ConfigurationManager.AppSettings["application.id"];
            _tenant = ConfigurationManager.AppSettings["tenant.id"];
            _thumbprint = ConfigurationManager.AppSettings["application.thumbprint"];
        }
        #endregion

        #region GetAccessToken
        /// <summary>
        /// Réclamer un jeton d'authentification au vault
        /// </summary>
        /// <param name="authority">Adresse du service chargé de renvoyer le jeton</param>
        /// <param name="resource">Adresse de base du vault</param>
        /// <param name="scope"></param>
        /// <returns></returns>
        public async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            string token = await GetAccessTokenFromCertificate(_clientId, _thumbprint, _tenant, resource)
                .ConfigureAwait(false);

            return token;
        }
        #endregion

        #region GetAccessTokenFromCertificate (private)
        /// <summary>
        /// Obtenir le jeton
        /// </summary>
        /// <param name="clientId"></param>
        /// <param name="thumprint"></param>
        /// <param name="authority"></param>
        /// <param name="resource"></param>
        /// <returns></returns>
        private async Task<string> GetAccessTokenFromCertificate(string clientId, string thumprint, string authority, string resource)
        {
            X509Certificate2 certificate = FindCertificate(thumprint);
            ClientAssertionCertificate clientAssertionCertificate = new ClientAssertionCertificate(clientId, certificate);
            AuthenticationContext authenticationContext = new AuthenticationContext(
                authority,
                TokenCache.DefaultShared);

            AuthenticationResult result = await authenticationContext
                .AcquireTokenAsync(resource, clientAssertionCertificate)
                .ConfigureAwait(false);

            return result.AccessToken;
        }
        #endregion

        #region FindCertificate (private)
        private static object _lock = new object();
        /// <summary>
        /// Cache
        /// </summary>
        private static Dictionary<string, X509Certificate2> loadedCertificatePfx = new Dictionary<string, X509Certificate2>();

        /// <summary>
        /// Recherche un certificat dans les différents magasins à partir de son empreinte
        /// </summary>
        /// <param name="thumprint">Empreinte du certificat à rechercher</param>
        /// <returns></returns>
        private X509Certificate2 FindCertificate(string thumprint)
        {
            X509Certificate2 pfx;
            loadedCertificatePfx.TryGetValue(thumprint, out pfx);
            if (pfx == null)
            {
                lock (_lock)
                {
                    loadedCertificatePfx.TryGetValue(thumprint, out pfx);

                    // on recherche tout d'abord dans le magasin de l'utilisateur
                    pfx = CertificateHelper
                            .FindCertificateByThumbprint(thumprint, StoreLocation.CurrentUser)[0];

                    if (pfx == null)
                    {
                        // pas trouvé
                        // on cherche alors dans le magasin de l'ordinateur local
                        pfx = CertificateHelper
                                .FindCertificateByThumbprint(thumprint, StoreLocation.LocalMachine)[0];
                    }
                }
            }
            return pfx;
        }
        #endregion
    }
}
