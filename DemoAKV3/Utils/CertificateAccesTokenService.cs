using System.Configuration;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace DemoAKV3.Utils
{
    /// <summary>
    /// Obtenir un jeton d'accès via un certificat
    /// </summary>
    public class CertificateAccesTokenService
    {
        #region Constructeur
        readonly string _clientId;
        readonly string _thumbprint;

        public CertificateAccesTokenService()
        {
            _clientId = ConfigurationManager.AppSettings["AuthClientId"];
            _thumbprint = ConfigurationManager.AppSettings["Thumbprint"];
        } 
        #endregion

        #region GetAccessToken
        /// <summary>
        /// Réclamer un jeton d'authentification au vault
        /// </summary>
        /// <param name="authority"></param>
        /// <param name="resource"></param>
        /// <param name="scope"></param>
        /// <returns></returns>
        public async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            string token = await GetAccessTokenFromCertificate(_clientId, _thumbprint, authority, resource).ConfigureAwait(false);

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
        /// <summary>
        /// Recherche un certificat dans les différents magasins à partir de son empreinte
        /// </summary>
        /// <param name="thumprint"></param>
        /// <returns></returns>
        private X509Certificate2 FindCertificate(string thumprint)
        {
            X509Certificate2 certificatePfx;
            // on recherche tout d'abord dans le magasin de l'utilisateur
            certificatePfx = FindCertificateByThumbprint(thumprint, StoreLocation.CurrentUser);

            if (certificatePfx == null)
            {
                // pas trouvé
                // on cherche alors dans le magasin de l'ordinateur lpcal
                certificatePfx = FindCertificateByThumbprint(thumprint, StoreLocation.LocalMachine);
            }

            return (certificatePfx);
        }
        #endregion

        #region FindCertificateByThumbprint (private)
        /// <summary>
        /// Recherche un certificat dans un magasin donné étant connue son empreinte
        /// </summary>
        /// <param name="thumbprint"></param>
        /// <param name="storeLocation"></param>
        /// <returns></returns>
        private X509Certificate2 FindCertificateByThumbprint(string thumbprint, StoreLocation storeLocation)
        {
            // obtient une instance d'un proxy vers le magasin
            using (X509Store store = new X509Store(StoreName.My, storeLocation))
            {
                // ouvre le magasin en lecture seule
                store.Open(OpenFlags.ReadOnly);

                // recherche les certificats qui répondent au critère
                X509Certificate2Collection col = store
                    .Certificates
                    .Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (col == null || col.Count == 0)
                {
                    // pas de certificat candidat
                    return null;
                }
                else
                {
                    // on retourne le premier certificat de la liste
                    return col[0];
                }
            }
        } 
        #endregion
    }
}
