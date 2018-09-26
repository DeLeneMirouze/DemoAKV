using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Clients.ActiveDirectory;
using MyVault.Utils;

namespace MyVault.AccessToken
{
    /// <summary>
    /// Obtenir un jeton d'accès à Azure Key Vault avec une authentification Azure AD
    /// </summary>
    public class AzureADAccessToken : IAccessTokenService
    {
        #region Constructeur
        readonly string _clientId;
        readonly string _tenant;
        readonly string _secret;

        /// <summary>
        /// Constructeur
        /// </summary>
        /// <param name="contextParam">Doit fournir un TenantId, ClientId et un secret</param>
        public AzureADAccessToken(IVaultContextParam contextParam)
        {
            _clientId = contextParam.GetClientId();
            _tenant = contextParam.GetTenant();
            _secret = contextParam.GetSecret();
        }
        #endregion

        #region GetAccessToken
        /// <summary>
        /// Réclamer un jeton d'authentification au vault
        /// </summary>
        /// <param name="authority">Adresse du service chargé de renvoyer le jeton</param>
        /// <param name="resource">Adresse de base du vault</param>
        /// <param name="scope"></param>
        public async Task<string> GetAccessToken(string authority, string resource, string scope)
        {
            AuthenticationContext context = new AuthenticationContext(_tenant, TokenCache.DefaultShared);

            ClientCredential credential = new ClientCredential(_clientId, _secret);

            AuthenticationResult authResult = await context
                .AcquireTokenAsync(resource, credential)
                .ConfigureAwait(false);

            return authResult.AccessToken;
        } 
        #endregion
    }
}
