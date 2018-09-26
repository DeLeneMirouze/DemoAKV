using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MyVault.Utils
{
    /// <summary>
    /// Interface pour implémenter une méthode qui remonte les informations des contextes
    /// </summary>
    public interface IVaultContextParam
    {
        /// <summary>
        /// Client Id d'une application Azure AD
        /// </summary>
        /// <returns></returns>
        string GetClientId();

        /// <summary>
        /// Empreinte d'un certificat
        /// </summary>
        /// <returns></returns>
        string GetThumprint();

        /// <summary>
        /// Adresse de l'autorité chargée de renvoyer le jeton
        /// </summary>
        /// <returns></returns>
        string GetTenant();

        /// <summary>
        /// Retourne un secret
        /// </summary>
        /// <returns></returns>
        string GetSecret();
    }
}
