using System.Threading.Tasks;

namespace MyVault.AccessToken
{
    /// <summary>
    /// Prototype pour implémenter une classe qui remonte un jeton d'accès vers un Azure Key Vault
    /// </summary>
    public interface IAccessTokenService
    {
        Task<string> GetAccessToken(string authority, string resource, string scope);
    }
}