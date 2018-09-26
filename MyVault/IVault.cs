using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.WebKey;

namespace MyVault
{
    public interface IVault
    {
        Task<string> Decrypt(string keyName, string message);
        Task<string> EncryptAsync(string keyName, string message);
        Task<JsonWebKey> GetKeyAsync(string keyName);
        Task<string> GetSecretAsync(string secretName);
    }
}