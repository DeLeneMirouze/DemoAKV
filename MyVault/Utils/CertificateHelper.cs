using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MyVault.Utils
{
    public static class CertificateHelper
    {
        #region ToHexString
        /// <summary>
        /// Convertir en String une byte[]
        /// </summary>
        /// <param name="hex">Tableau de Byte</param>
        /// <returns></returns>
        public static string ToHexString(this byte[] hex)
        {
            if (hex == null)
            {
                return null;
            }

            if (hex.Length == 0)
            {
                return string.Empty;
            }

            var s = new StringBuilder();
            foreach (byte b in hex)
            {
                s.Append(b.ToString("x2"));
            }
            return s.ToString();
        }
        #endregion

        #region FindCertificateByThumbprint 
        /// <summary>
        /// Recherche un certificat dans un magasin donné étant connue son empreinte
        /// </summary>
        /// <param name="thumbprint">Empreinte du certificat à retrouver</param>
        /// <param name="storeLocation">Magasin où rechercher</param>
        /// <returns></returns>
        public static X509Certificate2Collection FindCertificateByThumbprint(string thumbprint, StoreLocation storeLocation)
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
                    // on retourne la collection trouvée
                    return col;
                }
            }
        }
        #endregion
    }
}
