using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DemoAKV3.Utils
{
    public static class CertificateHelper
    {
        public static string ToHexString(this byte[] hex)
        {
            if (hex == null)
                return null;
            if (hex.Length == 0)
                return string.Empty;

            var s = new StringBuilder();
            foreach (byte b in hex)
            {
                s.Append(b.ToString("x2"));
            }
            return s.ToString();
        }
    }
}
