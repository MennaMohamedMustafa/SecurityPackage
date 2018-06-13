using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SecurityLibrary.AES;

namespace SecurityLibrary.ElGamal
{
    public class ElGamal
    {
        public static int Mod_Power(int num, int pow, int mod)
        {
            int result = 1;
            for (int i = 1; i <= pow; i++)
            {
                result = (result * num) % mod;
            }
            return result;
        }
        public List<long> Encrypt(int q, int alpha, int y, int k, int m)
        {
            List<long> Keys = new List<long>();
            int K = Mod_Power(y, k, q);
            long C1 = Mod_Power(alpha, k, q);
            long C2 = (K * m) % q;
            Keys.Add(C1); Keys.Add(C2);
            return Keys;
        }
        public int Decrypt(int c1, int c2, int x, int q)
        {
            int K = Mod_Power(c1, x, q);
            int KPowerNegOne = new ExtendedEuclid().GetMultiplicativeInverse(K, q);
            int M = (c2 * KPowerNegOne) % q;
            return M;
        }
    }
}
