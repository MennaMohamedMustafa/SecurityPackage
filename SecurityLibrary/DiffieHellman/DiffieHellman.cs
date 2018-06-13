using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
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
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            List<int> Keys = new List<int>();
            int Ya = Mod_Power(alpha, xa, q);
            int Yb = Mod_Power(alpha, xb, q);
            int K1 = Mod_Power(Ya, xb, q);
            int K2 = Mod_Power(Yb, xa, q);
             Keys.Add(K1); Keys.Add(K2);
            return Keys;
        }
    }
}
