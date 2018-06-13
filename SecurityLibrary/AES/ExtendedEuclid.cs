using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int Inverse = -1, A1 = 1, A2 = 0, A3 = baseN, B1 = 0, B2 = 1, B3 = number, Q = A3 / B3;
            while (B3 != 1)
            {
                int[] OldA = new int[3];
                OldA[0] = A1;
                OldA[1] = A2;
                OldA[2] = A3;
                A1 = B1;
                A2 = B2;
                A3 = B3;
                B1 = OldA[0] - Q * B1;
                B2 = OldA[1] - Q * B2;
                B3 = OldA[2] - Q * B3;
                if (B3 == 0)
                {
                    Inverse = -1;
                    break;
                }
                Q = A3 / B3;
                Inverse = B2;
                if (Inverse < 0)
                    Inverse += baseN;
            }
            return Inverse;
        }
    }
}
