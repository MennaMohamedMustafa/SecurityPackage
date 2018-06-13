using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    /// <summary>
    /// The List<int> is row based. Which means that the key is given in row based manner.
    /// </summary>
    public class HillCipher :  ICryptographicTechnique<List<int>, List<int>>
    {
        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {
            throw new NotImplementedException();
        }


        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {

            throw new NotImplementedException();
            /* List<int> pt = new List<int>(cipherText.Count);


            double count = Math.Sqrt(Convert.ToDouble(key.Count));
            int m = Convert.ToInt32(count);
            int[,] vkey = new int[m, m];

            int k = 0;
            //convert list of key to matrix

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    vkey[i, j] = key[k];
                    k++;
                }
            }


            int[,] m_inverse = new int[m, m];
            int[,] mat = new int[m, m];
            mat = cofactor(vkey, m);
            // find transpose of cofactor matrix 
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    m_inverse[i, j] = mat[j, i];
                }
            }
            int e = 0;
            int ctindex;
            int[] vct = new int[m];

            int[] vectorpt = new int[m];

            //get vector
            while (e < cipherText.Count)
            {
                // get ciphe vector
                for (int i = 0; i < m; i++)
                {

                    ctindex = cipherText[e];
                    vct[i] = ctindex;
                    e++;

                }
                // get plain text
                for (int s = 0; s < m; s++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        vectorpt[s] += m_inverse[s, j] * vct[j];

                    }
                    int index1 = vectorpt[s] % 26;
                    pt.Add(index1);

                    vectorpt[s] = 0;
                }
            }
            return pt;
            */
        }


        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();
            List<int> ct = new List<int>(plainText.Count);

            double count = Math.Sqrt(Convert.ToDouble(key.Count));
            int m = Convert.ToInt32(count);
            int colmn = plainText.Count / m;
            int[,] vkey = new int[m, m];
            int[] vpt = new int[m];

            int[] vectorct = new int[m];

            int k = 0;
            //convert list of key to matrix

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    vkey[i, j] = key[k];
                    k++;
                }
            }


            int e = 0;
            int ptindex;

            //get vector
            while (e < plainText.Count)
            {
                // get plain vector
                for (int i = 0; i < m; i++)
                {

                    ptindex = plainText[e];
                    vpt[i] = ptindex;
                    e++;

                }
                // get cipher text
                for (int s = 0; s < m; s++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        vectorct[s] += vkey[s, j] * vpt[j];

                    }
                    int index1 = vectorct[s] % 26;
                    ct.Add(index1);

                    vectorct[s] = 0;
                }
            }
            return ct;
        }


        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {
            // throw new NotImplementedException();
            List<int> key = new List<int>(cipher3.Count);


            double count = Math.Sqrt(Convert.ToDouble(plain3.Count));
            int m = Convert.ToInt32(count);
            int[,] vplain = new int[m, m];

            int k = 0;
            //convert list of plain to matrix

            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    vplain[i, j] = plain3[k];
                    k++;
                }
            }



            int[,] m_inverse = new int[m, m];
            int[,] mat = new int[m, m];
            mat = cofactor(vplain, m);
            // find transpose of cofactor matrix 
            for (int i = 0; i < m; i++)
            {
                for (int j = 0; j < m; j++)
                {
                    m_inverse[i, j] = mat[j, i];
                }
            }




            int ctindex;
            int[] vct = new int[m];

            int[] keyvector = new int[m];

            int e = 0;
            int f = 0;

            while (e < cipher3.Count)
            {
                // get cipher vector


                for (int j = 0; j < m; j++)
                {
                    ctindex = cipher3[f + j * m];
                    vct[j] = ctindex;
                    e++;
                }


                f++;


                // get key
                for (int s = 0; s < m; s++)
                {
                    for (int j = 0; j < m; j++)
                    {
                        keyvector[s] += m_inverse[s, j] * vct[j];

                    }
                    int index1 = keyvector[s] % 26;
                    key.Add(index1);

                    keyvector[s] = 0;
                }

            }
            return key;

        }
        static int[,] cofactor(int[,] vkey, int m)
        {
            int[,] cofactor = new int[m, m];
            int[,] matrix_cofactor = new int[m, m];
            int p, q, l, n, i, j;
            for (q = 0; q < m; q++)
            {
                for (p = 0; p < m; p++)
                {
                    l = 0;
                    n = 0;
                    for (i = 0; i < m; i++)
                    {
                        for (j = 0; j < m; j++)
                        {
                            if (i != q && j != p)
                            {
                                cofactor[l, n] = vkey[i, j];
                                if (n < (m - 2))
                                    n++;
                                else
                                {
                                    n = 0;
                                    l++;
                                };
                            }
                        }
                    }
                    int e = p + q;
                    int f = Convert.ToInt32(Math.Pow(-1, e));
                    int g = determinant(cofactor, m - 1);

                    int det = determinant(vkey, m);

                    double x = 26 - det;

                    double val = 1;
                    bool integer;
                    double c;
                    do
                    {
                        c = val / x;
                        integer = IsInteger(c);
                        if (integer == false)
                        {
                            val += 26;
                        }
                    }
                    while (integer == false);



                    int b = (int)(26 - c);
                    int mod = (b * f * g) % 26;

                    if (mod < 0)
                    {
                        mod += 26;
                    }

                    matrix_cofactor[q, p] = mod;

                }

            }
            return matrix_cofactor;
        }
        static bool IsInteger(double d)
        {
            if (d == (int)d)
                return true;
            else
                return false;
        }

        static int determinant(int[,] vkey, int m)
        {

            int s = 1, det = 0;
            int[,] minor = new int[m, m];
            if (m == 1)
            {
                det = vkey[0, 0];
            }
            else
            {
                det = 0;
                for (int c = 0; c < m; c++)
                {
                    int x = 0;
                    int y = 0;
                    for (int i = 0; i < m; i++)
                    {
                        for (int j = 0; j < m; j++)
                        {
                            minor[i, j] = 0;
                            if (i != 0 && j != c)
                            {
                                minor[x, y] = vkey[i, j];
                                if (y < (m - 2))
                                    y++;
                                else
                                {
                                    y = 0;
                                    x++;
                                }
                            }

                        }
                    }
                    det = det + s * (vkey[0, c] * determinant(minor, m - 1));
                    s = -1 * s;
                }
            }
            while (det < 0)
            {
                det += 26;
            }
            return det;
        }

    }
}
