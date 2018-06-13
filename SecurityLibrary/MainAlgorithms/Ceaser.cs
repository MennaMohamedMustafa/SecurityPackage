using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public Dictionary<char, int> Dic = new Dictionary<char, int>();
        public char KeyByValue(Dictionary<char, int> dict, int val)
        {
            char Key = new char();
            foreach (KeyValuePair<char, int> pair in dict)
            {
                if (pair.Value == val)
                {
                    Key = pair.Key;
                    break;
                }
            }
            return Key;
        }
        public string Encrypt(string plainText, int key)
        {
            int Number = 0, k = 0, L = 0;
            string cyphertext = "";
            char s = new char();
            plainText = plainText.ToUpper();
            for (char c = 'A'; c <= 'Z'; c++)
            {
                Number = c - 'A';
                Dic.Add((char)c, Number);
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                k = Dic[plainText[i]];
                L = (key + k) % 26;
                s = KeyByValue(Dic, L);

                cyphertext += s;
                // cyphertext.Insert(i, s.ToString());

                s = ' ';
            }
            return cyphertext;
        }
        public string Decrypt(string cipherText, int key)
        {
            int Number = 0, k = 0, L = 0;
            string plaintext = "";
            char s = new char();
            cipherText = cipherText.ToUpper();
            for (char c = 'A'; c <= 'Z'; c++)
            {
                Number = c - 'A';
                Dic.Add((char)c, Number);
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                k = Dic[cipherText[i]];

                L = (k - key);
                if (L < 0)
                {
                    L += 26;
                }
                s = KeyByValue(Dic, L);

                plaintext += s;
                // cyphertext.Insert(i, s.ToString());

                s = ' ';
            }
            plaintext = plaintext.ToLower();
            return plaintext;
        }
        public int Analyse(string plainText, string cipherText)
        {
            int Number = 0, k1 = 0, k2 = 0, Key = 0;
            char pt = new char();
            char ct = new char();
            plainText = plainText.ToUpper();
            cipherText = cipherText.ToUpper();
            for (char c = 'A'; c <= 'Z'; c++)
            {
                Number = c - 'A';
                Dic.Add((char)c, Number);
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                k1 = Dic[plainText[i]];
                k2 = Dic[cipherText[i]];
            }
            Key = k2 - k1;
            if (Key < 0)
            {
                Key += 26;
            }
            return Key;
        }
    }
}
