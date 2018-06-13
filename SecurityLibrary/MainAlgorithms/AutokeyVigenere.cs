using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public Dictionary<char, int> Dic = new Dictionary<char, int>();
        public string Analyse(string plainText, string cipherText)
        {
            int Number = 0, CharIndx;
            string key = "";
            cipherText = cipherText.ToUpper();
            plainText = plainText.ToUpper();
            for (char c = 'A'; c <= 'Z'; c++)
            {
                Number = c - 'A';
                Dic.Add((char)c, Number);
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                CharIndx = Dic[cipherText[i]] - Dic[plainText[i]];
                if (CharIndx < 0)
                    CharIndx += 26;
                key += KeyByValue(Dic, CharIndx);
                CharIndx = 0;
            }
            string test = "";
            List<int> list = new List<int>();
            int x = 0;
            for (int j = 0; j < key.Length; j++)
            {
                if (key[j] == plainText[x])
                {
                    list.Add(j);
                    test += plainText[x];
                    x++;
                }
                else
                {
                    list.Clear();
                    test = "";
                    x = 0;
                }
            }

            if (list.Count() > 0)
                key = key.Remove(list[0]);

            return key.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            int Number = 0;
            string plainText = "";
            int CharIndx;
            key = key.ToUpper();
            cipherText = cipherText.ToUpper();
            int count = 0;
            for (char c = 'A'; c <= 'Z'; c++)
            {
                Number = c - 'A';
                Dic.Add((char)c, Number);
            }
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (i < key.Length)
                {
                    CharIndx = Dic[cipherText[i]] - Dic[key[i]];
                    if (CharIndx < 0)
                        CharIndx += 26;
                    plainText += KeyByValue(Dic, CharIndx);
                    CharIndx = 0;
                }
                else
                {
                    CharIndx = Dic[cipherText[i]] - Dic[plainText[count]];
                    if (CharIndx < 0)
                        CharIndx += 26;
                    plainText += KeyByValue(Dic, (CharIndx));
                    CharIndx = 0;
                    count++;
                }

            }

            return plainText.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            int Number = 0;
            string cyphertext = "";
            int CharIndx;
            plainText = plainText.ToUpper();
            key = key.ToUpper();
            for (char c = 'A'; c <= 'Z'; c++)
            {
                Number = c - 'A';
                Dic.Add((char)c, Number);
            }
            if (key.Length < plainText.Length)
            {
                key += plainText.Substring(0, plainText.Length - key.Length);
            }
            for (int i = 0; i < plainText.Length; i++)
            {
                CharIndx = (Dic[key[i]] + Dic[plainText[i]]) % 26;
                cyphertext += KeyByValue(Dic, CharIndx);
                CharIndx = 0;
            }
            return cyphertext;
        }

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
    }
}
