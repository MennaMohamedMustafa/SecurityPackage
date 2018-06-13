using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public Dictionary<char, char> Dic = new Dictionary<char, char>();
        public Dictionary<char, int> NumOfChar = new Dictionary<char, int>();
        public char KeyByValue(Dictionary<char, char> dict, char val)
        {
            char Key = new char();
            foreach (KeyValuePair<char, char> pair in dict)
            {
                if (pair.Value == val)
                {
                    Key = pair.Key;
                    break;
                }
            }
            return Key;
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

        public string Analyse(string plainText, string cipherText)
        {
            List<char> alphabet = new List<char>
            {
                'a',
                'b',
                'c',
                'd',
                'e',
                'f',
                'g',
                'h',
                'i',
                'j',
                'k',
                'l',
                'm',
                'n',
                'o',
                'p',
                'q',
                'r',
                's',
                't',
                'u',
                'v',
                'w',
                'x',
                'y',
                'z'
            };
            var key = new char[26];
            cipherText = cipherText.ToLower();
            for (var i = 0; i < plainText.Length; i++)
            {
                var index = plainText[i] - 'a';
                key[index] = cipherText[i];
                alphabet.Remove(cipherText[i]);
            }
            for (var i = 0; i < 26; i++)
            {
                if (key[i] != '\0')
                    continue;
                key[i] = alphabet[0];
                alphabet.RemoveAt(0);
            }
            var result = new string(key);
            return result;
        }

        public string Decrypt(string cipherText, string key)
        {
            int i = 0;
            string plaintext = "";
            char k = new char();
            cipherText = cipherText.ToUpper();
            key = key.ToUpper();
            for (char c = 'A'; c <= 'Z'; c++)
            {
                Dic.Add((char)c,key[i]);
                i++;
            }
            for (int j = 0; j < cipherText.Length; j++)
            {
                k = KeyByValue(Dic,cipherText[j]);
                plaintext += k;
            }
            plaintext = plaintext.ToLower();
            return plaintext;
        }

        public string Encrypt(string plainText, string key)
        { 
        int i=0 ;
        char k = new char();
        string cyphertext = "";
        plainText = plainText.ToUpper();
            for (char c = 'A'; c <= 'Z'; c++)
            { 
                Dic.Add((char)c,key[i] );
                i++;
            }
            for (int j=0; j<plainText.Length;j++)
            {
                k = Dic[plainText[j]];
                cyphertext += k;
            }

            return cyphertext;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {

            string CharFreq = "ETAOINSRHLDCUMFBGWYBVKXJZ".ToLower();
            int c = 0;
            string output = "";
            for (int i = 0; i < cipher.Length; i++)
            {
                for (int j = 0; j < cipher.Length; j++)
                {
                    if (cipher[i] == cipher[j])
                        c += 1;
                }
                if (!NumOfChar.ContainsKey(cipher[i]))
                    NumOfChar.Add(cipher[i], c);
                c = 0;
            }
            int counter = 0;
            int zeft = NumOfChar.Count;
            for (int k = 0; k < zeft - 1; k++)
            {
                int maxVal = NumOfChar.Values.Max();
                char maxKey = KeyByValue(NumOfChar, maxVal);
                for (int i = 0; i < cipher.Length; i++)
                {
                    if (maxKey == cipher[i])
                    {
                        cipher = cipher.Replace(maxKey, CharFreq[counter]);
                        counter++;
                        break;

                    }
                }
                NumOfChar.Remove(maxKey);
            }
            cipher = cipher.ToLower();
            return cipher;
        }

    }
}
