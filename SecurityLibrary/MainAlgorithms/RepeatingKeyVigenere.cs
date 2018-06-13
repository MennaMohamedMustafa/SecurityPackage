using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
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

        public string Analyse(string plainText, string cipherText)
        {
            int Number = 0, KeyIndex = 0, Index = 0, x = 0, y = 0;
            char AddToKey = new char();
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
                KeyIndex = Dic[cipherText[i]] - Dic[plainText[i]];
                if (KeyIndex < 0)
                { KeyIndex += 26; }

                AddToKey = KeyByValue(Dic, KeyIndex);
                key += AddToKey;
                AddToKey = ' ';
            }
            string test = "";
            List<int> list = new List<int>();
            int a = 0;
            for (int j = 1; j < key.Length; j++)
            {
                if (key[j] == key[a])
                {
                    list.Add(j);
                    test += key[x];
                    a++;
                }
                else
                {
                    list.Clear();
                    test = "";
                    a = 0;
                }
            }

            if (list.Count() > 0)
                key = key.Remove(list[0]);

            return key.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            int Number = 0, counter = 0, calcCTIndex = 0, calcKEYIndex = 0, calcIndex = 0;
            string PlainText = "";
            char AddToPT = new char();

            cipherText = cipherText.ToUpper();
            key = key.ToUpper();

            // fill dictionary characters with index from 0:25
            for (char c = 'A'; c <= 'Z'; c++)
            {
                Number = c - 'A';
                Dic.Add((char)c, Number);
            }

            if (cipherText.Length > key.Length)
            {
                counter = cipherText.Length - key.Length;
                for (int i = 0; i < counter; i++)
                {
                    key += key[i];
                }
            }



            for (int i = 0; i < cipherText.Length; i++)
            {

                calcCTIndex = Dic[cipherText[i]];
                calcKEYIndex = Dic[key[i]];
                calcIndex = (calcCTIndex - calcKEYIndex);
                if (calcIndex < 0)
                {
                    calcIndex += 26;
                }

                calcIndex = calcIndex % 26;
                AddToPT = KeyByValue(Dic, calcIndex);

                PlainText += AddToPT;
                // cyphertext.Insert(i, s.ToString());

                AddToPT = ' ';

            }
            PlainText = PlainText.ToLower();
            return PlainText;
        }

        public string Encrypt(string plainText, string key)
        {
            int Number = 0, counter = 0, calcPTIndex = 0, calcKEYIndex = 0, calcIndex = 0;
            string cyphertext = "";
            char AddToCT = new char();

            plainText = plainText.ToUpper();
            key = key.ToUpper();

            // fill dictionary characters with index from 0:25
            for (char c = 'A'; c <= 'Z'; c++)
            {
                Number = c - 'A';
                Dic.Add((char)c, Number);
            }

            if (plainText.Length > key.Length)
            {
                counter = plainText.Length - key.Length;
                for (int i = 0; i < counter; i++)
                {
                    key += key[i];
                }
            }



            for (int i = 0; i < plainText.Length; i++)
            {

                calcPTIndex = Dic[plainText[i]];
                calcKEYIndex = Dic[key[i]];
                calcIndex = (calcPTIndex + calcKEYIndex) % 26;
                AddToCT = KeyByValue(Dic, calcIndex);

                cyphertext += AddToCT;
                // cyphertext.Insert(i, s.ToString());

                AddToCT = ' ';

            }

            return cyphertext;
        }
    }
}