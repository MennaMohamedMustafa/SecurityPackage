using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToUpper();
            char SecondCharacterOfCT = cipherText[1];
            int counter = 0;
            int Index1OfList = 0, Index2OfList = 0;

            List<int> SaveIndex = new List<int>();
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] == SecondCharacterOfCT)
                {
                    SaveIndex.Add(i);
                }
            }
            Index1OfList = SaveIndex[0];
            Index2OfList = SaveIndex[1];
            counter = Index2OfList - Index1OfList;
            if (counter == 1)
            {
                return Index2OfList;
            }
            else
            {
                return Index1OfList;
            }
            return Index1OfList;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            string plaintext = "";
            int index = 0;
            int cipherCols = cipherText.Length / key;
            int remainder = cipherText.Length % key;
            if (remainder > 0)
            { cipherCols++; }
            char[,] cipherMatrix = new char[key, cipherCols];

            //read p.t row wise
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < cipherCols; j++)
                {
                    if (index >= cipherText.Length)
                    { continue; }
                    else
                    {
                        cipherMatrix[i, j] = cipherText[index];
                        index++;
                    }
                }
            }
            //write p.t column wise
            for (int i = 0; i < cipherCols; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (cipherMatrix[j, i] != ' ')
                    { plaintext += cipherMatrix[j, i]; }
                }
            }
            return plaintext;
        }

        public string Encrypt(string plainText, int key)
        {
            string ciphertext = "";
            int index = 0;
            int cipherCols = plainText.Length / key;
            int remainder = plainText.Length % key;
            if (remainder > 0)
            { cipherCols++; }
            char[,] cipherMatrix = new char[key, cipherCols];
            //write p.t column wise
            for (int i = 0; i < cipherCols; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (index >= plainText.Length)
                    { continue; }
                    else
                    {
                        cipherMatrix[j, i] = plainText[index];
                        index++;
                    }
                }
            }
            //read p.t row wise
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < cipherCols; j++)
                {
                    if (cipherMatrix[i, j] != ' ')
                    { ciphertext += cipherMatrix[i, j]; }
                }
            }
            ciphertext = ciphertext.ToUpper();
            return ciphertext;
        }
    }
}
