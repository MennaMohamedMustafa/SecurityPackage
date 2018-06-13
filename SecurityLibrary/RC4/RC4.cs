using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            //check if input hexa
            int flg = 0;
            if (key.StartsWith("0x"))
            { key = CheckInput(key); cipherText = CheckInput(cipherText); flg = 1; }
            // Initialization of S and T
            int[] S = new int[256];
            char[] T = new char[256];
            var PlainText = "";
            int KeyLen = key.Length;
            int index = 0;
            for (int i = 0; i < 256; i++)
            {
                S[i] = i;
                if (index >= KeyLen)
                    index -= KeyLen;

                T[i] = key[index];
                index++;
            }
            //Initial permutation of S
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]);
                while (j >= 256) j -= 256;
                Swap(S, i, j);
            }
            //Generation of Key stream K
            int x = 0, y = 0;
            int cipherLen = cipherText.Length;
            int[] GeneratedKey = new int[cipherLen];
            int ind = 0, temp;
            while (cipherLen > 0)
            {
                x = (x + 1);
                y = (y + S[x]);
                while (y >= 256) y -= 256;
                while (x >= 256) x -= 256;
                Swap(S, x, y);
                temp = S[x] + S[y];
                while (temp >= 256) temp -= 256;
                GeneratedKey[ind] = S[temp];
                ind++;
                cipherLen--;
            }
            //Decryption (XOR with K)
            for (int i = 0; i < cipherText.Length; i++)
            {
                int XorRes = GeneratedKey[i] ^ (int)cipherText[i];
                char ch = Convert.ToChar(XorRes);
                PlainText += ch;
            }
            if (flg == 1)
            {
                PlainText = stringToHex(PlainText);
            }
            return PlainText.ToString();
        }
        public override string Encrypt(string plainText, string key)
        {
            //check if input hexa
            int flg = 0;
            if (key.StartsWith("0x"))
            { key = CheckInput(key); plainText = CheckInput(plainText); flg = 1; }
            // Initialization of S and T
            int[] S = new int[256];
            char[] T = new char[256];
            var cipherText = "";
            int KeyLen = key.Length;
            int index = 0;
            for (int i = 0; i < 256; i++)
            {
                S[i] = i;
                if (index >= KeyLen)
                    index -= KeyLen;

                T[i] = key[index];
                index++;
            }
            //Initial permutation of S
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]);
                while (j >= 256) j -= 256;
                Swap(S, i, j);
            }
            //Generation of Key stream K
            int x = 0, y = 0;
            int plainLen = plainText.Length;
            int[] GeneratedKey = new int[plainLen];
            int ind = 0, temp;
            while (plainLen > 0)
            {
                x = (x + 1);
                y = (y + S[x]);
                while (y >= 256) y -= 256;
                while (x >= 256) x -= 256;
                Swap(S, x, y);
                temp = S[x] + S[y];
                while (temp >= 256) temp -= 256;
                GeneratedKey[ind] = S[temp];
                ind++;
                plainLen--;
            }
            //Decryption (XOR with K)
            for (int i = 0; i < plainText.Length; i++)
            {
                int XorRes = GeneratedKey[i] ^ (int)plainText[i];
                char ch = Convert.ToChar(XorRes);
                cipherText += ch;
            }

            if (flg == 1)
            {
                cipherText = stringToHex(cipherText);
            }

            return cipherText;
        }
        string stringToHex(string str)
        {
            string output = "0x";
            for (int i = 0; i < str.Length; i++)
            {
                byte b = Convert.ToByte(str[i]);
                String hex = b.ToString("x");
                output += hex;
            }
            return output;
        }
        void Swap(int[] arr, int i1, int i2)
        {
            int temp;
            temp = arr[i1];
            arr[i1] = arr[i2];
            arr[i2] = temp;
        }
        public string CheckInput(string input)
        {
            byte[] result = new byte[100];
            string Text = "";
            if (input.StartsWith("0x"))
                input = input.Substring(2);
            result = new byte[input.Length / 2];
            int counter = 0;
            for (int i = 0; i < input.Length; i += 2)
            {
                result[counter] = Convert.ToByte(input[i].ToString() + input[i + 1].ToString(), 16);
                counter++;
            }
            for (int i = 0; i < result.Length; i++)
                Text += (char)result[i];

            return Text;
        }
    }
}
