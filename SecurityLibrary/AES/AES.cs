using System;
using System.Collections.Generic;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    /// 
    public class AES : CryptographicTechnique
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="key"></param>
        /// <returns></returns>
        public override string Decrypt(string cipherText, string key)
        {
            throw new NotImplementedException();
        }
        public override string Encrypt(string plainText, string key)
        {
            byte[,] pText = new byte[4, 4];
            byte[,] theKey = new byte[4, 4];
            pText = convertHexaToBytes(plainText);
            theKey = convertHexaToBytes(key);
            byte[] plainTextArray = pText.Cast<byte>().ToArray();
            byte[] theKeyArray = theKey.Cast<byte>().ToArray();
            byte[] Output = Cipher(plainTextArray, theKeyArray);
            string cipherTextOutput = "";
            cipherTextOutput = ConvertBytesToString(Output);
            cipherTextOutput = "0x" + cipherTextOutput;
            return cipherTextOutput;
        }
        /// <summary>
        /// //As mentioned that size of block is word
        /// </summary>
        static public int NumberOfColumns = 4;

        /// <summary>
        /// As Number Of rounds is 10 Rounds 
        /// </summary>
        static public int NumberOfRounds = 10;

        /// <summary>
        /// Num of Word
        /// </summary>
        static public int LenghtOfKey = 4;

        /// <summary>
        /// This is The Declaration of SBox A Matrix of 16 * 16
        /// </summary>
        static byte[,] Sbox = new byte[16, 16] {  
      {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
      {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
      {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
      {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
      {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
      {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
      {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
      {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
      {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
      {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
      {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
      {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
      {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
      {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
      {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
      {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16} };


        /// <summary>
        /// This is The Declaration of Inverse SBox A Matrix of 16 * 16
        /// </summary>
        static byte[,] inverseSbox = new byte[16, 16]{
      {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
      {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
      {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
      {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
      {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
      {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
      {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
      {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
      {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
      {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
      {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
      {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
      {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
      {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
      {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
      {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d} };
        /// <summary>
        /// 
        /// </summary>
        static byte[,] Rcon = new byte[11, 4] { 
                                   {0x00, 0x00, 0x00, 0x00},  
                                   {0x01, 0x00, 0x00, 0x00},
                                   {0x02, 0x00, 0x00, 0x00},
                                   {0x04, 0x00, 0x00, 0x00},
                                   {0x08, 0x00, 0x00, 0x00},
                                   {0x10, 0x00, 0x00, 0x00},
                                   {0x20, 0x00, 0x00, 0x00},
                                   {0x40, 0x00, 0x00, 0x00},
                                   {0x80, 0x00, 0x00, 0x00},
                                   {0x1b, 0x00, 0x00, 0x00},
                                   {0x36, 0x00, 0x00, 0x00} };
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Data"></param>
        /// <returns></returns>
        public static string ConvertBytesToString(byte[] Data)
        {
            SoapHexBinary SH = new SoapHexBinary(Data);
            //byte[,] item = new byte[4, 4];
            return SH.ToString();
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="HexaString"></param>
        /// <returns></returns>
        public static byte[,] convertHexaToBytes(string HexaString)
        {
            string croppedString = HexaString.Substring(2);
            int idx = 0;
            byte[,] obj = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    obj[i, j] = Convert.ToByte(croppedString.Substring(idx, 2), 16);
                    idx += 2;
                }
            }
            return obj;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Stat"></param>
        /// <param name="Round"></param>
        /// <param name="theKey"></param>
        /// <returns></returns>
        private static byte[,] toAddRoundKey(byte[,] Stat, int Round, byte[,] theKey)
        {
            for (int r = 0; r < 4; r++)
            {
                for (int c = 0; c < 4; c++)
                {
                    Stat[r, c] = (byte)((int)Stat[r, c] ^ (int)theKey[r, c]);
                }
            }
            return Stat;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="shift"></param>
        /// <returns></returns>
        private static byte[,] shiftRows(byte[,] shift)
        {
            byte[,] t = new byte[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    t[i, j] = shift[i, j];
                }
            }
            for (int i = 1; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    shift[i, j] = t[i, (j + i) % 4];
                }
            }
            return shift;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="sub"></param>
        /// <returns></returns>
        private static byte[,] subBytes(byte[,] sub)
        {
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    sub[i, j] = Sbox[(sub[i, j] >> 4), (sub[i, j] & 0x0f)];
                }
            }
            return sub;
        }
        private static byte gfMultby01(byte byt)
        {
            return byt;
        }
        private static byte gfMultby02(byte byt)
        {
            if (byt < 0x80)
                return (byte)(int)(byt << 1);
            else
                return (byte)((int)(byt << 1) ^ (int)(0x1b));
        }
        private static byte gfMultby03(byte byt)
        {
            return (byte)((int)gfMultby02(byt) ^ (int)byt);
        }
        private static byte gfMultby09(byte byt)
        {
            return (byte)((int)gfMultby02(gfMultby02(gfMultby02(byt))) ^
                           (int)byt);
        }
        private static byte gfMultby0b(byte byt)
        {
            return (byte)((int)gfMultby02(gfMultby02(gfMultby02(byt))) ^ (int)gfMultby02(byt) ^ (int)byt);
        }
        private static byte gfMultby0d(byte byt)
        {
            return (byte)((int)gfMultby02(gfMultby02(gfMultby02(byt))) ^ (int)gfMultby02(gfMultby02(byt)) ^
                           (int)(byt));
        }
        private static byte gfMultby0e(byte byt)
        {
            return (byte)((int)gfMultby02(gfMultby02(gfMultby02(byt))) ^
                           (int)gfMultby02(gfMultby02(byt)) ^
                           (int)gfMultby02(byt));
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Data"></param>
        private static void InverseSubBytes(byte[,] Data)
        {
            for (int i = 0; i < 4; ++i)
            {
                for (int j = 0; j < 4; ++j)
                {
                    Data[i, j] = inverseSbox[(Data[i, j] >> 4), (Data[i, j] & 0x0f)];
                }
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Data"></param>
        private static void InverseShiftRows(byte[,] Data)
        {
            byte[,] tmp = new byte[4, 4];
            for (int i = 0; i < 4; ++i)
            {
                for (int j = 0; j < 4; ++j)
                {
                    tmp[i, j] = Data[i, j];
                }
            }
            for (int i = 1; i < 4; ++i)
            {
                for (int j = 0; j < 4; ++j)
                {
                    Data[i, (j + i) % 4] = tmp[i, j];
                }
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Data"></param>
        private static void InverseMixColumns(byte[,] Data)
        {
            byte[,] tmp = new byte[4, 4];
            for (int i = 0; i < 4; ++i)
            {
                for (int j = 0; j < 4; ++j)
                {
                    tmp[i, j] = Data[i, j];
                }
            }
            for (int i = 0; i < 4; ++i)
            {
                Data[0, i] = (byte)((int)gfMultby0e(tmp[0, i]) ^ (int)gfMultby0b(tmp[1, i]) ^
                                           (int)gfMultby0d(tmp[2, i]) ^ (int)gfMultby09(tmp[3, i]));
                Data[1, i] = (byte)((int)gfMultby09(tmp[0, i]) ^ (int)gfMultby0e(tmp[1, i]) ^
                                           (int)gfMultby0b(tmp[2, i]) ^ (int)gfMultby0d(tmp[3, i]));
                Data[2, i] = (byte)((int)gfMultby0d(tmp[0, i]) ^ (int)gfMultby09(tmp[1, i]) ^
                                           (int)gfMultby0e(tmp[2, i]) ^ (int)gfMultby0b(tmp[3, i]));
                Data[3, i] = (byte)((int)gfMultby0b(tmp[0, i]) ^ (int)gfMultby0d(tmp[1, i]) ^
                                      (int)gfMultby09(tmp[2, i]) ^ (int)gfMultby0e(tmp[3, i]));
            }
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="input"></param>
        /// <param name="theKey"></param>
        /// <returns></returns>
        public static byte[] InverseCipher(byte[] input, byte[] theKey)
        {
            byte[,] stat = new byte[4, 4];
            for (int i = 0; i < (4 * 4); ++i)
            {
                stat[i % 4, i / 4] = input[i];
            }
            byte[,] d = new byte[4, 4];

            for (int i = 0; i < 4 * NumberOfColumns; i++)
            {
                d[i % 4, i / 4] = theKey[i];
            }

            byte[] roundkey = new byte[176];
            roundkey = keyExpansion(theKey);
            int idx = 160;
            byte[,] x = new byte[4, 4];

            for (int f = 0; f < 4; f++)
            {
                for (int j = 0; j < 4; j++)
                {
                    x[j, f] = roundkey[idx];
                    idx++;
                }
            }
            stat = toAddRoundKey(stat, 0, x);
            idx = 144;
            for (int i = 1; i < NumberOfRounds; i++)
            {
                InverseShiftRows(stat);
                InverseSubBytes(stat);
                for (int f = 0; f < 4; f++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        x[j, f] = roundkey[idx];
                        idx++;
                    }
                }
                idx -= 31;
                toAddRoundKey(stat, i, x);
                InverseMixColumns(stat);
            }  // end main round loop for InvCipher
            InverseShiftRows(stat);
            InverseSubBytes(stat);
            toAddRoundKey(stat, NumberOfRounds, d);
            byte[] output = new byte[4 * 4];
            for (int i = 0; i < (4 * 4); ++i)
            {
                output[i] = stat[i % 4, i / 4];
            }
            return output;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="Data"></param>
        /// <returns></returns>
        private static byte[,] mixColumns(byte[,] Data)
        {
            byte[,] tmp = new byte[4, 4];
            for (int i = 0; i < 4; ++i)
            {
                for (int j = 0; j < 4; ++j)
                {
                    tmp[i, j] = Data[i, j];
                }
            }
            for (int ii = 0; ii < 4; ++ii)
            {
                Data[0, ii] = (byte)((int)gfMultby02(tmp[0, ii]) ^ (int)gfMultby03(tmp[1, ii]) ^
                               (int)gfMultby01(tmp[2, ii]) ^ (int)gfMultby01(tmp[3, ii]));
                Data[1, ii] = (byte)((int)gfMultby01(tmp[0, ii]) ^ (int)gfMultby02(tmp[1, ii]) ^
                                            (int)gfMultby03(tmp[2, ii]) ^ (int)gfMultby01(tmp[3, ii]));
                Data[2, ii] = (byte)((int)gfMultby01(tmp[0, ii]) ^ (int)gfMultby01(tmp[1, ii]) ^
                                           (int)gfMultby02(tmp[2, ii]) ^ (int)gfMultby03(tmp[3, ii]));
                Data[3, ii] = (byte)((int)gfMultby03(tmp[0, ii]) ^ (int)gfMultby01(tmp[1, ii]) ^
                                           (int)gfMultby01(tmp[2, ii]) ^ (int)gfMultby02(tmp[3, ii]));
            }
            return Data;
        }
        public static byte[] Cipher(byte[] input, byte[] theKey)
        {
            byte[,] stat = new byte[4, 4];
            //initialize state with a block of input 
            for (int i = 0; i < 4 * NumberOfColumns; i++)
            {
                stat[i % 4, i / 4] = input[i];
            }
            byte[,] w = new byte[4, 4];

            for (int i = 0; i < 4 * NumberOfColumns; i++)
            {
                w[i % 4, i / 4] = theKey[i];
            }
            //initial round 
            stat = toAddRoundKey(stat, 0, w);
            byte[] roundkey = new byte[176];
            roundkey = keyExpansion(theKey);
            // apply 9 main rounds
            int index = 16;
            byte[,] x = new byte[4, 4];

            for (int i = 1; i < NumberOfRounds; i++)
            {
                stat = subBytes(stat);
                stat = shiftRows(stat);
                stat = mixColumns(stat);

                for (int f = 0; f < 4; f++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        x[j, f] = roundkey[index];
                        index++;
                    }
                }
                stat = toAddRoundKey(stat, i, x);
            }
            // final round 
            stat = subBytes(stat);
            stat = shiftRows(stat);

            for (int f = 0; f < 4; f++)
            {
                for (int j = 0; j < 4; j++)
                {
                    x[j, f] = roundkey[index];
                    index++;
                }
            }
            stat = toAddRoundKey(stat, NumberOfRounds, x);
            byte[] output = new byte[4 * NumberOfColumns];
            for (int i = 0; i < 4 * NumberOfColumns; i++)
            {
                output[i] = stat[i % 4, i / 4];
            }
            return output;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        public static byte[] keyExpansion(byte[] key)
        {
            byte[,] w = new byte[NumberOfColumns * (NumberOfRounds + 1), 4];
            byte[] temp = new byte[4];
            for (int i = 0; i < LenghtOfKey; i++)
            {
                w[i, 0] = key[4 * i];
                w[i, 1] = key[4 * i + 1];
                w[i, 2] = key[4 * i + 2];
                w[i, 3] = key[4 * i + 3];
            }
            for (int i = LenghtOfKey; i < (NumberOfColumns * (NumberOfRounds + 1)); i++)
            {
                for (int t = 0; t < 4; t++)
                    temp[t] = w[i - 1, t];
                if (i % LenghtOfKey == 0)
                {
                    temp = subWord(rotWord(temp));
                    for (int t = 0; t < 4; t++)
                        temp[t] = (byte)((int)temp[t] ^ (int)Rcon[i / LenghtOfKey, t]);
                }
                else if (LenghtOfKey > 6 && i % LenghtOfKey == 4)
                {
                    temp = subWord(temp);
                }
                for (int t = 0; t < 4; t++)
                    w[i, t] = (byte)((int)w[i - LenghtOfKey, t] ^ (int)temp[t]);
            }
            byte[] x = w.Cast<byte>().ToArray();
            return x;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="w"></param>
        /// <returns></returns>
        private static byte[] rotWord(byte[] w)
        {
            byte tmp;
            tmp = w[0];
            for (int i = 0; i < 3; i++)
                w[i] = w[i + 1];
            w[3] = tmp;
            return w;
        }
        /// <summary>
        /// 
        /// </summary>
        /// <param name="w"></param>
        /// <returns></returns>
        private static byte[] subWord(byte[] w)
        {
            byte[] result = new byte[4];
            for (int i = 0; i < 4; i++)
                result[i] = Sbox[w[i] >> 4, w[i] & 0x0f];
            return result;
        }
    }
}
