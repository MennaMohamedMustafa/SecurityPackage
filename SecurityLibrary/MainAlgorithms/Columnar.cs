using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int Columns = key.Count; // num of columns 
            int Remainder = -1;
            int Rows = cipherText.Length / Columns; // num of rows         
            Remainder = cipherText.Length % Columns;
            if (Remainder > 0)
            {
                Rows++;
            }
            while ((Rows * Columns) > cipherText.Length)
            {
                cipherText += "x";
            }
            char[,] matrix = new char[Columns, Rows];
            int count = 0;
            string PT = "";
            var k = key.ToArray();
            // hena bmshy colums wise 
            for (int i = 0; i < Columns; i++)
            {
                var ColumnIndex = Array.FindIndex(k, row => row.Equals(i + 1)); // ba5od el key w artb beha bel key 
                for (int j = 0; j < Rows; j++)
                {
                    matrix[ColumnIndex, j] = cipherText[count];
                    count++;
                }
            }
            // row wise 
            for (int i = 0; i < Rows; i++)
            {
                for (int j = 0; j < Columns; j++)
                {
                    PT += matrix[j, i];
                }
            }
            return PT.ToUpper();
        }

        public string Encrypt(string plainText, List<int> key)
        {

            {
                int Columns = key.Count; // num of columns 
                int Remainder = -1;
                int Rows = plainText.Length / Columns; // num of rows         
                Remainder = plainText.Length % Columns;
                if (Remainder > 0)
                {
                    Rows++;
                }
                while ((Rows * Columns) > plainText.Length)
                {
                    plainText += "x";
                }
                char[,] matrix = new char[Columns, Rows];
                int count = 0;
                string CT = "";
                // row wise 
                for (int i = 0; i < Rows; i++)
                {
                    for (int j = 0; j < Columns; j++)
                    {
                        matrix[j, i] = plainText[count];
                        count++;
                    }
                }

                char[,] outmatrix = new char[Columns, Rows];
                var k = key.ToArray();
                // column wise 
                for (int i = 0; i < Columns; i++)
                {
                    var ColumnIndex = Array.FindIndex(k, row => row.Equals(i + 1));

                    for (int j = 0; j < Rows; j++)
                    {
                        outmatrix[i, j] = matrix[ColumnIndex, j];
                        CT += outmatrix[i, j];
                    }
                }
                return CT.ToUpper();
            }
        }
    }
}
