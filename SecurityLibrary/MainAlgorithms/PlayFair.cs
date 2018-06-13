using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        List<char> Alphapit = new List<char>();
        Char[,] keyMatrix = new Char[5, 5];

        public string Decrypt(string cipherText, string key)
        {
            string result = "";
            int IterationCounter = 0; // This Object To count number of characters performed from the KeyString
            for (int i = 65, j = 0; j < 26; i++, j++)
            {
                if (i == 74) continue; // To Neglect J from the Alphapit
                Alphapit.Add(Convert.ToChar(i));
            }

            string UpperKey = key.ToUpper();
            cipherText = cipherText.ToUpper();
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (IterationCounter < key.Length)
                    {
                        if (AvailableCharFromAlphapit(UpperKey[IterationCounter]))
                        {
                            keyMatrix[i, j] = UpperKey[IterationCounter];
                            ReplaceCharFromAlphapit(UpperKey[IterationCounter]); // replace the character with another one to avoid string lenth problem and avoid redundency of the character

                        }
                        else
                        {
                            j--;
                        }
                    }
                    else
                    {
                        keyMatrix[i, j] = ReturnFirstChar();
                    }
                    IterationCounter++;
                }
            }



            //------------------------//
            ////Now We Have The keyMatrix////
            //--------------------------//

            for (int i = 0; i < cipherText.Length; i = i + 2)
            {
                string secondCharPosition;

                // cipherText.Replace('J', 'I');

                if (cipherText[i] == cipherText[i + 1])
                {
                    secondCharPosition = GetCharPositionIn_KeyMatrix('X');

                }
                else
                {
                    secondCharPosition = GetCharPositionIn_KeyMatrix(cipherText[i + 1]);

                }
                string firstCharPosition = GetCharPositionIn_KeyMatrix(cipherText[i]);

                int firstCharRow = Convert.ToInt32(firstCharPosition[0]) - 48;
                int firstCharColumn = Convert.ToInt32(firstCharPosition[1]) - 48;

                int secondCharRow = Convert.ToInt32(secondCharPosition[0]) - 48;
                int secondCharColumn = Convert.ToInt32(secondCharPosition[1]) - 48;




                // Case Same Row 

                if (firstCharRow == secondCharRow)
                {
                    if (firstCharColumn > 0)
                    {
                        result += keyMatrix[firstCharRow, firstCharColumn - 1];
                    }
                    else
                    {
                        result += keyMatrix[firstCharRow, 4];

                    }

                    if (secondCharColumn > 0)
                    {
                        result += keyMatrix[secondCharRow, secondCharColumn - 1];
                    }
                    else
                    {
                        result += keyMatrix[secondCharRow, 4];

                    }
                }
                else
                    // Case Same Column
                    if (firstCharColumn == secondCharColumn)
                    {



                        if (firstCharRow > 0)
                        {
                            result += keyMatrix[firstCharRow - 1, firstCharColumn];
                        }
                        else
                        {
                            result += keyMatrix[4, firstCharColumn];

                        }

                        if (secondCharRow > 0)
                        {
                            result += keyMatrix[secondCharRow - 1, secondCharColumn];
                        }
                        else
                        {
                            result += keyMatrix[4, secondCharColumn];

                        }
                    }
                    else
                    {
                        //Case Rectangle
                        result += keyMatrix[firstCharRow, secondCharColumn];
                        result += keyMatrix[secondCharRow, firstCharColumn];

                    }

                if (cipherText[i] == cipherText[i + 1])
                {
                    i -= 1;

                }

                if (i + 2 > cipherText.Length)
                    break;
            }

            string finalResult = "";
            finalResult += result[0];

            for (int i = 1; i < result.Length - 1; i++)
            {
                if ((result[i - 1] == result[i + 1]) && (result[i] == 'X'))
                {

                }
                else
                    finalResult += result[i];
            }

            if (result[result.Length - 1] != 'X')
                finalResult += result[result.Length - 1];


            return finalResult;

        }




        public string Encrypt(string plainText, string key)
        {
            string result = "";
            int IterationCounter = 0; // This Object To count number of characters performed from the KeyString
            for (int i = 65, j = 0; j < 26; i++, j++)
            {
                if (i == 74) continue; // To Neglect J from the Alphapit
                Alphapit.Add(Convert.ToChar(i));
            }

            string UpperKey = key.ToUpper();
            plainText = plainText.ToUpper();
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (IterationCounter < key.Length)
                    {
                        if (AvailableCharFromAlphapit(UpperKey[IterationCounter]))
                        {
                            keyMatrix[i, j] = UpperKey[IterationCounter];
                            ReplaceCharFromAlphapit(UpperKey[IterationCounter]); // replace the character with another one to avoid string lenth problem and avoid redundency of the character

                        }
                        else
                        {
                            j--;
                        }
                    }
                    else
                    {
                        keyMatrix[i, j] = ReturnFirstChar();
                    }
                    IterationCounter++;
                }
            }



            //------------------------//
            ////Now We Have The keyMatrix////
            //--------------------------//

            for (int i = 0; i < plainText.Length; i = i + 2)
            {
                string secondCharPosition;

                plainText.Replace('J', 'I');

                if (plainText[i] == plainText[i + 1])
                {
                    secondCharPosition = GetCharPositionIn_KeyMatrix('X');

                }
                else
                {
                    secondCharPosition = GetCharPositionIn_KeyMatrix(plainText[i + 1]);

                }
                string firstCharPosition = GetCharPositionIn_KeyMatrix(plainText[i]);

                int firstCharRow = Convert.ToInt32(firstCharPosition[0]) - 48;
                int firstCharColumn = Convert.ToInt32(firstCharPosition[1]) - 48;

                int secondCharRow = Convert.ToInt32(secondCharPosition[0]) - 48;
                int secondCharColumn = Convert.ToInt32(secondCharPosition[1]) - 48;




                // Case Same Row 

                if (firstCharRow == secondCharRow)
                {
                    if (firstCharColumn < 4)
                    {
                        result += keyMatrix[firstCharRow, firstCharColumn + 1];
                    }
                    else
                    {
                        result += keyMatrix[firstCharRow, 0];

                    }

                    if (secondCharColumn < 4)
                    {
                        result += keyMatrix[secondCharRow, secondCharColumn + 1];
                    }
                    else
                    {
                        result += keyMatrix[secondCharRow, 0];

                    }
                }
                else
                    // Case Same Column
                    if (firstCharColumn == secondCharColumn)
                    {



                        if (firstCharRow < 4)
                        {
                            result += keyMatrix[firstCharRow + 1, firstCharColumn];
                        }
                        else
                        {
                            result += keyMatrix[0, firstCharColumn];

                        }

                        if (secondCharRow < 4)
                        {
                            result += keyMatrix[secondCharRow + 1, secondCharColumn];
                        }
                        else
                        {
                            result += keyMatrix[0, secondCharColumn];

                        }
                    }
                    else
                    {
                        //Case Rectangle
                        result += keyMatrix[firstCharRow, secondCharColumn];
                        result += keyMatrix[secondCharRow, firstCharColumn];

                    }

                if (plainText[i] == plainText[i + 1])
                {
                    i -= 1;

                }

                if (i + 2 > plainText.Length)
                    break;
            }




            //for (int i = 0; i < 5; i++)
            //{
            //    for (int j = 0; j < 5; j++)
            //        result += keyMatrix[i, j];
            //}
            return result;
        }

        //not required
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        // This Function Check if the Character is Available And return True else Character wasn't found
        bool AvailableCharFromAlphapit(Char DeletedChar)
        {
            for (int i = 0; i < Alphapit.Count; i++)
            {
                if (Alphapit[i] == DeletedChar)
                {

                    return true;
                }

            }
            return false;
        }

        // Replace Char with _
        void ReplaceCharFromAlphapit(Char DeletedChar)
        {
            for (int i = 0; i < Alphapit.Count; i++)
            {
                if (Alphapit[i] == DeletedChar)
                {

                    Alphapit[i] = '_';
                }

            }

        }


        char ReturnFirstChar()
        {
            char x = ' ';
            for (int i = 0; i < Alphapit.Count; i++)
            {
                if (Alphapit[i] != '_')
                {
                    x = Alphapit[i];
                    Alphapit[i] = '_';
                    return x;
                }
            }
            return x;
        }

        // This function to find Char in Key matrix
        string GetCharPositionIn_KeyMatrix(char x)
        {
            string result = "";

            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    if (keyMatrix[i, j] == x)
                    {
                        result += i.ToString();
                        result += j.ToString();
                        return result;
                    }
                }
            }

            return result;
        }
    }
}
