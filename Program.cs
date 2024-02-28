using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices.ComTypes;

namespace SymmetricalEncrypting
{
    internal class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                ////////////////////////////
                // Symmetrical Encrypting //
                ////////////////////////////

                // GUI Menu
                Console.WriteLine("1. AES (Advanced Encrypting Standard)");
                Console.WriteLine("2. DES (Data Encrypting Standard)");
                Console.WriteLine("3. Triple DES (3DES)");
                Console.WriteLine("4. AesGcm");
                Console.WriteLine("");

                // User input
                ConsoleKey selected = Console.ReadKey().Key;
                Console.WriteLine("");

                // Variables for User's Message and String Key
                string message;
                string strKey;

                // Switch User input
                switch (selected)
                {
                    case ConsoleKey.D1: // User Input 1 / AES
                        Console.WriteLine("Type your Message then Press enter:"); // User Types the Message they want to encrypt
                        message = Console.ReadLine(); // Gets User Input
                        EncryptWithAES(message);
                        break;
                    case ConsoleKey.D2: // User Input 2 / DES
                        Console.WriteLine("Type your Message then Press enter:"); // User Types the Message they want to encrypt
                        message = Console.ReadLine(); // Gets User Input
                        EncryptWithDES(message); // Encrypts and Decrypts the message with the Des algorithm, Then Print Results.
                        break;
                    case ConsoleKey.D3: // User Input 3 / 3DES
                        Console.WriteLine("Type your Message then Press enter:"); // User Types the Message they want to encrypt
                        message = Console.ReadLine(); // Gets User Input
                        Console.WriteLine("Type your SecretKey then Press enter:"); // User Types the string key
                        strKey = Console.ReadLine(); // Gets User Input
                        EncryptWith3DES(message, strKey);
                        break;
                    case ConsoleKey.D4: // User Input 4 / AesGcm
                        // 
                        //
                        //
                        //
                        break;
                    default:
                        Console.WriteLine($"Type:({selected.ToString()}) Not Allowed");
                        break;
                }

                Console.WriteLine("Press Enter to go back to start menu");
                Console.ReadLine();
                Console.Clear();
            }
        }

        // AesManaged
        private static void EncryptWithAES(string message)
        {
            try
            {
                // Check If Message is null or not
                if (String.IsNullOrEmpty(message))
                {
                    throw new ArgumentNullException
                           ("The string which needs to be encrypted can not be null.");
                }

                using (AesManaged aes = new AesManaged())
                {
                    // Encrypt string
                    byte[] encrypted = EncryptAes(message, aes.Key, aes.IV);

                    // Decrypt the bytes to a string.
                    string decrypted = DecryptAes(encrypted, aes.Key, aes.IV);

                    // Print Results
                    PrintResult(Encoding.UTF8.GetString(encrypted), decrypted, $"{Encoding.UTF8.GetString(aes.Key)}", $"{Encoding.UTF8.GetString(aes.IV)}");
                }
            }
            catch (Exception)
            {
                throw;
            }
        }
        private static byte[] EncryptAes(string plainText, byte[] Key, byte[] IV)
        {
            // The Example in Moodle Does not work, as AesGcm can't be used.
            // so followed a guide and other docs from the web.

            byte[] encrypted;
            // Create a new AesManaged.
            using (AesManaged aes = new AesManaged())
            {
                // Create encryptor
                ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);
                // Create MemoryStream
                using (MemoryStream ms = new MemoryStream())
                {
                    // Create crypto stream using the CryptoStream class. This class is the key to encryption
                    // and encrypts and decrypts data from any given stream. In this case, we will pass a memory stream
                    // to encrypt
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // Create StreamWriter and write data to a stream
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            // Return encrypted data
            return encrypted;
        }
        private static string DecryptAes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext;
            // Create AesManaged
            using (AesManaged aes = new AesManaged())
            {
                // Create a decryptor
                ICryptoTransform decryptor = aes.CreateDecryptor(Key, IV);
                // Create the streams used for decryption.
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    // Create crypto stream
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // Read crypto stream
                        using (StreamReader reader = new StreamReader(cs))
                            plaintext = reader.ReadToEnd();
                    }
                }
            }
            return plaintext;
        }

        private static void EncryptWithDES(string message)
        {
            try
            {
                // Check If Message is null or not
                if (String.IsNullOrEmpty(message))
                {
                    throw new ArgumentNullException
                           ("The string which needs to be encrypted can not be null.");
                }
                byte[] key;
                byte[] iv;

                using (DES des = DES.Create())
                {
                    key = des.Key;
                    iv = des.IV;
                }

                // Log Key and
                //Console.WriteLine(key.Length + " | " + key.ToString());
                //Console.WriteLine(iv.Length + " | " + iv.ToString());


                // Encrypt Message
                byte[] encryptedBytes = EncryptDes(message, key, iv);
                string encrypted = Encoding.UTF8.GetString(encryptedBytes);

                // Decrypt Message
                string decrypted = DecryptDes(encryptedBytes, key, iv);

                // Print Results
                PrintResult(encrypted, decrypted, Encoding.UTF8.GetString(key), Encoding.UTF8.GetString(iv));
            }
            catch (Exception)
            {
                throw;
            }
        }
        private static byte[] EncryptDes(string strData, byte[] key, byte[] iv)
        {
            try
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    using (DES des = DES.Create())
                    using (ICryptoTransform encrypter = des.CreateEncryptor(key, iv))
                    using (var cStream = new CryptoStream(ms, encrypter, CryptoStreamMode.Write))
                    {
                        byte[] messageBytes = Encoding.UTF8.GetBytes(strData);

                        cStream.Write(messageBytes, 0, messageBytes.Length);

                    }

                    byte[] encrypted = ms.ToArray();

                    return encrypted;
                }

                //DES des = DES.Create();

                //inputByteArray = Encoding.UTF8.GetBytes(strData);

                //MemoryStream ms = new MemoryStream();
                //CryptoStream cs = new CryptoStream(ms, des.CreateEncryptor(key, iv), CryptoStreamMode.Write);

                //cs.Write(inputByteArray, 0, inputByteArray.Length);
                //cs.FlushFinalBlock();

                //return Convert.ToBase64String(ms.ToArray()); //encrypted string
            }
            catch (Exception)
            {
                throw;
            }
        }
        // Error with Des Decrypt
        private static string DecryptDes(byte[] encrypted, byte[] key, byte[] iv)
        {
            try
            {
                // Create a buffer to hold the decrypted data.
                // DES-encrypted data will always be slightly bigger than the decrypted data.
                byte[] decrypted = new byte[encrypted.Length];
                int offset = 0;

                // Create a new MemoryStream using the provided array of encrypted data.
                using (MemoryStream mStream = new MemoryStream(encrypted))
                {
                    // Create a new DES object.
                    using (DES des = DES.Create())
                    // Create a DES decryptor from the key and IV
                    using (ICryptoTransform decryptor = des.CreateDecryptor(key, iv))
                    // Create a CryptoStream using the MemoryStream and decryptor
                    using (var cStream = new CryptoStream(mStream, decryptor, CryptoStreamMode.Read))
                    {
                        // Keep reading from the CryptoStream until it finishes (returns 0).
                        int read = 1;

                        while (read > 0)
                        {
                            read = cStream.Read(decrypted, offset, decrypted.Length - offset);
                            offset += read;
                        }
                    }
                }
                // Convert the buffer into a string and return it.
                return Encoding.UTF8.GetString(decrypted, 0, offset);

                //using (MemoryStream ms = new MemoryStream())
                //using (DES des = DES.Create())
                //using (ICryptoTransform decrypter = des.CreateDecryptor(key, iv))
                //using (var cStream = new CryptoStream(ms, decrypter, CryptoStreamMode.Write))
                //using (StreamReader reader = new StreamReader(cStream, Encoding.UTF8))
                //{
                //    return reader.ReadToEnd();
                //}


                //DES des = DES.Create();

                //inputByteArray = Convert.FromBase64String(strData);
                ////inputByteArray = Encoding.UTF8.GetBytes(strData);

                //MemoryStream ms = new MemoryStream();
                //CryptoStream cs = new CryptoStream(ms, des.CreateDecryptor(key, iv), CryptoStreamMode.Write);

                //cs.Write(inputByteArray, 0, inputByteArray.Length);
                //cs.FlushFinalBlock();

                //Encoding encoding = Encoding.UTF8;

                //return encoding.GetString(ms.ToArray());
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        // 3Des
        private static void EncryptWith3DES(string message, string strKey)
        {
            try
            {
                // Check If Message is null or not
                if (String.IsNullOrEmpty(message))
                {
                    throw new ArgumentNullException
                           ("The string which needs to be encrypted can not be null.");
                }

                // Encrypt Message
                string encrypted = Encrypt3Des(message, strKey);

                // Decrypt Message
                string decrypted = Decrypt3Des(encrypted, strKey);

                //Print Result
                PrintResult(encrypted, decrypted);

            }
            catch (Exception)
            {

                throw;
            }
        }
        private static string Encrypt3Des(string message, string strKey)
        {
            byte[] messageBytes = Encoding.UTF8.GetBytes(message); // Get message in bytes

            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();

            byte[] keyBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(strKey)); // Hash the bytes of the strKey

            md5.Clear(); // Release resorces used by the md5

            TripleDESCryptoServiceProvider tripleDes = new TripleDESCryptoServiceProvider();

            tripleDes.Key = keyBytes; // Set 3Des key
            tripleDes.Mode = CipherMode.ECB; // Set 3Des Mode
            tripleDes.Padding = PaddingMode.PKCS7; // Set 3Des Padding

            ICryptoTransform ct = tripleDes.CreateEncryptor();

            byte[] encrypted = ct.TransformFinalBlock(messageBytes, 0, messageBytes.Length);

            tripleDes.Clear();

            return Convert.ToBase64String(encrypted, 0, encrypted.Length); // Return Encrypted Message
        }
        private static string Decrypt3Des(string message, string strKey)
        {
            byte[] messageBytes = Convert.FromBase64String(message); // Change The encrypted message To a bytes array

            MD5CryptoServiceProvider md5 = new MD5CryptoServiceProvider();

            byte[] keyBytes = md5.ComputeHash(Encoding.UTF8.GetBytes(strKey)); // Hash the bytes of the strKey

            md5.Clear(); // Release resorces used by the md5

            TripleDESCryptoServiceProvider tripleDes = new TripleDESCryptoServiceProvider();

            tripleDes.Key = keyBytes; // Set 3Des key
            tripleDes.Mode = CipherMode.ECB; // Set 3Des Mode
            tripleDes.Padding = PaddingMode.PKCS7; // Set 3Des Padding

            ICryptoTransform ct = tripleDes.CreateDecryptor();

            byte[] decrypted = ct.TransformFinalBlock(messageBytes, 0, messageBytes.Length);

            tripleDes.Clear();

            return Encoding.UTF8.GetString(decrypted); // Return Decrypted Message
        }


        private static void PrintResult(string encrypted, string decrypted)
        {
            // Print Encrypted Message
            Console.WriteLine("Encrypted data: " + encrypted);

            // Print Decrypted Message
            Console.WriteLine("Decrypted data: " + decrypted);
        }

        private static void PrintResult(string encrypted, string decrypted, string key, string iv)
        {
            // Print Encrypted and Decrypted
            PrintResult(encrypted, decrypted);

            // Print Key
            Console.WriteLine("Key: " + key);

            // Print IV
            Console.WriteLine("IV: " + iv);

            // Skip a Line
            Console.WriteLine("");
        }
    }
}
