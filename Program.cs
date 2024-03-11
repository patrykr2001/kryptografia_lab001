using System;
using System.Text;
using System.Security.Cryptography;

namespace LAB01
{
    internal class Program
    {
        private static Aes aesAlgorithm = Aes.Create();
        
        public static void Main(string[] args)
        {
            Configure();
            
            Console.WriteLine("CBC padding oracle attack demo");
            Console.WriteLine("Maciej Halec 2024");
            Console.WriteLine("Tekst jawny:");

            var tekstJawny = Console.ReadLine() ?? "";
            Console.WriteLine(tekstJawny);

            Console.WriteLine("Szyfrogram:");
            var encrypted = Encrypt(tekstJawny);
            Console.WriteLine(Convert.ToBase64String(encrypted));

            var encryptedBlocks = PodzielNaBloki(encrypted);

            var ostatniBlokIndex = encryptedBlocks.Count - 1;
            var decrypted = DecryptBlock(encryptedBlocks[ostatniBlokIndex], encryptedBlocks[ostatniBlokIndex - 1]);
            //decrypted = RemovePadding(decrypted);
            var decryptedTekstJawny = Encoding.UTF8.GetString(decrypted, 0, decrypted.Length);
            Console.WriteLine(decryptedTekstJawny);
        }

        private static void Configure()
        {
            aesAlgorithm.BlockSize = 128; // 16 Bajtowe bloki (128b = 16B)
            aesAlgorithm.Mode = CipherMode.CBC;
            aesAlgorithm.Padding = PaddingMode.PKCS7;
        }

        private static byte[] Encrypt(string plaintext)
        {
            byte[] encrypted;

            var encryptor = aesAlgorithm.CreateEncryptor(aesAlgorithm.Key, aesAlgorithm.IV);

            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (var swEncrypt = new StreamWriter(csEncrypt))
                    {
                        swEncrypt.Write(plaintext);
                    }

                    encrypted = msEncrypt.ToArray();
                }
            }

            return encrypted;
        }

        private static List<byte[]> PodzielNaBloki(byte[] bytes)
        {
            var bloki = new List<byte[]>();

            for (var i = 0; i < bytes.Length; i += 16)
            {
                var blok = new byte[16];
                Array.Copy(bytes, i, blok, 0, 16);
                bloki.Add(blok);
            }
            
            return bloki;
        }

        private static byte[] DecryptBlock(byte[] blok, byte[] poprzedniBlok)
        {
            var decrypted = new byte[16];
            var zmienionyPoprzedni = new byte[16];

            for (var aktualnaPozycja = 15; aktualnaPozycja >= 0; --aktualnaPozycja)
            {
                var paddingDlugosc = 16 - aktualnaPozycja;

                for (var poz = 15; poz > aktualnaPozycja; --poz)
                {
                    zmienionyPoprzedni[poz] ^= (byte)((byte)(paddingDlugosc - 1) ^ (byte)paddingDlugosc);
                }

                var znaleziono = false;

                for (var v = 0; v <= 255; ++v)
                {
                    zmienionyPoprzedni[aktualnaPozycja] = (byte)v;

                    if (IsPaddingCorrect(ConcatenateByte(zmienionyPoprzedni, blok)))
                    {
                        znaleziono = true;
                        decrypted[aktualnaPozycja] = (byte)(poprzedniBlok[aktualnaPozycja] ^ (byte)paddingDlugosc ^ v);
                        break;
                    }
                }
                
                if (!znaleziono)
                {
                    throw new Exception("Nie możne deszyfrować!");
                }
            }

            return decrypted;
        }

        private static byte[] ConcatenateByte(byte[] first, byte[] second)
        {
            var result = new byte[first.Length + second.Length];

            first.CopyTo(result, 0);
            second.CopyTo(result, first.Length);

            return result;
        }

        private static bool IsPaddingCorrect(byte[] zaszyfrowanyTekst)
        {
            try
            {
                var decryptor = aesAlgorithm.CreateDecryptor(aesAlgorithm.Key, aesAlgorithm.IV);
                
                using (var msDecrypt = new MemoryStream(zaszyfrowanyTekst))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
            catch (CryptographicException)
            {
                return false;
            }

            return true;
        }

        private static byte[] RemovePadding(byte[] blok)
        {
            var paddingLength = blok[^1];

            if (paddingLength <= 1 && paddingLength >= blok.Length)
            {
                throw new Exception("Incorrect padding");
            }

            var contentLength = blok.Length - paddingLength;

            for (int i = blok.Length - 2; i >= contentLength; --i)
            {
                if (blok[i] != paddingLength)
                {
                    throw new Exception("Incorrect padding");
                }
            }

            var result = new byte[contentLength];

            Array.Copy(blok, 0, result, 0, contentLength);

            return result;
        }
    }
}