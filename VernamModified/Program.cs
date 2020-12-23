using System;
using System.Text;
using System.Linq;
using System.Text.RegularExpressions;
using System.Collections;
using System.Security.Cryptography;

namespace VernamModified {
    class Program {

        private static String privatekey = "5E08D364CE89FFADF5DA12A7E14D1C3B303F283A1F3D4A0A36C4621FCFF8048F160E0A7A35ADFF0B57D63BE63DF5AD94479A4684E440486863B49B4D2FE79A005E08D364CE89FFADF5DA12A7E14D1C3B303F283A1F3D4A0A36C4621FCFF8048F160E0A7A35ADFF0B57D63BE63DF5AD94479A4684E440486863B49B4D2FE79A005E08D364CE89FFADF5DA12A7E14D1C3B303F283A1F3D4A0A36C4621FCFF8048F160E0A7A35ADFF0B57D63BE63DF5AD94479A4684E440486863B49B4D2FE79A005E08D364CE89FFADF5DA12A7E14D1C3B303F283A1F3D4A0A36C4621FCFF8048F160E0A7A35ADFF0B57D63BE63DF5AD94479A4684E440486863B49B4D2FE79A00";

        static void Main(string[] args) {
            
            //Prompt user String
            Console.WriteLine("Vernam modified: Enter text to be encrypted.");
            string originalText = Console.ReadLine();
            Console.WriteLine("Your input: " + originalText);

            // Append Hash with String, convert to bit array
            Console.WriteLine("original String appended with hash");
            byte[] data = sha512(originalText);
            String hash = shaToString(data);
            originalText += hash;
            String hash_rep = hash;
            while (originalText.Length < privatekey.Length) {
                hash_rep = shaToString(sha512(hash_rep));
                originalText += hash_rep;
            }
            originalText = originalText.Substring(0, privatekey.Length);
            //Console.WriteLine(originalText.Length);
            //Console.WriteLine(privatekey.Length);
            BitArray message = convertStringToBits(originalText);
            //Console.WriteLine(message.Length);
            //PrintBits(message);

            // Convert private key to bit array
            Console.WriteLine("private key");
            BitArray encryptedbits = convertStringToBits(privatekey);
            //Console.WriteLine(encryptedbits.Length);
            //PrintBits(encryptedbits);

            // Xor privatekey and mesage
            Console.WriteLine("data XOR w/private key");
            BitArray encr = message.Xor(encryptedbits);
            //Console.WriteLine(encr.Length);
            //PrintBits(encr);

            // Decrypt encrypted message with XOR w/ priavte key
            Console.WriteLine("Decrypting encryption");
            BitArray decr = encr.Xor(encryptedbits);
            //Console.WriteLine(decr.Length);
            //PrintBits(decr);

            Console.WriteLine("Results:");
            String results = convertBitsToUTF8(decr);
            while (true) {
                if (results.Contains(hash)) {
                    results = results.Replace(hash, "");
                    hash = shaToString(sha512(hash));
                } else if (true) {
                    int i = 0;
                    if (results.Length > 128) {
                        string start,end = "";
                        start = results.Substring(0, results.Length - 128);
                        end = results.Substring(results.Length - 128, 128);
                        while (i < 128) {
                            bool rez = string.Equals(end.Substring(i, end.Length - i), (hash.Substring(0, hash.Length - i)));
                            if (rez) {
                                end = end.Substring(0,i);
                                break;
                            }
                            i++;
                        }
                        results = start + end;
                        break;
                    } else {
                        while (i < 128) {
                            bool rez = string.Equals(results.Substring(i, results.Length - i), (hash.Substring(0, hash.Length - i)));
                            if (rez) {
                                results = results.Substring(0, i);
                                break;
                            }
                            i++;
                        }
                        break;
                    }
                }
            }
            Console.WriteLine(results);
        }

        static byte[] sha512(String str) {
            using (SHA512 sha512Hash = SHA512.Create()) {
                byte[] sourceBytes = Encoding.UTF8.GetBytes(str);
                byte[] hashBytes = sha512Hash.ComputeHash(sourceBytes);
                return hashBytes;
            }
        }

        static String shaToString(byte[] bits) {
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bits.Length; i++)
                builder.Append(bits[i].ToString("x2"));
            return builder.ToString();
        }

        static byte[] getStringToBytes(String str) {
            return System.Text.Encoding.UTF8.GetBytes(str);
        }

        static BitArray convertStringToBits(String str) {
            byte[] bt = getStringToBytes(str);
            Array.Reverse(bt);
            BitArray bit = new BitArray(bt);
            return bit;
        }

        static void PrintBits(BitArray bit) {
            StringBuilder sb = new StringBuilder();
            for (int i = bit.Length - 1; i >= 0; i--){
                if (bit[i] == true)
                    sb.Append(1);
                else
                    sb.Append(0);
            }
            Console.WriteLine(sb.ToString());
        }

        static string convertBitsToString(BitArray bit) {
            StringBuilder sb = new StringBuilder();
            for (int i = bit.Length - 1; i >= 0; i--) {
                if (bit[i] == true)
                    sb.Append(1);
                else
                    sb.Append(0);
            }
            return sb.ToString();
        }

        static String convertBitsToUTF8(BitArray bits) {
          return Encoding.UTF8.GetString(Regex.Split(convertBitsToString(bits), "(.{8})")
              .Where(binary => !String.IsNullOrEmpty(binary))
              .Select(binary => Convert.ToByte(binary, 2))
              .ToArray());
        }

    }
}
