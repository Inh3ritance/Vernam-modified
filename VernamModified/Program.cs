using System;
using System.Text;
using System.Linq;
using System.Text.RegularExpressions;
using System.Collections;
using System.Security.Cryptography;

namespace VernamModified {
    class Program {

        // Assume Key is generated with a good unguessable seed...
        private static String privatekey = "5E08D364CE89FFADF5DA12A7E14D1C3B303F283A1F3D4A0A36C4621FCFF8048F160E0A7A35ADFF0B57D63BE63DF5AD94479A4684E440486863B49B4D2FE79A005E08D364CE89FFADF5DA12A7E14D1C3B303F283A1F3D4A0A36C4621FCFF8048F160E0A7A35ADFF0B57D63BE63DF5AD94479A4684E440486863B49B4D2FE79A005E08D364CE89FFADF5DA12A7E14D1C3B303F283A1F3D4A0A36C4621FCFF8048F160E0A7A35ADFF0B57D63BE63DF5AD94479A4684E440486863B49B4D2FE79A005E08D364CE89FFADF5DA12A7E14D1C3B303F283A1F3D4A0A36C4621FCFF8048F160E0A7A35ADFF0B57D63BE63DF5AD94479A4684E440486863B49B4D2FE79A00";
        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
        private static Random random = new Random();

        static void Main(string[] args) {
            privatekey = GenerateRandomCryptographicKey(384);
            Console.WriteLine(privatekey.Length);
            String private_key2 = "";
            private_key2 += shaToString(sha512(privatekey));
            while (privatekey.Length != private_key2.Length)
                private_key2 += shaToString(sha512(private_key2));
            //Console.WriteLine(private_key2.Length);

            // Prompt user String (Origianl message M1)
            Console.WriteLine("Vernam modified: Enter text to be encrypted.");
            string originalText = Console.ReadLine();
            if(originalText.Length < 512 - 8) {
                originalText += "/[EXT:";
                string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; // Prevent Hash Tables/Rainbows
                while (originalText.Length < 512-2)
                    originalText += chars[random.Next(chars.Length)];
                originalText += "]/";
            }
            //Console.WriteLine("Your input: " + originalText.Length);
            String hash = shaToString(sha512(originalText));
            //Console.WriteLine(hash);

            // IV, does not need to be kept secret, for CBC
            String IV = "";
            while (IV.Length < 512) {
                string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                IV += chars[random.Next(chars.Length)];
            }
            //Console.WriteLine("IV: " + IV)

            /* Encryption */

            BitArray message = convertStringToBits(originalText);
            //Console.WriteLine(message.Length);
            //PrintBits(message);

            // Convert private key to bit array
            Console.WriteLine("private key");
            BitArray encryptedbits = convertStringToBits(privatekey);
            //Console.WriteLine(encryptedbits.Length);
            //PrintBits(encryptedbits);

            // Convert private key 2 to bit array
            Console.WriteLine("private key 2");
            BitArray encryptedbits2 = convertStringToBits(private_key2);
            //Console.WriteLine(encryptedbits2.Length);
            //PrintBits(encryptedbits2);

            // Xor privatekey and message
            Console.WriteLine("data XOR w/private key");
            BitArray encr = message.Xor(encryptedbits);
            //Console.WriteLine(encr.Length);
            //PrintBits(encr);

            // Xor private key 2 and message
            Console.WriteLine("data XOR w/private key 2");
            encr = encr.Xor(encryptedbits2);
            //Console.WriteLine(encr.Length);
            //PrintBits(encr);

            /* Encryption Done */

            Console.WriteLine("Send: cipherText, MAC");

            /* Decryption */

            // Decrypt encrypted message with XOR w/ private key
            Console.WriteLine("Decrypting encryption");
            BitArray decr = encr.Xor(encryptedbits);
            // Console.WriteLine(decr.Length);
            // PrintBits(decr);

            // Decrypt encrypted message with XOR w/ private key 2
            Console.WriteLine("Decrypting encryption");
            decr = encr.Xor(encryptedbits2);
            // Console.WriteLine(decr.Length);
            // PrintBits(decr);

            /* Decryption Done */

            Console.WriteLine("Results:");
            String results = convertBitsToUTF8(decr);


            // Perform Regex
            string pattern = @"/\[EXT:.*\]/";
            Regex rep = new Regex(pattern);
            results = rep.Replace(results, "");

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

        static String GenerateRandomCryptographicKey(int keyLength) {
            RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            byte[] randomBytes = new byte[keyLength];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            return Convert.ToBase64String(randomBytes);
        }

    }
}
