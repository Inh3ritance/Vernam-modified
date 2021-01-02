using System;
using System.Text;
using System.Linq;
using System.Text.RegularExpressions;
using System.Collections;
using System.Security.Cryptography;

namespace VernamModified {
    class Program {

        private static String privatekey;
        private static String client;

        static void Main(string[] args) {

            //ASK if client A or B
            Console.WriteLine("Are you client A or B (A/B)");
            if (Console.ReadLine().Equals("A"))
                client = "ClientA";
            else
                client = "ClientB";
          
            // Recieved from RSA intially, store locally after initializing key
            retrieveKeyFromFile();
            // Generate 2nd private key from 1st private key
            String private_key2 = gen2ndKey();

            //Ask user to Encrypt or Decrypt
            Console.WriteLine("Encrypt/Decrypt(E/D)");
            if (Console.ReadLine().Equals("E")) {
                Console.WriteLine("Text or File(T/F)");
                if (Console.ReadLine().Equals("T"))
                    Encryption(privatekey, private_key2);
                else
                    Console.WriteLine("CBC Encryption");
            } else {
                Console.WriteLine("Encrypt/Decrypt(E/D)");
                if (false /* check if image is present for decryption */) {
                    Console.WriteLine("soon");
                } else {
                    Decryption(privatekey, private_key2);
                }
            }
               
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

        static void retrieveKeyFromFile(){
            if (System.IO.File.ReadAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\" + client + "\\private.key").Length == 0) {
                privatekey = GenerateRandomCryptographicKey(384);
                System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\" + client + "\\private.key", privatekey);
                // Share with RSA
            } else {
                privatekey = System.IO.File.ReadAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\" + client + "\\private.key");
            }
        }

        static String gen2ndKey() {
            String str = shaToString(sha512(privatekey));
            while (privatekey.Length != str.Length)
                str += shaToString(sha512(str));
            return str;
        }

        static String conformOriginalText(){
            Random random = new Random();
            String str = Console.ReadLine();
            if (str.Length < 512 - 8) {
                str += "/[EXT:";
                string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; // Prevent Hash Tables/Rainbows
                while (str.Length < 512 - 2)
                    str += chars[random.Next(chars.Length)];
                str += "]/";
            }
            return str;
        }

        static void Encryption(String privatekey, String private_key2) {

            // Prompt user M1
            Console.WriteLine("Vernam modified: Enter text to be encrypted.");
            String originalText = conformOriginalText();

            // Hash Original Text
            String hash = shaToString(sha512(originalText));

            // Convert M1 to bits 
            Console.WriteLine("Original Text");
            BitArray message = convertStringToBits(originalText);

            // Convert private key to bit array
            Console.WriteLine("private key");
            BitArray e1 = convertStringToBits(privatekey);

            // Convert private key 2 to bit array
            Console.WriteLine("private key 2");
            BitArray e2 = convertStringToBits(private_key2);

            // Xor private key 2 and message
            Console.WriteLine("data XOR w/private key 2");
            BitArray c1 = message.Xor(e2);

            // Get Cipher text
            String CipherText = convertBitsToUTF8(c1);

            // Generate new Key, convert to bits and Xor privatekey
            String gen_new_key = GenerateRandomCryptographicKey(384);
            BitArray new_key_bits = convertStringToBits(gen_new_key);
            String new_key = convertBitsToUTF8(new_key_bits.Xor(e1));

            // Hash new key
            String hashkey = shaToString(sha512(gen_new_key));

            // Replace current key with new key
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\" + client + "\\private.key", gen_new_key);

            Send(CipherText, hash, new_key, hashkey);
        }

        // Will replace with TCP
        static void Send(String CipherText, String hash, String new_key, String hashkey) {
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\Data\CipherText.txt", CipherText);
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\Data\CipherHash.txt", hash);
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\Data\NewKey.key", new_key);
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\Data\HashKey.txt", hashkey);
        }

        static void Decryption(String privateKey, String privateKey2) {

            String[] str = Read();
            String cipherText = str[0];
            String hash = str[1];
            String new_key = str[2];
            String hashKey = str[3];

            // If everything is good, setup
            BitArray e1 = convertStringToBits(privateKey);
            BitArray e2 = convertStringToBits(privateKey2);
            BitArray cipherBits = convertStringToBits(cipherText);

            // Decrypt encrypted message with XOR w/ private key
            Console.WriteLine("Decrypting encryption");
            BitArray decr = cipherBits.Xor(e2);

            // Get results
            Console.WriteLine("Results:");
            String results = convertBitsToUTF8(decr);

            // Update Key
            BitArray new_key_bits = convertStringToBits(new_key);
            String update_key = convertBitsToUTF8(new_key_bits.Xor(e1));

            // Check for tampering
            if (!shaToString(sha512(update_key)).Equals(hashKey)){
                Console.WriteLine("There has been tampering with the hash or key, replace key with new one from authority RSA");
                return;
            } else if (!shaToString(sha512(results)).Equals(hash)) {
                Console.WriteLine("There has been tampering with the ciphertext or the cipher hash, update key from new key and ask to resend the message");
            }

            // Perform Regex
            string pattern = @"/\[EXT:.*\]/";
            Regex rep = new Regex(pattern);
            results = rep.Replace(results, "");

            // Display results
            Console.WriteLine(results);

            // Replace current key with new key
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\" + client + "\\private.key", update_key);
        }

        static String[] Read() {
            String[] str = new String[4];
            str[0] = System.IO.File.ReadAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\Data\CipherText.txt");
            str[1] = System.IO.File.ReadAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\Data\CipherHash.txt");
            str[2] = System.Text.Encoding.UTF8.GetString(System.IO.File.ReadAllBytes(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\Data\NewKey.key"));
            str[3] = System.IO.File.ReadAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\Data\HashKey.txt");
            return str;
        }
    }
}
