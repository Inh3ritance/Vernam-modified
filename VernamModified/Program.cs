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
        private static Random random = new Random();

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
            Console.WriteLine("Encrypt/Decrypt");
            if(Console.ReadLine().Equals("E"))
                Encryption(privatekey,private_key2);
            else
                Decryption(privatekey, private_key2);
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

            // Convert M1 to bits 
            Console.WriteLine("Original Text");
            BitArray message = convertStringToBits(originalText);

            // Convert private key to bit array
            Console.WriteLine("private key");
            BitArray e1 = convertStringToBits(privatekey);

            // Convert private key 2 to bit array
            Console.WriteLine("private key 2");
            BitArray e2 = convertStringToBits(private_key2);

            // Xor privatekey and message
            Console.WriteLine("data XOR w/private key");
            BitArray c1 = message.Xor(e1);

            // Xor private key 2 and message
            Console.WriteLine("data XOR w/private key 2");
            c1 = c1.Xor(e2);

            String CipherText = convertBitsToUTF8(c1);

            // Hash Cipher Text
            String hash = shaToString(sha512(CipherText));

            // Generate new Key, convert to bits and Xor privatekey
            String gen_new_key = GenerateRandomCryptographicKey(384);
            BitArray new_key_bits = convertStringToBits(gen_new_key);
            String new_key = convertBitsToUTF8(new_key_bits.Xor(e1));

            // Replace current key with new key
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\" + client + "\\private.key", gen_new_key);

            // Hash new key
            String hashkey = shaToString(sha512(new_key));

            Send(CipherText, hash,new_key,hashkey);
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

            // Check for tampering, need to think about this more
            if (!shaToString(sha512(new_key)).Equals(hashKey)) {
                Console.WriteLine("There has been tampering with the hash or key, replace key with new one for authority RSA");
                return;
            } else if(!shaToString(sha512(cipherText)).Equals(hash)) {
                Console.WriteLine("There has been tampering with the ciphertext or the cipher hash, update key from ney key and ask to resend the message");
            }

            // If everything is good, setup
            BitArray e1 = convertStringToBits(privateKey);
            BitArray e2 = convertStringToBits(privateKey2);
            BitArray cipherBits = convertStringToBits(cipherText);

            // Decrypt encrypted message with XOR w/ private key
            Console.WriteLine("Decrypting encryption");
            BitArray decr = cipherBits.Xor(e1);

            // Decrypt encrypted message with XOR w/ private key 2
            Console.WriteLine("Decrypting encryption");
            decr = decr.Xor(e2);

            // get results
            Console.WriteLine("Results:");
            String results = convertBitsToUTF8(decr);

            // Perform Regex
            string pattern = @"/\[EXT:.*\]/";
            Regex rep = new Regex(pattern);
            results = rep.Replace(results, "");

            // Display results
            Console.WriteLine(results);
            // Update Key
            BitArray new_key_bits = convertStringToBits(new_key);
            String update_key = convertBitsToUTF8(new_key_bits.Xor(e1));

            // Replace current key with new key
            privatekey = update_key;
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\" + client + "\\private.key", privatekey);
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
