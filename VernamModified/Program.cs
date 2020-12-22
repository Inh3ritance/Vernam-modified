using System;
using System.Text;
using System.Security.Cryptography;

namespace VernamModified {
    class Program {

        private static String privatekey = "C224575EBA1E0B2778C603796199AEFC2972B160862B9AB603A9AC7329F95A16E91D713A1DA737D15348E943F0BE9B65D505EF14AF19DA7B16F692DC1BC3A815";

        static void Main(string[] args) {
            Console.WriteLine("Vernam modified: Enter text to be encrypted.");
            string originalText = Console.ReadLine();
            Console.WriteLine("Your input: " + originalText);

            Console.WriteLine("original String appended with hash");
            byte[] data = sha512(originalText);
            originalText += getBytesToString(data);
            Console.WriteLine(originalText);

            Console.WriteLine("data XOR w/priavte key");
            byte[] encr = XOR(getStringToBytes(originalText),getStringToBytes(privatekey));
            String encr_string = getBytesToString(encr);
            Console.WriteLine(encr_string);

            //byte[] decr = XOR(getStringToBytes(encr_string), getStringToBytes(privatekey));
            //Console.WriteLine(getBytesToString(decr));
        }

        static byte[] sha512(String str) {
            byte[] hash;
            var data = Encoding.UTF8.GetBytes(str);
            using (SHA512 shaM = new SHA512Managed()) {
                hash = shaM.ComputeHash(data);
            }
            return hash;
        }

        static byte[] getStringToBytes(String str) {
            return Encoding.UTF8.GetBytes(str);
        }

        static String getBytesToString(byte[] bits) {
            return System.Text.Encoding.UTF8.GetString(bits, 0, bits.Length);
        }

        static byte[] XOR(byte[] buffer1, byte[] buffer2) {
            for (int i = 0; i < buffer1.Length; i++)
                buffer1[i] ^= buffer2[i];
            return buffer1;
        }
    }
}
