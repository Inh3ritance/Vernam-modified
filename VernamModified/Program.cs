using System;
using System.Text;
using System.Security.Cryptography;

namespace VernamModified {
    class Program {
        static void Main(string[] args) {
            Console.WriteLine("Vernam modified: Enter text to be encrypted.");
            string originalText = Console.ReadLine();
            Console.WriteLine("Your input: " + originalText);
            byte[] data = sha512(originalText);
            Console.WriteLine(data);
            Console.WriteLine(data.Length);
        }

        static byte[] sha512(String str) {
            byte[] hash;
            var data = Encoding.UTF8.GetBytes(str);
            using (SHA512 shaM = new SHA512Managed()) {
                hash = shaM.ComputeHash(data);
            }
            return hash;
        }
    }
}
