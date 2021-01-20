using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Net;
using System.Threading;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using System.Collections;
using System.Security.Cryptography;

namespace VernamModified {

    // State object for receiving data from remote device
    public class StateObject {
        public Socket workSocket = null;
        public const int BufferSize = 1024;
        public byte[] buffer = new byte[BufferSize];  
        public StringBuilder sb = new StringBuilder();
    }

    class Program {

        private static String privatekey;
        private static String client;

        // ManualResetEvent instances signal completion.  
        private static ManualResetEvent connectDone = new ManualResetEvent(false);
        private static ManualResetEvent sendDone = new ManualResetEvent(false);
        private static ManualResetEvent receiveDone = new ManualResetEvent(false);
        private static String response;

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

            // Ask if local or echoe server
            bool local = false;
            Console.WriteLine("Local?(Y/N)");
            if (Console.ReadLine().Equals("Y"))
                local = true;
            else
                local = false;

            //Ask user to Encrypt or Decrypt
            Console.WriteLine("Encrypt/Decrypt(E/D)");
            if (Console.ReadLine().Equals("E")) {
                Console.WriteLine("Text or File(T/F)");
                if (Console.ReadLine().Equals("T"))
                    Encryption(privatekey, private_key2, local);
                else
                    EncrCBC(privatekey, private_key2);
            } else {
                Console.WriteLine("Text/File(T/F)");
                if (Console.ReadLine().Equals("T"))
                    Decryption(privatekey, private_key2, local);
                else
                    DecrCBC(privatekey, private_key2);
            }
        }

        static byte[] sha512(String str) {
            using (SHA512 sha512Hash = SHA512.Create()) {
                byte[] sourceBytes = Encoding.UTF8.GetBytes(str);
                byte[] hashBytes = sha512Hash.ComputeHash(sourceBytes);
                return hashBytes;
            }
        }

        static String BytesToUTF16(byte[] bits) {
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

        static String convertBitsToUTF16(BitArray bits) {
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
            } else {
                privatekey = System.IO.File.ReadAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\" + client + "\\private.key");
            }
        }

        static String gen2ndKey() {
            String str = BytesToUTF16(sha512(privatekey));
            while (privatekey.Length != str.Length)
                str += BytesToUTF16(sha512(str));
            return str;
        }

        static String genMultKeys(String priv) {
            String str = BytesToUTF16(sha512(priv));
            while (privatekey.Length != str.Length)
                str += BytesToUTF16(sha512(str));
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

        static String conformOriginalFile(String str) {
            Random random = new Random();
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"; // Prevent Hash Tables/Rainbows
            str += "/[EXT:";
            if(str.Length % 512 == 0) 
                str += chars[random.Next(chars.Length)];
            while (str.Length % 512 != 510)
                str += chars[random.Next(chars.Length)];
            str += "]/";
            return str;
        }

        static void Encryption(String privatekey, String private_key2, bool local) {

            // Prompt user M1
            Console.WriteLine("Vernam modified: Enter text to be encrypted.");
            String originalText = conformOriginalText();

            // Hash Original Text
            String hash = BytesToUTF16(sha512(originalText));

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
            String CipherText = convertBitsToUTF16(c1);

            // Generate new Key, convert to bits and Xor privatekey
            String gen_new_key = GenerateRandomCryptographicKey(384);
            BitArray new_key_bits = convertStringToBits(gen_new_key);
            String new_key = convertBitsToUTF16(new_key_bits.Xor(e1));

            // Hash new key
            String hashkey = BytesToUTF16(sha512(gen_new_key));

            // Replace current key with new key
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\" + client + "\\private.key", gen_new_key);

            String[] data = new String[4];
            data[0] = CipherText;
            data[1] = hash;
            data[2] = new_key;
            data[3] = hashkey;
            if (local){
                Send(CipherText, hash, new_key, hashkey);
            } else {
                StartClient("send", data);
            }
            
        }

        static void Send(String CipherText, String hash, String new_key, String hashkey) {
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\Data\CipherText.txt", CipherText);
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\Data\CipherHash.txt", hash);
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\Data\NewKey.key", new_key);
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\Data\HashKey.txt", hashkey);
        }

        static void Decryption(String privateKey, String privateKey2, bool local) {

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
            String results = convertBitsToUTF16(decr);

            // Update Key
            BitArray new_key_bits = convertStringToBits(new_key);
            String update_key = convertBitsToUTF16(new_key_bits.Xor(e1));

            // Check for tampering
            if (!BytesToUTF16(sha512(update_key)).Equals(hashKey)){
                Console.WriteLine("There has been tampering with the hash or key, replace key with new one from authority RSA");
                return;
            } else if (!BytesToUTF16(sha512(results)).Equals(hash)) {
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

        static BitArray bytesToBits(byte[] arr) {
            Array.Reverse(arr);
            BitArray bit = new BitArray(arr);
            return bit;
        }

        static void EncrCBC(String privateKey, String privateKey2) {

            // Convert file to % 512 == 0
            Console.WriteLine("Vernam modified: Enter File to be Encrypted");
            string path = @"Image.PNG";
            byte[] arr = File.ReadAllBytes(path);
            String str = BytesToUTF16(arr);
            str = conformOriginalFile(str);

            // Hash file 
            String hash = BytesToUTF16(sha512(str));

            // Get key size == to file size
            String tempKey = privateKey2;
            while(privateKey2.Length < str.Length) {
                tempKey = genMultKeys(tempKey);
                privateKey2 += tempKey;
            }

            // Convert to bits
            BitArray key = convertStringToBits(privateKey);
            BitArray key2 = convertStringToBits(privateKey2);
            BitArray message = convertStringToBits(str);

            // XOR
            BitArray e1 = key2.Xor(message);

            // Cipher encryption
            String CipherFile = convertBitsToUTF16(e1);

            // Generate new Key, convert to bits and Xor privatekey
            String gen_new_key = GenerateRandomCryptographicKey(384);
            BitArray new_key_bits = convertStringToBits(gen_new_key);
            String new_key = convertBitsToUTF16(new_key_bits.Xor(key));

            // Hash new key
            String hashkey = BytesToUTF16(sha512(gen_new_key));

            // Replace current key with new key
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\" + client + "\\private.key", gen_new_key);

            Send(CipherFile, hash, new_key, hashkey);
        }

        static void DecrCBC(String privateKey, String privateKey2) {
            
            // Get our data
            String[] str = Read();
            String cipherText = str[0];
            String hash = str[1];
            String new_key = str[2];
            String hashKey = str[3];

            // Get key size == to file size
            String tempKey = privateKey2;
            while (privateKey2.Length < cipherText.Length) {
                tempKey = genMultKeys(tempKey);
                privateKey2 += tempKey;
            }

            // If everything is good, setup
            BitArray e1 = convertStringToBits(privateKey);
            BitArray e2 = convertStringToBits(privateKey2);
            BitArray cipherBits = convertStringToBits(cipherText);

            // Decrypt encrypted message with XOR w/ private key
            Console.WriteLine("Decrypting encryption");
            BitArray decr = cipherBits.Xor(e2);

            // Get results
            String results = convertBitsToUTF16(decr);

            // Update Key
            BitArray new_key_bits = convertStringToBits(new_key);
            String update_key = convertBitsToUTF16(new_key_bits.Xor(e1));

            // Check for tampering
            if (!BytesToUTF16(sha512(update_key)).Equals(hashKey)) {
                Console.WriteLine("There has been tampering with the hash or key, replace key with new one from authority RSA");
                return;
            } else if (!BytesToUTF16(sha512(results)).Equals(hash)) {
                Console.WriteLine("There has been tampering with the ciphertext or the cipher hash, update key from new key and ask to resend the message");
            }

            // Perform Regex
            string pattern = @"/\[EXT:.*\]/";
            Regex rep = new Regex(pattern);
            results = rep.Replace(results, "");

            // Display File results
            String path = @"DecryptedImage.PNG";
            File.WriteAllBytes(path, getStringToBytes(results));

            // Replace current key with new key
            System.IO.File.WriteAllText(@"C:\Users\marcos\Documents\GitHub\Vernam-modified\" + client + "\\private.key", update_key);
        }

        /* Start of TCP functions */
        private static void StartClient(String action, String[] data) {
            IPHostEntry ipHostInfo = Dns.GetHostEntry(Dns.GetHostName());
            IPAddress ipAddressA = ipHostInfo.AddressList[0];
            IPEndPoint remoteEPA = new IPEndPoint(ipAddressA, 11000);
            Socket clientA = new Socket(ipAddressA.AddressFamily, SocketType.Stream, ProtocolType.Tcp);  
            for (int i = 0; i < 4; i++)
            if (action == "send") {
                try {
                    Send(clientA, data[i] + "<EOF>");
                    sendDone.WaitOne();
                } catch (Exception e) {
                    Console.WriteLine(e.ToString());
                }
            } else if(action == "recieve") {
                try {
                    Receive(clientA);
                    sendDone.WaitOne();
                } catch (Exception e) {
                    Console.WriteLine(e.ToString());
                }
            }
            clientA.Shutdown(SocketShutdown.Both);
            clientA.Close();
        }

        private static void ConnectCallback(IAsyncResult ar) {
            try {
                Socket client = (Socket)ar.AsyncState;  
                client.EndConnect(ar);
                Console.WriteLine("Socket connected to {0}", client.RemoteEndPoint.ToString());
                connectDone.Set();
            } catch (Exception e) {
                Console.WriteLine(e.ToString());
            }
        }

        private static void Receive(Socket client) {
            try { 
                StateObject state = new StateObject();
                state.workSocket = client;  
                client.BeginReceive(state.buffer, 0, StateObject.BufferSize, 0, new AsyncCallback(ReceiveCallback), state);
            } catch (Exception e) {
                Console.WriteLine(e.ToString());
            }
        }

        private static void ReceiveCallback(IAsyncResult ar) {
            try {
                StateObject state = (StateObject)ar.AsyncState;
                Socket client = state.workSocket;
                int bytesRead = client.EndReceive(ar);
                if (bytesRead > 0) { 
                    state.sb.Append(Encoding.ASCII.GetString(state.buffer, 0, bytesRead));  
                    client.BeginReceive(state.buffer, 0, StateObject.BufferSize, 0, new AsyncCallback(ReceiveCallback), state);
                } else {
                    if (state.sb.Length > 1)
                        response = state.sb.ToString();  
                    receiveDone.Set();
                }
            } catch (Exception e) {
                Console.WriteLine(e.ToString());
            }
        }

        private static void Send(Socket client, String data) {
            byte[] byteData = Encoding.ASCII.GetBytes(data);
            client.BeginSend(byteData, 0, byteData.Length, 0, new AsyncCallback(SendCallback), client);
        }

        private static void SendCallback(IAsyncResult ar) {
            try {
                Socket client = (Socket)ar.AsyncState; 
                int bytesSent = client.EndSend(ar);
                Console.WriteLine("Sent {0} bytes to server.", bytesSent);
                sendDone.Set();
            } catch (Exception e) {
                Console.WriteLine(e.ToString());
            }
        }
        /* End of TCP functions*/

    }
}
