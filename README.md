# Vernam-modified
The <b>Vernam Cipher</b> modification allows the unbreakableness of the <b>OTP(One Time Pad)</b> properties with the practicality of key resuse, and salting. 
The program works utilizing File inventory at the moment but soon to TCP/UDP connections. This is very similair to AES Procedures.

Algorithm:

Hashes: Sha-512

Encry: XOR

Decr: XOR

Assume both parties secrurely have the same Private Key Key<sub>1</sub>

<h2>Sender Side:</h2>

input = RAW TEXT

Message M1 = (input) size: (514 char. Length) (Last <b>128</b>/64/32/8 characters reserved for Salt).

IF M1 < 384, fill with Salt.

Key<sub>1 priv.</sub> = Shared key, must be securely trasferred. (512 char. Length).

Hash<sub>1</sub> = Hash(Key<sub>1</sub>). (128 char. Length).

Hash<sub>2</sub> = Hash(Hash<sub>1</sub>). (128 char. Length).

Hash<sub>3</sub> = Hash(Hash<sub>2</sub>). (128 char. Length).

Hash<sub>4</sub> = Hash(Hash<sub>3</sub>). (128 char. Length).

Key<sub>2 priv.</sub> = Hash<sub>1</sub> + Hash<sub>2</sub> + Hash<sub>3</sub> + Hash<sub>4</sub>. (512 char. Length).

Authentication A<sub>1</sub> = Hash<sub>A1</sub>(M1). (128 char. Length).

Cipher Text CT = Key<sub>2</sub> ⊕ M1. (512 char. Length).

Key<sub>new</sub> = CSPRNG|TRNG. (514 char. Length).

Authentication A<sub>2</sub> = Hash(Key<sub>new</sub>). (512 char. Length).

Key<sub>Secret</sub> = Key<sub>1</sub> ⊕ Key<sub>new</sub>. (512 char. Length).

Discard Key<sub>1</sub> and replace with Key<sub>new</sub>.

Key<sub>1</sub> <- Key<sub>new</sub>.

SEND(CT, A<sub>1</sub>, Key<sub>Secret</sub>, A<sub>2</sub>).


<h2>Reciever Side:</h2>

RECIEVE(CT, A<sub>1</sub>, Key<sub>Secret</sub>, A<sub>2</sub>).

Decrypted Message M<sub>Decr</sub> = CT ⊕ Key<sub>2</sub>. (512 char. Length).

Authentication A<sub>3</sub> = Hash(M<sub>Decr</sub>). (128 char. Length).

IF A<sub>3</sub> == A<sub>1</sub>, Valid, else tamperment update Key.

Original Text OT = Parse Salt from M1. (input Length).

Key<sub>Update</sub> = Key<sub>1</sub> ⊕ Key<sub>Secret</sub>. (512 char. Length).

Authentication A<sub>4</sub> = Hash(Key<sub>Upadate</sub>). (128 char. Length).

IF A<sub>4</sub> == A<sub>2</sub>, Valid, Reject key and DO NOT UPDATE, need to re-establish private key again.

Key<sub>1</sub> <- Key<sub>Update</sub>

END.

<h2>Vulnerabilities:</h2>

Given that the Key Generation is not likely to be 'Truly Random' a seed may be found. But a Cryptographically Secure Random Number Generator(CSRNG) 
may do for now until a setup for a True RNG is made.

Sadly if the attacker manages to break into the server and change the bits of the key hash or secret key, then you will have to re-establish a 
secure communication again resseting both parties private keys, having to meet in person, online, text, RSA or whatever you feel comftorable sending the initial 
private key... again. Does not mean the attacker wins by figuring out the message, but more like the attacker wins by being a nusaince having to break your 
convenience.

<h2>Notes*: </h2>

At the moment we follow 3/4 rules of a (OTP):

1.The key must be truly random. ❌

2.The key must be at least as long as the plaintext. ✔
    
3.The key must never be reused in whole or in part. ✔
    
4.The key must be kept completely secret. ✔

(1) This is a long standing issue of cryptography in general, it does not mean this cryptographic algorithm is weak because it does not fulfill this requirement,
but we cannot consider it unbreakable if it can be generated from computer code. A setup for envirormental randomness detection can be setup to achieve True 
Randomness fulfilling this requirement, at the moment I am only using code to generate the key. 

(2) Because the encryption is based on a fixed key size it is considered as block encryption. We can handle and achieve larger files by breaking the bits into blocks 
and smaller files by padding them. At the moment there is no Cipher Block Chaining but it is being tested and created as we speak. We could also lazilily create 
a GB key file and use that, the XOR operation would still be fast enough to accomplish it but a linearly large file size would linearly scale the time needed for XOR
operations as well, very naive approach.

(3) This is the bread and butter of the algorithm as the Vernam Cipher Pad can only be used once, then destroyed to prevent chosen plaintext and chosen ciphertext 
attacks. Reuse of the key potentially compromises the whole key. The modification made here is that we can actually use the key twice without ever letting the 
attacker know what the private key is. The private key is used in 2 seperate paths, one involving the setup for the new private key and one for setting up the Cipher 
Text. You may wonder <i>"how does this not break the One Time Pad, are we not only suppose to use the private key once?"</i> And you would be right, except that we 
may not use the Pad twice, not the private key. The pad is unique and still being used once, the pad is generated by a 2nd private key and a Message, the 2nd private 
key is a sum of hashes from the original private key. We can gaurantee this is safe and unique because unless the attacker knew what the private key was, then he 
could get the hashes for the 2nd private key. But the only way to get the private key is to brute force a seed and try 1 out of 2^(1024) possibilites of getting it 
right. By that time you will have already exchanged to the new key. So, we use the (OTP) once but the private key twice, theoretically speaking if we did use the (OTP) twice the attacker would be able to guess and decrypt future messages with the pad, but the attacker would still never be able to deduce the private key. Now we have peace of mind of using the original private key, and setup a new key disposing of the previouse one, allowing us to 
have seamless comunication without having to A) physically meet in person to exchange the key every time and B) trust your communication source such as email, text,
or whatever secure setup you may think you have repeatedly. Both parties will update there private key after every new send/recieve transaction thus rule 3 is not 
broken.

(4) Because the algorithm uses a secure pseudo random generator it can only get you so far at the moment, but no attacker will bother with such a computationally 
strennous task which gets updated anyways. Now, depending on how you store the key, in a DB, localStorage, FileSystems, is a client side responsibility for 
maintaining this aspect of (OTP). It is reccomended to have a Master key to encrypt your private keys from invaders that access your computer files.
