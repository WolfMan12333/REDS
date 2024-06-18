REDS - Ransomware Encryption/Decryption Simulation

I was working on it last time. Written in C++ with additional libraries from openssl.
Before I will continue description it is good to know that used libraries are added in properties
for the project and to make it work on your workstation you should probably change the paths to the 
libs.
Continue:
This simulation is doing those steps and depends on choice(encryption/decryption):
Encryption
1. generating random keys for each file in input/output folder
2. those keys are used to encrypt files with AES-256 algorithm
3. and those keys are stored in keys.txt file in input/output directory
4. content of keys.txt file is encrypted with RSA by using public key as variable
5. additionally is added a code with sending with POST metod the content of the keys.txt file to the
   web server(tested with python server, separate code written in python)

Decryption:
1. decrypting keys.txt content with private key
2. using keys stored in keys.txt to decrypt encrypted files.
