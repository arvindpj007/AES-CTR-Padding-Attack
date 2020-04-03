# AES CTR Padding Attack
> Golang programs for Padding Oracle attack on AES-CTR mode that uses HMAC with checksum

1. `encrypt-auth-chk` contains `main.go` program to perform AES encryption in CTR mode with HMAC. Here the AES function is used from the standard package, but the CTR mode encryption and checksum calculations are performed in program. 

    The checksum works as follows: 

    On input a message M, first parse M into a sequence of octets M1, . . . , Mn. Then checksum 
    
    T = sum(M_i mod 256) for i= 1 to n
    
    To build the binary, the following command can be performed:
            
        go build
    The encryption/decryption can be performed with the following command:

        ./encrypt <mode> -k <16-byte key in hexadecimal> -i <input file> -o <output file>
    mode = `encrypt` or `decrypt`

2. `decrypt-test-chk` contains `main.go` program that works like the oracle. The program `./decrypt-test-chk` that has the key K hardcoded into it. It performs decryption of the provided cipher text and it will not return the decrypted ciphertext, but instead only a single one of the following three response messages:
    1. “SUCCESS”
    3. “INVALID MAC”

    The command-line profile for decrypt-test will be as follows:

        ./decrypt-test-chk -i <ciphertext file>

3. `decrypt-attack-chk` contains `main.go` program that performs the padding oracle attack. The program takes a cipher text as the input programmatically decrypts and returns the plain text of any ciphertext produced by your encryption utility from `encrypt-auth-chk` with the help of `./decrypt-test-chk`. It will not have access to a decrypt-key. The command-line profile for decrypt-test will be as follows:

        ./decrypt-attack-chk -i <ciphertext file>

> Golang programs for Padding Oracle attack on AES-CTR mode that uses HMAC with CRC32

1. `encrypt-auth-crc` contains `main.go` program to perform AES encryption in CTR mode with HMAC. Here the AES and CRC32 function is used from the standard package, but the CTR mode encryption calculation is performed in program. 

    To build the binary, the following command can be performed:
            
        go build
    The encryption/decryption can be performed with the following command:

        ./encrypt <mode> -k <16-byte key in hexadecimal> -i <input file> -o <output file>
    mode = `encrypt` or `decrypt`

2. `decrypt-test-crc` contains `main.go` program that works like the oracle. The program `./decrypt-test-crc` that has the key K hardcoded into it. It performs decryption of the provided cipher text and it will not return the decrypted ciphertext, but instead only a single one of the following three response messages:
    1. “SUCCESS”
    3. “INVALID MAC”

    The command-line profile for decrypt-test will be as follows:

        ./decrypt-test-crc -i <ciphertext file>

3. `decrypt-attack-crc` contains `main.go` program that performs the padding oracle attack. The program takes a cipher text as the input programmatically decrypts and returns the plain text of any ciphertext produced by your encryption utility from `encrypt-auth-crc` with the help of `./decrypt-test-crc`. It will not have access to a decrypt-key. The command-line profile for decrypt-test will be as follows:

        ./decrypt-attack-crc -i <ciphertext file>
