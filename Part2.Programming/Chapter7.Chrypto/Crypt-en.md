# 7. Cryptographic algorithm

This chapter introduces sample programs for various cryptographic algorithms.

### Common wrapper
The programs in this chapter provide a main function that acts as a common wrapper so that it acts as a command. Its contents are stored in common / cipher_main.c. The main function in cipher_main.c checks and parses a series of arguments and calls the cipher_main function.
The cipher_main function is a separate function for each algorithm sample. This wrapper allows individual algorithm functions to do only the specific processing for the algorithm.

Commands using this wrapper function accept the following arguments.

- First argument: Input file name
- Second argument: Output file name (optional)

The following optional arguments:
- -e: Encryption process
- -d: Decryption process
- -k: Specify hexadecimal key value in the next argument
- -i: Specify hexadecimal IV value in the next argument
- -t: Specify hexadecimal tag value in the next argument

As a wrapper, pass the mode indicated by -e, -d, and the hexadecimal value of any length specified by -k, -i, -t to cipher_main.
Check each cipher_main for proper size.
The need for option arguments is determined within the algorithm's individual processing.

The cipher_main function is defined in cipher_main.h as follows: The main function in cipher_main.c inherits the analysis contents of the argument to the argument of the cipher_main function.

```
void cipher_main (int mode, FILE * infp, int sz, FILE * outfp,
                 unsigned char * key, int key_sz,
                 unsigned char * iv, int iv_sz,
                 unsigned char * tag, int tag_sz
                );
```

### Buffer size
The cryptographic API used in the sample can process at once with a buffer as large as the memory size allows, but the buffer size is intentionally shown to show an example of processing large size data by repeating small processing units. Is restricted. The definition of "#define BUFF_SIZE" near the beginning of the source code of each algorithm can be changed as appropriate.


# 7.1 Random
    RAND_bytes ();
    RAND_pseudo_bytes ();
    
# 7.2 Hash

    SHA256_Init ();
    while (fread (stdin)) {
        SHA256_Update ();
    }
    SHA256_Final ();
    fwrite (stdout);

# 7.3 MAC

    HMAC_Init_ex ();
    while (fread (stdin)) {
        HMAC_Update ();
    }
    HMAC_Final ();
    fwrite (stdout);

# 7.4 Common key cryptography

OpenSSL / wolfSSL provides a set of functions starting with "EVP" for processing symmetric key cryptography. This section describes the general rules for this EVP function and examples of symmetric key cryptography programs that use it.

## 1) Overall flow

At the beginning of processing, the "CTX_new" function allocates a management block for managing the processing context. Next, use the "Init" function to set parameters such as the key and IV for the context secured by the initialization function.

The encryption / decryption process is performed by the "Update" function. Processing is performed on the input buffer in memory and output to the output buffer. If the memory size limit allows, the entire input data can be passed to the "Update" function at once, but if there is a limit, the "Update" function can be called multiple times by dividing it into appropriate sizes. increase. At that time, you can specify an appropriate processing size without worrying about the block size of the block type encryption. For this reason, it is necessary to process the padding for odd data by the "Final" function at the end.

Finally, release the management block after completion.


## 2) Sample program

The following is a sample program that realizes common key cryptographic processing using the EVP function in the dynamic mode. Various cipher algorithms and usage modes can be processed by changing the definition of the "CIPHER" constant. (Refer to "6) Cryptographic algorithm, usage mode" for the cipher suites that can be specified.)

See Examples / 2.Chrypto / sym / aes-cbc.c for working sample code. This program accepts the following command rules.


- Input file: Uses the file with the specified file name as input data. <br>
- Output file: Outputs the result data to the file with the specified file name. If omitted, output to standard output. <br>

- "-e" specifies encryption, "-d" specifies compound. If not specified, encryption processing will be performed. <br>
- Specify the key value in hexadecimal in the next argument after "-k". <br>
- Specify the IV value in hexadecimal in the next argument after "-i". <br>
<br> <br> <br>

```
#define CIPHER EVP_aes_128 | CBC ()

    Command argument processing

    evp = EVP_CIPHER_CTX_new (); / * Secure context * /
    EVP_CipherInit (evp, CIPHER, key, iv, mode); / * Algorithm, key, IV, mode setting * /

    while (1) {
        inl = fread(in, 1, BUFF_SIZE, stdin));
        if(inl < BUFF_SIZE) break;
        EVP_CipherUpdate(evp, out, &outl, in, inl); /*　暗号、復号 */
        fwrite(out, 1, outl, outfp);
    }
    EVP_CipherFinal (evp, out, & outl); / * Padding processing * /
    fwrite (out, 1, outl, outfp);

    EVP_CIPHER_CTX_free (evp);
```
<br> <br> <br>

## 3) Authenticated Encryption (AEAD)

For authenticated encryption such as AES-GCM, it is necessary to handle the authentication tag. As shown in the program below, when encrypting, get the authentication tag to be used for decryption after "Final". When decrypting, set the tag before "Final". Confirm that the authentication tag verification is successful by confirming that the return value of the "Final" process is successful.
<br> <br> <br>
See Examples/2.Chrypto/sym/aes-cbc.c for working sample code. This program accepts the following command arguments.


- Input file: Uses the file with the specified file name as input data. <br>
- Output file: Outputs the result data to the file with the specified file name. If omitted, output to standard output. <br>

- "-e" : encryption, "-d" : decryption. Encryption is the default<br>
- key value in hexadecimal next to "-k". <br>
- IV value in hexadecimal next to "-i". <br>
- tag value in hexadecimal next to "-t". <br>

```
   Command argument processing

    evp = EVP_CIPHER_CTX_new (); / * Secure context * /
    EVP_CipherInit (evp, CIPHER, key, iv, mode); / * Algorithm, key, IV, mode setting * /

    while (1) {
        inl = fread(in, 1, BUFF_SIZE, stdin));
        if(inl < BUFF_SIZE) break;
        EVP_CipherUpdate(evp, out, &outl, in, inl); /*　暗号、復号 */
        fwrite(out, 1, outl, outfp);
    }

    if (mode == DEC) / * Set authentication tag for decryption processing * /
        EVP_CIPHER_CTX_ctrl (evp, EVP_CTRL_AEAD_SET_TAG, tag_size, tagIn;

    if (EVP_CipherFinal (evp, out, & outl)! = SSL_SUCCESS) / * Padding process * /
        Error handling
    else else
        fwrite (out, 1, outl, outfp);

    if (mode == ENC) / * Get tag for cryptographic processing * /
        EVP_CIPHER_CTX_ctrl (evp EVP_CTRL_AEAD_GET_TAG, tag_size, tagOut);
    
    EVP_CIPHER_CTX_free (evp);


```
<br> <br> <br>



## 4) EVP function naming convention

The EVP function provides two series of functions, one for when the direction of symmetric key encryption or decryption processing is statically determined at programming time, and the other for dynamically determining at runtime. .. If static, the function name contains the name "Encrypt" or "Decrypt" to indicate the direction of processing. If it is dynamic, the function name will be named "Cipher" and the direction of processing will be specified during the initial setup of EVP_CipherInit. The following table summarizes the function names for these common key processes.

| Function | Encryption | Decryption | Dynamic specification |
| --- | --- | --- | --- |
Securing context | EVP_CIPHER_CTX_new | EVP_CIPHER_CTX_new | EVP_CIPHER_CTX_new |
| Initial Settings | EVP_EncryptInit | EVP_DecryptInit | EVP_CipherInit |
| Encryption / Decryption | EVP_EncryptUpdate | EVP_DecryptUpdate | EVP_CipherUpdate |
| Termination | EVP_EncryptFinal | EVP_DecryptFinal | EVP_CipherFinal |
Context release | EVP_CIPHER_CTX_free | EVP_CIPHER_CTX_free | EVP_CIPHER_CTX_free |


## 5) Padding process
The EVP function automatically performs padding for block cryptography. The padding scheme is PKCS. Therefore, in the case of encryption processing, it should be noted that the processing result will be larger by the amount aligned to an integral multiple of the block size compared to the size of the input data. Even if the input data is an integral multiple of the block size, one block of output data will be added for padding. On the other hand, when decrypting, the padding content is eliminated and only the original decrypted output data is available. The output data size of the encryption / decryption process including padding is returned to the argument of the "Final" function.

The scheme specified in PKCS # 7 is used as the padding scheme (see 3.4 Common Key Cryptography 4) Padding Scheme).


## 6) Cryptographic algorithm, usage mode

In EVP, various cryptographic algorithms, processing parameters such as usage modes are set with the "Init" function.
Can be handled by. The main cipher suites that can be specified with "Init" are summarized below.

| Symbol | Algorithm | Block length | Key length | Usage mode |
| --- | --- | --- | --- | --- |
EVP_aes_xxx_cbc | AES | 128 | xxx: 128, 192, 256 | CBC |
EVP_aes_xxx_cfb1 | AES | 128 | xxx: 128, 192, 256 | CFB1 |
EVP_aes_xxx_cfb8 | AES | 128 | xxx: 128, 192, 256 | CFB8 |
EVP_aes_xxx_cfb128 | AES | 128 | xxx: 128, 192, 256 | CFB128 |
EVP_aes_xxx_ofb | AES | 128 | xxx: 128, 192, 256 | OFB |
EVP_aes_xxx_xts | AES | 128 | xxx: 128, 256 | XTS |
EVP_aes_xxx_gcm | AES | 128 | xxx: 128, 192, 256 | GCM |
EVP_aes_xxx_ecb | AES | 128 | xxx: 128, 192, 256 | ECB |
EVP_aes_xxx_ctr | AES | 128 | xxx: 128, 192, 256 | CTR |
EVP_des_cbc | DES | 64 | 56 | CBC |
EVP_des_ecb | DES | 64 | 56 | ECB |
EVP_des_ede3_cbc | DES-EDE3 | 64 | 168 | CBC |
EVP_des_ede3_ecb | DES-EDE3 | 64 | 168 | ECB |
EVP_idea_cbc | IDEA | 64 | 128 | CBC |
| EVP_rc4 | RC4 ||||

## 7) Related API


<br>
The main EVP functions related to the processing of common key cryptography are summarized below.
<br>

| Function name | Function |
| --- | --- |
| EVP_CIPHER_CTX_iv_length, EVP_CIPHER_iv_length | Get IV size |
EVP_CIPHER_CTX_key_length, EVP_CIPHER_key_length | Get key size |
| EVP_CIPHER_CTX_mode, EVP_CIPHER_mode | Get encryption / decryption mode |
| EVP_CIPHER_CTX_block_size, EVP_CIPHER_block_size | Get block size |
EVP_CIPHER_CTX_flags, EVP_CIPHER_flags | Get Flags |
| EVP_CIPHER_CTX_cipher | Get Algorithm |
EVP_CIPHER_CTX_set_key_length | Set key size |
| EVP_CIPHER_CTX_set_iv | Set IV size |
EVP_CIPHER_CTX_set_padding | Set padding |
EVP_CIPHER_CTX_set_flags | Set flags |
EVP_CIPHER_CTX_clear_flags | Clear flags |
| EVP_CIPHER_CTX_reset | Reset context <br> (backward compatible: with EVP_CIPHER_CTX_FREE)
EVP_CIPHER_CTX_cleanup | Clean up the context <br> (backward compatibility: EVP_CIPHER_CTX_
In short) |



# 7.5 Public Key Cryptography / Decryption

    encryption
    fread (stdin);
    EVP_PKEY_CTX_set_rsa_padding ();
    EVP_PKEY_encrypt ();
    fwrite (sdiout);

    Decryption
    fread (stdin);
    EVP_PKEY_CTX_set_rsa_padding ();
    EVP_PKEY_decrypt ();
    fwrite (sdiout);

# 7.6 Public key signature
# 7.6.1 RSA signature
    signature
    EVP_PKEY_new ();
    EVP_PKEY_assign_RSA (priKey, rsa);
    EVP_DigestSignInit ();
    while (fread (stdin)) {
        EVP_DigestSignUpdate ();
    }
    EVP_DigestSignFinal ();

    inspection

# 7.6.2 ECDSA signature
    signature
    EVP_PKEY_new ();
    EVP_PKEY_assign_EC_KEY ();
    EVP_DigestSignInit ();
    while (fread (stdin)) {
        EVP_DigestSignUpdate ();
    }
    EVP_DigestSignFinal ();

    inspection

# 7.7 Keyed agreement

    EVP_PKEY_CTX_new_id ();
    EVP_PKEY_paramgen_init ();
    EVP_PKEY_paramgen ();

    EVP_PKEY_CTX_new ();

    EVP_PKEY_keygen_init ();
    EVP_PKEY_keygen ();


    EVP_PKEY_CTX_new ();
    EVP_PKEY_derive_init ();
    EVP_PKEY_derive_set_peer ();
    EVP_PKEY_derive ();