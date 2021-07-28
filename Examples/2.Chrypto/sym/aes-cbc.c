#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>

#define CIPHER EVP_aes_128_cbc()

#define BUFF_SIZE   256
#define ENC 1
#define DEC 0

static int hex2int(int hex) {
    if (hex >= '0' && hex <= '9')
        return hex - '0';
    else if (hex >= 'a' && hex <= 'f')
        return hex - 'a';
    else if (hex >= 'A' && hex <= 'F')
        return hex - 'A';
    else return -1;
} 

static int hex2bin(unsigned char *bin, char *hex, int sz) {
    int n, i;
    
    if(strlen(hex) > sz*2)
        return -1;
    memset(bin, 0, sz);

    for( ; ; bin++) {
        for(i=0; i<2; i++, hex++) {
            if(*hex == '\0')return 0;
            if((n = hex2int(*hex)) >= 0)
                *bin = *bin * 0x10 + n;
            else return -1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    FILE *infp  = NULL;
    FILE *outfp = NULL;

    int  mode;
    EVP_CIPHER_CTX *evp = NULL;
    unsigned char key[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char in[BUFF_SIZE];
    unsigned char out[BUFF_SIZE+AES_BLOCK_SIZE];
    int           inl, outl;
    int           size;

    if(argc != 6) {
        fprintf(stderr, "ERROR: Command Argument\n");
        goto cleanup;
    }

    mode = strcmp(argv[1], "e") == 0 ? ENC : DEC;

    if ((infp = fopen(argv[2], "r+")) == NULL ||
        fseek(infp, 0, SEEK_END) != 0 ||
        (size = ftell(infp)) < 0) {
        fprintf(stderr, "ERROR: Open input %s\n", argv[4]);
        goto cleanup;
    }
    rewind(infp);

    if ((outfp = fopen(argv[3], "w+")) == NULL) {
        fprintf(stderr, "ERROR: File out %s\n", argv[5]);
        goto cleanup;
    }

    if (hex2bin(key, argv[4], AES_BLOCK_SIZE) < 0) {
        fprintf(stderr, "ERROR: Key value\n");
        goto cleanup;
    }

    if (hex2bin(iv, argv[5], AES_BLOCK_SIZE) < 0) {
        fprintf(stderr, "ERROR: IV value\n");
        goto cleanup;
    }

    if ((evp = EVP_CIPHER_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: EVP_CIIPHER_CTX_new\n");
        goto cleanup;
    }

    if (EVP_CipherInit(evp, CIPHER, key, iv, mode) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_EncryptInit\n");
        goto cleanup;
    }

    /* Encrypt/Decrypt */
    for( ; size > 0; size -= BUFF_SIZE) {
        inl = fread(in, 1, BUFF_SIZE, infp); 
        in[inl] = '\0';
        EVP_CipherUpdate(evp, out, &outl, in, inl);
        fwrite(out, 1, outl, outfp);
    }
    EVP_CipherFinal(evp, out, &outl);
    fwrite(out, 1, outl, outfp);

cleanup:
    if(evp != NULL)
        EVP_CIPHER_CTX_free(evp);
    if(infp != NULL)
        fclose(infp);
    if(outfp != NULL)
        fclose(outfp);

    return 0;
}