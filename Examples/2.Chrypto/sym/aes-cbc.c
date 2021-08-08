#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/cipher_main.h"

#define CIPHER EVP_aes_128_cbc()

#define BUFF_SIZE   256

void chiper_main(int mode, FILE *infp, FILE *outfp,
                 unsigned char *key, int key_sz,
                 unsigned char *iv,  int iv_sz,
                 unsigned char *tag, int tag_sz)
{
    EVP_CIPHER_CTX *evp = NULL;
    unsigned char in[BUFF_SIZE];
    unsigned char out[BUFF_SIZE+AES_BLOCK_SIZE];
    int           inl, outl;
    int           size;

    /* Check arguments */
    if (tag != NULL || key == NULL || iv == NULL) {
        fprintf(stderr, "ERROR: Option\n");
        return;
    }

    if (fseek(infp, 0, SEEK_END) != 0 ||
        (size = ftell(infp)) < 0) {
        fprintf(stderr, "ERROR: Input file size\n");
        return;
    }
    rewind(infp);

    if ((evp = EVP_CIPHER_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: EVP_CIIPHER_CTX_new\n");
        return;
    }

    if(EVP_CIPHER_CTX_set_key_length(evp, key_sz) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: Invalid key length (len=%d)\n", key_sz);
        return;
    }

    if (EVP_CipherInit(evp, CIPHER, key, iv, mode) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_EncryptInit\n");
        return;
    }

    if (EVP_CIPHER_CTX_iv_length(evp) != iv_sz) {
        fprintf(stderr, "ERROR: Invalid iv lengty (len=%d, %d)\n", EVP_CIPHER_CTX_iv_length(evp), iv_sz);
        return;
    }
    /* End argment check */

    /* Start cipher process */
    for( ; size > 0; size -= BUFF_SIZE) {
        inl = fread(in, 1, BUFF_SIZE, infp); 
        in[inl] = '\0';
        EVP_CipherUpdate(evp, out, &outl, in, inl);
        printf("Out len = %d\n", outl);
        fwrite(out, 1, outl, outfp);
    }

    EVP_CipherFinal(evp, out, &outl);
    fwrite(out, 1, outl, outfp);
    printf("Out len = %d\n", outl);

    EVP_CIPHER_CTX_free(evp);
    /* End cipher process */

    return;
}