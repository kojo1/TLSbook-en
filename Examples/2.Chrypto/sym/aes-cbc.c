#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../../common/main.h"

#define CIPHER EVP_aes_128_cbc()

#define BUFF_SIZE   256

void algo_main(int mode, FILE *infp, FILE *outfp,
               unsigned char *key, int key_sz,
               unsigned char *iv, int iv_sz,
               unsigned char *tag, int tag_sz)
{
    EVP_CIPHER_CTX *evp = NULL;
    unsigned char in[BUFF_SIZE];
    unsigned char out[BUFF_SIZE+AES_BLOCK_SIZE];
    int           inl, outl;

    /* Check arguments */
    if (tag != NULL || key == NULL || iv == NULL) {
        fprintf(stderr, "ERROR: Option\n");
        return;
    }

    if ((evp = EVP_CIPHER_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: EVP_CIIPHER_CTX_new\n");
        return;
    }

    if(EVP_CIPHER_CTX_set_key_length(evp, key_sz) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: Invalid key length (len=%d)\n", key_sz);
        return;
    }

    if(wolfSSL_EVP_CIPHER_CTX_set_iv_length(evp, iv_sz) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: Invalid IV length (len=%d)\n", key_sz);
        return;
    }
    /* End argment check */

    /* Start cipher process */
    if (EVP_CipherInit(evp, CIPHER, key, iv, mode) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_EncryptInit\n");
        return;
    }

    while(1) {
        if((inl = fread(in, 1, BUFF_SIZE, infp)) <0) {
            fprintf(stderr, "ERROR: fread\n");
            return;
        } 
        if(inl < BUFF_SIZE) break;
        EVP_CipherUpdate(evp, out, &outl, in, inl);
        fwrite(out, 1, outl, outfp);
    }

    EVP_CipherFinal(evp, out, &outl);
    fwrite(out, 1, outl, outfp);

    EVP_CIPHER_CTX_free(evp);
    /* End cipher process */

    return;
}