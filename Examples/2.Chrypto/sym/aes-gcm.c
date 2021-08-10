#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/cipher_main.h"

#define CIPHER EVP_aes_128_gcm()

#define BUFF_SIZE   256

void cipher_main(int mode, FILE *infp, int size, FILE *outfp,
                 unsigned char *key, int key_sz,
                 unsigned char *iv,  int iv_sz,
                 unsigned char *tagIn, int tag_sz)
{
    EVP_CIPHER_CTX *evp = NULL;
    unsigned char in[BUFF_SIZE];
    unsigned char out[BUFF_SIZE+AES_BLOCK_SIZE];
    unsigned char tagOut[BUFF_SIZE];
    int           inl, outl;
    int           i;

    /* Check arguments */
    if(mode == ENC && tagIn != NULL) {
         fprintf(stderr, "ERROR: Tag Option with Enc mode\n");
        return;
    } else
        tag_sz = AES_BLOCK_SIZE;

    if(mode == DEC && tagIn == NULL) {
        fprintf(stderr, "ERROR: No Tag Option with Dec mode\n");
        return;
    }

    if(key == NULL || iv == NULL) {
        fprintf(stderr, "ERROR: Missing Option key or iv\n");
        return;
    }

    if((evp = EVP_CIPHER_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: EVP_CIIPHER_CTX_new\n");
        return;
    }

    if(EVP_CIPHER_CTX_set_key_length(evp, key_sz) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: Invalid key length (len=%d)\n", key_sz);
        return;
    }

    if (EVP_CIPHER_CTX_set_iv_length(evp, iv_sz) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: Invalid IV length (len=%d)\n", key_sz);
        return;
    }

    if (EVP_CipherInit(evp, CIPHER, key, iv, mode) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_EncryptInit\n");
        return;
    }
    /* End argment check */

    /* Start cipher process */
    for( ; size > 0; size -= BUFF_SIZE) {
        inl = fread(in, 1, BUFF_SIZE, infp); 
        in[inl] = '\0';
        EVP_CipherUpdate(evp, out, &outl, in, inl);
        fwrite(out, 1, outl, outfp);
    }

    if (mode == DEC)
        EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_SET_TAG, tag_sz, tagIn);

    EVP_CipherFinal(evp, out, &outl);

    if (mode == ENC) {
        EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_AEAD_GET_TAG, tag_sz, tagOut);
        for (i = 0; i < tag_sz; i++)
            printf("%02x", tagOut[i]);
        putchar('\n');
    }
    fwrite(out, 1, outl, outfp);

    EVP_CIPHER_CTX_free(evp);
    /* End cipher process */

    return;
}