

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/main.h"

#define HASH EVP_sha256()

void algo_main(int mode, FILE *infp, int size, FILE *fp2,
                 unsigned char *key, int key_sz,
                 unsigned char *iv, int iv_sz,
                 unsigned char *tag, int tag_sz)
{
    /***
        infp: RSA signature to verify
        fp2:  RSA Public key
        stdin: Sigened Message
    ***/
    EVP_PKEY  *pkey = NULL;
    EVP_MD_CTX *md = NULL;

    #define KEY_SIZE 512
    unsigned char pubkey[KEY_SIZE];
    const unsigned char *p = pubkey;
    #define SIG_SIZE 256
    unsigned char sig[SIG_SIZE];
    #define BUFF_SIZE 256
    unsigned char msg[BUFF_SIZE];
    int inl; 
    size_t sig_sz;

    /* Check arguments */
    if (tag != NULL || key != NULL || iv != NULL) {
        fprintf(stderr, "ERROR: command argment\n");
        return;
    }
    /* End argment check */

    if(size > KEY_SIZE || 
      (key_sz = fread(pubkey, 1, KEY_SIZE, infp)) < 0) {
        fprintf(stderr, "ERROR: read key\n");
        return;
    }

    if((sig_sz = fread(sig, 1, SIG_SIZE, fp2)) < 0) {
        fprintf(stderr, "ERROR: read signature\n");
        return;
    }

    if((pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p, key_sz)) == NULL) {
        fprintf(stderr, "ERROR: d2i_RSAPublicKey\n");
        goto cleanup;
    };

    if((md = EVP_MD_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: EVP_MD_CTX_new\n");
        goto cleanup;
    };

    if (EVP_DigestVerifyInit(md, NULL, HASH, NULL, pkey) != SSL_SUCCESS) {
        fprintf(stderr, "EVP_DigestVerifyInit\n");
        goto cleanup;
    }

    for (; size > 0; size -= BUFF_SIZE) {
        if((inl = fread(msg, 1, BUFF_SIZE, stdin)) < 0) {
            fprintf(stderr, "ERROR: fread\n");
            goto cleanup;
        }
        EVP_DigestVerifyUpdate(md, msg, inl);
    }

    if(EVP_DigestVerifyFinal(md, sig, sig_sz) == SSL_SUCCESS)
        printf("Signature Verified\n");
    else
        printf("Invalid Signature\n");

cleanup:
    if(pkey != NULL)EVP_PKEY_free(pkey);
    if(md   != NULL)EVP_MD_CTX_free(md);
    return;
}
