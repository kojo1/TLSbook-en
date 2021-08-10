

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/main.h"

#define HASH EVP_sha256()

void algo_main(int mode, FILE *infp, int size, FILE *outfp,
                 unsigned char *key, int key_sz,
                 unsigned char *iv, int iv_sz,
                 unsigned char *tag, int tag_sz)
{
    /***
        infp: RSA key in DER for sign
        stdin: Message to sign
        outfp: RSA Signature
    ***/
    
    EVP_PKEY  *pkey = NULL;
    EVP_MD_CTX *md = NULL;

    #define KEY_SIZE 2048
    unsigned char in[KEY_SIZE];
    const unsigned char *inp = in;
    #define SIG_SIZE 256
    unsigned char sig[SIG_SIZE];
    #define BUFF_SIZE 256
    unsigned char msg[BUFF_SIZE];
    int inl; 
    size_t sig_sz;

    /* Check arguments */
    if (tag != NULL || key != NULL || iv != NULL || outfp == stdout) {
        fprintf(stderr, "ERROR: command argment\n");
        return;
    }
    /* End argment check */

    if(size > KEY_SIZE || 
       (key_sz = fread(in, 1, size, infp)) < 0) {
        fprintf(stderr, "ERROR: read key\n");
        return;
    }

    if((pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, &inp, key_sz)) == NULL) {
        fprintf(stderr, "ERROR: d2i_PrivateKey\n");
        return;
    };

    if((md = EVP_MD_CTX_new()) == NULL) {
        fprintf(stderr, "ERROR: EVP_MD_CTX_new\n");
        goto cleanup;
    };

    if (EVP_DigestSignInit(md, NULL, HASH, NULL, pkey)
             != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: EVP_EncryptInit\n");
        goto cleanup;
    }

    for (; size > 0; size -= BUFF_SIZE) {
        if((inl = fread(msg, 1, BUFF_SIZE, stdin)) < 0) {
            fprintf(stderr, "ERROR: fread\n");
            goto cleanup;
        }
        EVP_DigestSignUpdate(md, msg, inl);
    }

    EVP_DigestSignFinal(md, sig, &sig_sz);
    if(fwrite(sig, 1, sig_sz, outfp) != sig_sz) {
        fprintf(stderr, "ERROR: fwrite\n");
        goto cleanup;
    }

cleanup:
    if(pkey != NULL)EVP_PKEY_free(pkey);
    if(md   != NULL) EVP_MD_CTX_free(md);

    return;
}
