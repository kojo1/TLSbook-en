

#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/cipher_main.h"

#define CIPHER EVP_aes_128_cbc()

#define BUFF_SIZE 256

int main(int argc, char **argv)
{
    int mode = KEY_RSA;
    int size = 0;
    int i;
    FILE *outfp;

    RSA *rsa   = NULL;
    EC_KEY *ec = NULL;
    unsigned char *pri = NULL;
    unsigned char *pub = NULL;
    int pri_sz, pub_sz;

    /* Check arguments */
    if (argc <= 1 || argc > 4) {
        fprintf(stderr, "Usage: keygen private_key -[edr](%d)\n", argc);
        return -1;
    }

    if((outfp = fopen(argv[1], "w+")) == NULL) {
        fprintf(stderr, "ERROR: Open output file (%s)\n", argv[2]);
        goto cleanup;
    }

    for(i = 2; i < argc; i++) {
        if(argv[i][0] == '-') {
            switch (argv[i][1]) {
            case 'e': mode = KEY_ECC; break;
            case 'd': mode = KEY_DH;  break;
            case 'r': mode = KEY_RSA; break;

            case 's': /* size option */
                if(argv[i+1] != NULL)
                    size = atoi(argv[i+1]);
                printf("Key Size = %d\n", size);
                break;

            default:
                fprintf(stderr, "ERROR: Invalid option (-%c)\n", argv[2][1]);
                return -1;
            }
        }
    }

    /* End argment check */

    /* Start cipher process */
    switch(mode) {
    case KEY_RSA:
        if(size == 0) {
            fprintf(stderr, "Missing size option\n");
            goto cleanup;
        }
        rsa = RSA_generate_key(size, 3, NULL, NULL);
        if(rsa == NULL) {
            fprintf(stderr, "ERROR: RSA_generate_key\n");
            goto cleanup;            
        }
        pri_sz = i2d_RSAPrivateKey(rsa, &pri);
        pub_sz = i2d_RSAPublicKey(rsa, &pub);
        if(pri == NULL || pub == NULL) {
            fprintf(stderr, "ERROR: i2d_RSAPrivate/PublicKey\n");
            goto cleanup;
        }
        printf("pri=%d, pub=%d\n", pri_sz, pub_sz);
        break;

    case KEY_ECC:
        if((ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL) {
            fprintf(stderr, "ERROR: EC_KEY_new_by_curve_name\n");
            goto cleanup;            
        }
        if(EC_KEY_generate_key(ec) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: EC_KEY_generate_key\n");
            goto cleanup;
        }
        pub_sz = i2d_EC_PUBKEY(ec, &pub);
        pri_sz = i2d_ECPrivateKey(ec, &pri);
        if(pri == NULL || pub == NULL) {
            fprintf(stderr, "ERROR: i2d_RSAPrivate/PublicKey\n");
            goto cleanup;
        }
        break;

    default:
        fprintf(stderr, "ERROR: Mode option\n");
        goto cleanup;
    }

    if(fwrite(pub, 1, pub_sz, stdout) != pub_sz) {
        fprintf(stderr, "ERROR: fwrite Pub key\n");
        goto cleanup;
    }

    if(pri != NULL) {
        if(fwrite(pri, 1, pri_sz, outfp) != pri_sz) {
            fprintf(stderr, "ERROR: fwrite Private key\n");
            goto cleanup;
        }
    }

cleanup:
    if(rsa!= NULL)free(rsa);
    if(ec!= NULL)free(ec);
    if(pri!= NULL)free(pri);
    if(pub!= NULL)free(pub);
    if(outfp != NULL)fclose(outfp);
    return 0;
}