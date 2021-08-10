#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/cipher_main.h"

static int hex2int(int hex) {
    if (hex >= '0' && hex <= '9')
        return hex - '0';
    else if (hex >= 'a' && hex <= 'f')
        return hex - 'a' + 10;
    else if (hex >= 'A' && hex <= 'F')
        return hex - 'A' + 10;
    else return -1;
}

static unsigned char *hex2bin(char *hex, int *sz)
{
    int n, i;
    unsigned char *bin, *b;    

    *sz = (strlen(hex)+1)/2;
    if ((bin = (unsigned char *)malloc(*sz)) == NULL)
        return NULL;
    memset(bin, 0, *sz);
    b = bin;

    for( ; ; b++) {
        for(i=0; i<2; i++, hex++) {
            if(*hex == '\0')return bin;
            if((n = hex2int(*hex)) >= 0)
                *b = *b * 0x10 + n;
            else return NULL;
        }
    }
    return bin;
}

int main(int argc, char **argv)
{
    FILE *infp  = NULL;
    FILE *outfp = NULL;
    int mode = ENC;
    unsigned char *key = NULL;
    unsigned char *iv  = NULL;
    unsigned char *tag = NULL;
    unsigned char *v;
    int key_sz = 0;
    int iv_sz  = 0;
    int tag_sz = 0;
    int sz;
    int i;

    if(argc < 2) {
        fprintf(stderr, "Usage: %s infile [outfile] [-[edikv]]\n", argv[0]);
        goto cleanup;
    }
    
    if ((infp = fopen(argv[1], "r+")) == NULL) {
        fprintf(stderr, "ERROR: Open input file (%s)\n", argv[1]);
        goto cleanup;
    }

    if (fseek(infp, 0, SEEK_END) != 0 ||
        (sz = ftell(infp)) < 0) {
        fprintf(stderr, "ERROR: Input file size\n");
        goto cleanup;
    }
    rewind(infp);

    i = 2;
    if(argc > 2 && argv[2][0] != '-') {
        if((outfp = fopen(argv[2], "w+")) == NULL) {
            fprintf(stderr, "ERROR: Open output file (%s)\n", argv[2]);
            goto cleanup;
        }
        i ++;
    } else
        outfp = stdout;

    for( ; i < argc; i++) {
        if(argv[i][0] == '-') {
            switch (argv[i][1]) {
            case 'e': mode = ENC; break;
            case 'd': mode = DEC; break;

            case 'i':
            case 'k' :
            case 't':
                v = hex2bin(argv[i+1], &sz);
                break;

            default:
                fprintf(stderr, "ERROR: Invalid option (-%c)\n", argv[i][1]);
                goto cleanup;
            }
            
            if(v != NULL) {
                switch (argv[i][1]) {
                case 'k' : key = v; key_sz = sz; break;
                case 'i' : iv  = v; iv_sz  = sz; break;
                case 't' : tag = v; tag_sz = sz; break;
                }
                i++;
            } else {
                fprintf(stderr, "ERROR: Invalid option (-%c)\n", argv[i][1]);
                goto cleanup;
            }
        }
        else {
            fprintf(stderr, "ERROR: Invalid arg (%s)\n", argv[i]);
            goto cleanup;
        }
    }

    cipher_main(mode, infp, sz, outfp, key, key_sz, iv, iv_sz, tag, tag_sz);

cleanup:
    if(infp != NULL)
        fclose(infp);
    if(outfp != NULL && outfp != stdout)
        fclose(outfp);
    if (key != NULL) free(key);
    if (iv  != NULL) free(iv);
    if (tag != NULL) free(tag);
    return 0;
}