#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include "../common/main.h"

#ifndef OPEN_MODE1
#define OPEN_MODE1 "r+"
#endif

#ifndef OPEN_MODE2
#define OPEN_MODE2 "w+"
#endif

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
    FILE *fp1  = NULL;
    FILE *fp2 = NULL;
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
    
    if ((fp1 = fopen(argv[1], OPEN_MODE1)) == NULL) {
        fprintf(stderr, "ERROR: Open input file (%s)\n", argv[1]);
        goto cleanup;
    }

    i = 2;
    if(argc > 2 && argv[2][0] != '-') {
        if((fp2 = fopen(argv[2], OPEN_MODE2)) == NULL) {
            fprintf(stderr, "ERROR: Open output file (%s)\n", argv[2]);
            goto cleanup;
        }
        i ++;
    } else
        fp2 = stdout;

    for( ; i < argc; i++) {
        if(argv[i][0] == '-') {
            switch (argv[i][1]) {
            case 'e': mode = ENC; break;
            case 'd': mode = DEC; break;
            case 's': mode = SIG; break;
            case 'v': mode = VER; break;
            case 'r': mode = KEY_RSA; break;

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
        else if (argv[i][0] == '>' || argv[i][0] == '<')
            break;
        else
        {
            fprintf(stderr, "ERROR: Invalid arg (%s)\n", argv[i]);
            goto cleanup;
        }
    }

    algo_main(mode, fp1, fp2, key, key_sz, iv, iv_sz, tag, tag_sz);

cleanup:
    if(fp1 != NULL)
        fclose(fp1);
    if(fp2 != NULL && fp2 != stdout)
        fclose(fp2);
    if (key != NULL) free(key);
    if (iv  != NULL) free(iv);
    if (tag != NULL) free(tag);
    return 0;
}