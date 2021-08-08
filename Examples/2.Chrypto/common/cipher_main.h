#ifndef CIPHER_MAIN_H
#define CIPHER_MAIN_H

#define ENC 1
#define DEC 0

void cipher_main(int mode, FILE *infp, FILE *outfp,
                 unsigned char *key, int key_sz, 
                 unsigned char *iv,  int iv_sz,
                 unsigned char *tag, int tag_sz
                );

#endif