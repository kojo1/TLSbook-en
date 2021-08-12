#ifndef CIPHER_MAIN_H
#define CIPHER_MAIN_H

#define ENC 1
#define DEC 0
#define SIG 2
#define VER 3

#define KEY_RSA 10
#define KEY_ECC ENC
#define KEY_DH  DEC

void algo_main(int mode, FILE *fp1, FILE *fp2,
                 unsigned char *key, int key_sz, 
                 unsigned char *iv,  int iv_sz,
                 unsigned char *tag, int tag_sz
                );

#endif