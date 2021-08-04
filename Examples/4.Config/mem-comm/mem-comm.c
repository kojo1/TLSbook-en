/* 
 * mem_comms.c
 * Memory communication
 */

#include <stdlib.h>
#include <openssl/ssl.h>
#include "mem-comm.h"

#define BUFF_SIZE 2048

typedef struct {
    int used;
    int head;
    unsigned char buff[BUFF_SIZE];
} MEM_channel;

static MEM_channel ch[2];
pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;

void mem_init(int no)
{
    ch[no].used = 0;
    ch[no].head = 0;
}


void * mem_getCH(int no)
{
    return (void *)&ch[no];
}


int mem_send(SSL *ssl, char *buff, int sz, void *ctx)
{
    (void)ssl;
    int copySz;
    MEM_channel *ch = (MEM_channel *)ctx;

    if(pthread_mutex_lock(&mtx) != 0)
        return WOLFSSL_CBIO_ERR_GENERAL;
    copySz = (ch->used + sz) > BUFF_SIZE ? BUFF_SIZE - ch->used : sz;

    memcpy(&ch->buff[ch->head], buff, copySz);
    ch->head += copySz;
    ch->used += copySz;
    if(pthread_mutex_unlock(&mtx) != 0)
        return WOLFSSL_CBIO_ERR_GENERAL;

    return copySz;
}

int mem_recv(SSL *ssl, char *buff, int sz, void *ctx)
{
    (void)ssl;
    int copySz;
    MEM_channel *ch = (MEM_channel *)ctx;

    copySz = 0;
    while(1) {
        if(pthread_mutex_lock(&mtx) != 0)
            return WOLFSSL_CBIO_ERR_GENERAL;
        copySz  = ch->used >= sz ? sz : ch->used;
        memcpy(buff, &ch->buff[ch->head-ch->used], copySz);
        ch->used -= copySz;
        if(ch->used == 0)
            ch->head = 0;
        if(pthread_mutex_unlock(&mtx) != 0)
            return WOLFSSL_CBIO_ERR_GENERAL;

        if(copySz == 0)
            sched_yield();
        else
            break;
    } 

    return copySz;
}
