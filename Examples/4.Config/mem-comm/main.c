#include <stdio.h>
#include <pthread.h>

#include <openssl/ssl.h>
#include "mem-comm.h"

extern void client_main();
extern void server_main(void *arg);

static void *server_wrapper(void *arg) {
    server_main(arg);
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t server_thread;

    mem_init(0);
    mem_init(1);

    /* Initialize library */
    if (SSL_library_init() != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to initialize the library\n");
        return -1;
    }

    if(pthread_create(&server_thread, NULL, server_wrapper, NULL) != 0) {
        fprintf(stderr, "ERROR: pthread_create\n");
        return -1;
    }

    client_main();

    if(pthread_join(server_thread, NULL) != 0) {
        fprintf(stderr, "ERROR: pthread_join\n");
        return -1;
    }

    return 0;
}