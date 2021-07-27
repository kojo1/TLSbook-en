/* 
 * client-tls.c
 * Simple Client Program
 */
#include "example_common.h"

#include <openssl/ssl.h>
#include <mem-comm.h>

#define CA_CERT_FILE        "../../certs/tb-ca-cert.pem"
#define LOCALHOST           "127.0.0.1"
#define DEFAULT_PORT        11111

#define MSG_SIZE            256

/* Print SSL error message */
static void print_SSL_error(const char* msg, SSL* ssl)
{
    int err;
    err = SSL_get_error(ssl, 0);
    fprintf(stderr, "ERROR: %s (err %d, %s)\n", msg, err,
                    ERR_error_string(err, NULL));
}

enum
{
    CLIENT_BEGIN,
    CLIENT_SSL_CONNECT,
    CLIENT_SSL_WRITE,
    CLIENT_SSL_READ,
    CLIENT_END
};

static int client_stat = CLIENT_BEGIN;
#define FALLTHROUGH

static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;

void client_main(void)
{

    char               msg[MSG_SIZE];
    size_t             sendSz;
    int                ret = SSL_FAILURE;
  
    switch(client_stat) {
    case CLIENT_BEGIN:

        /* Initialize library */
        if (SSL_library_init() != SSL_SUCCESS) {
            printf("ERROR: failed to initialize the library\n");
            goto cleanup;
        }
        
        /* Create and initialize an SSL context object*/
        if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
            fprintf(stderr, "ERROR: failed to create an SSL context object\n");
            goto cleanup;
        }
        /* Load CA certificate to the context */
        if ((ret = SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL)) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: failed to load %s \n", CA_CERT_FILE);
            goto cleanup;
        }

        wolfSSL_SetIORecv(ctx, mem_recv);
        wolfSSL_SetIOSend(ctx, mem_send);

        /* Create a WOLFSSL object */
        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
            goto cleanup;
        }
        wolfSSL_SetIOReadCtx(ssl, mem_getCH(0));
        wolfSSL_SetIOWriteCtx(ssl, mem_getCH(1));

        client_stat = CLIENT_SSL_CONNECT;
        FALLTHROUGH;

    case CLIENT_SSL_CONNECT:

        /* SSL connect to the server */
        if ((ret = SSL_connect(ssl)) != SSL_SUCCESS) {
            if ((ret = SSL_want(ssl)) == SSL_WRITING ||
                SSL_want(ssl) == SSL_READING)
                return;
            print_SSL_error("failed SSL connect", ssl);
            goto cleanup;
        }

    /* 
        * Application messaging
        */
        while (1) {

            printf("Message to send: ");
            if(fgets(msg, sizeof(msg), stdin) <= 0)
                break;
            sendSz = strlen(msg);

            /* send a message to the server */
            client_stat = CLIENT_SSL_WRITE;
            FALLTHROUGH;
        case CLIENT_SSL_WRITE:

            if ((ret = SSL_write(ssl, msg, sendSz)) < 0) {
                if (SSL_want(ssl) == SSL_WRITING ||
                    SSL_want(ssl) == SSL_READING)
                    return;
                print_SSL_error("failed SSL write", ssl);
                goto cleanup;
            }
            /* only for SSL_MODE_ENABLE_PARTIAL_WRITE mode */
            if (ret != sendSz) {
                fprintf(stderr, "Partial write\n");
            }

            if (strcmp(msg, "break\n") == 0) {
                printf("Sending break command\n");
                ret = SSL_SUCCESS;
                goto cleanup;
            }

            client_stat = CLIENT_SSL_READ;
            FALLTHROUGH;
        case CLIENT_SSL_READ:

            /* receive a message from the server */
            if ((ret = SSL_read(ssl, msg, sizeof(msg) - 1)) < 0)
            {
                if (SSL_want(ssl) == SSL_WRITING ||
                    SSL_want(ssl) == SSL_READING)
                    return;
                print_SSL_error("failed SSL read", ssl);
                break;
            }
            msg[ret] = '\0';
            printf("Received: %s\n", msg);
        }
    }


/*  Cleanup and return */
cleanup:

    client_stat = CLIENT_END;

    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (ret != SSL_SUCCESS)
        ret = SSL_FAILURE;
    printf("End of TLS Client\n");

}

