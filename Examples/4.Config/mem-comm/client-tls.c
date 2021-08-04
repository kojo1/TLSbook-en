/* 
 * client-tls.c
 * Simple Client Program
 */
#include "example_common.h"

#include <openssl/ssl.h>
#include "mem-comm.h"

#define CA_CERT_FILE        "../../certs/tb-ca-cert.pem"

#define MSG_SIZE            256

/* Print SSL error message */
static void print_SSL_error(const char* msg, SSL* ssl)
{
    int err;
    err = SSL_get_error(ssl, 0);
    fprintf(stderr, "ERROR: %s (err %d, %s)\n", msg, err,
                    ERR_error_string(err, NULL));
}

int client_main(void)
{
    char               msg[MSG_SIZE];
    int                ret = SSL_FAILURE;

    /* SSL objects */
    SSL_CTX* ctx = NULL;
    SSL*     ssl = NULL;
    
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

    /* Register callbacks */
    wolfSSL_SetIORecv(ctx, mem_recv);
    wolfSSL_SetIOSend(ctx, mem_send);

    /* Create an SSL object */
    if ((ssl = SSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create an SSL object\n");
        goto cleanup;
    }

    wolfSSL_SetIOReadCtx(ssl, mem_getCH(0));
    wolfSSL_SetIOWriteCtx(ssl, mem_getCH(1));

    /* SSL connect to the server */
    if ((ret = SSL_connect(ssl)) != SSL_SUCCESS) {
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

        /* send a message to the server */
        if ((ret = SSL_write(ssl, msg, strnlen(msg, sizeof(msg)))) < 0) {
            print_SSL_error("failed SSL write", ssl);
            break;
        }
        /* only for SSL_MODE_ENABLE_PARTIAL_WRITE mode */
        if (ret != strnlen(msg, sizeof(msg))) {
            printf("Partial write\n");
        }

        if (strcmp(msg, "break\n") == 0) {
            printf("Sending break command\n");
            ret = SSL_SUCCESS;
            break;
        }

        /* receive a message from the server */
        if ((ret = SSL_read(ssl, msg, sizeof(msg) - 1)) < 0) {
            print_SSL_error("failed SSL read", ssl);
            break;
        }
        msg[ret] = '\0';
        printf("Received: %s\n", msg);
    }

/*  Cleanup and return */
cleanup:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (ret != SSL_SUCCESS)
        ret = SSL_FAILURE;
    printf("End of TLS Client\n");
    return ret;
}

