/*
 * server-tls.c
 * simple server program
 */
#include "example_common.h"

#include <openssl/ssl.h>
#include <mem-comm.h>

#define SERVER_CERT_FILE    "../../certs/tb-server-cert.pem"
#define SERVER_KEY_FILE     "../../certs/tb-server-key.pem"

#define DEFAULT_PORT        11111
#define MSG_SIZE            256

/* Print SSL error message */
static void print_SSL_error(const char *msg, SSL *ssl)
{
    int err;
    err = SSL_get_error(ssl, 0);
    fprintf(stderr, "ERROR: %s (err %d, %s)\n", msg, err,
            ERR_error_string(err, NULL));
}

enum
{
    SERVER_BEGIN,
    SERVER_SSL_ACCEPT,
    SERVER_SSL_WRITE,
    SERVER_SSL_READ,
    SERVER_END
};

static int server_stat = SERVER_BEGIN;
#define FALLTHROUGH

/* Declare SSL objects */
static SSL_CTX *ctx = NULL;
static SSL *ssl = NULL;

void server_main(int argc, char** argv)
{
    
    char               buff[MSG_SIZE];
    int                len;
    const char         reply[] = "I hear ya fa shizzle!";
    int                ret;

    switch(server_stat) {
    case SERVER_BEGIN:

        /* Initialize library */
        if (SSL_library_init() != SSL_SUCCESS) {
            printf("ERROR: Failed to initialize the library\n");
            goto cleanup;
        }

        /* Create and initialize an SSL context object */
        if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
            fprintf(stderr, "ERROR: failed to create an SSL context object\n");
            goto cleanup;
        }

        /* Load server certificates to the SSL context object */
        if ((ret = SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, 
            SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: failed to load %s\n", SERVER_CERT_FILE);
            goto cleanup;
        }

        /* Load server key into the SSL context object */
        if ((ret = SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, 
            SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
            fprintf(stderr, "ERROR: failed to load %s\n", SERVER_KEY_FILE);
            goto cleanup;
        }

        /* set callbacks */
        wolfSSL_SetIORecv(ctx, mem_recv);
        wolfSSL_SetIOSend(ctx, mem_send);

        while (1) {
            printf("Waiting for a connection...\n");
            
            /* Create an SSL object */
            if ((ssl = SSL_new(ctx)) == NULL) {
                fprintf(stderr, "ERROR: failed to create an SSL object\n");
                goto cleanup;
            }

            wolfSSL_SetIOReadCtx (ssl, mem_getCH(1));
            wolfSSL_SetIOWriteCtx(ssl, mem_getCH(0));

            server_stat = SERVER_SSL_ACCEPT;
            FALLTHROUGH;
        case SERVER_SSL_ACCEPT:
            /* Establish TLS connection  */
            if ((ret = SSL_accept(ssl)) != SSL_SUCCESS) {
                if (SSL_want(ssl) == SSL_WRITING || 
                    SSL_want(ssl) == SSL_READING)
                    return;
                print_SSL_error("failed SSL accept", ssl);
                goto cleanup;
            }
            
            printf("Client connected successfully\n");

            /* 
            * Application messaging
            */
            while(1) {

                server_stat = SERVER_SSL_READ;
                FALLTHROUGH;
            case SERVER_SSL_READ:

                /* receive a message from the client */
                if ((ret = SSL_read(ssl, buff, sizeof(buff)-1)) <= 0) {
                    if (SSL_want(ssl) == SSL_WRITING ||
                        SSL_want(ssl) == SSL_READING)
                        return;
                    print_SSL_error("failed SSL read", ssl);
                    goto ssl_end;
                }
                buff[ret] = '\0';
                printf("Received: %s\n", buff);

                /* Check for server shutdown command */
                if (strcmp(buff, "break\n") == 0) {
                    printf("Received break command\n");
                    goto ssl_end;
                }

                server_stat = SERVER_SSL_WRITE;
                FALLTHROUGH;
            case SERVER_SSL_WRITE:
                /* send a message to the server */
                if ((ret = SSL_write(ssl, reply, sizeof(reply))) < 0) {
                    if (SSL_want(ssl) == SSL_WRITING ||
                        SSL_want(ssl) == SSL_READING)
                        return;
                    print_SSL_error("failed SSL write", ssl);
                    goto ssl_end;
                }
                /* only for SSL_MODE_ENABLE_PARTIAL_WRITE mode */
                if (ret != sizeof(reply)) {
                    fprintf(stderr, "Partial write\n");
                }

            }

        /* Cleanup after the connection */
        ssl_end:
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = NULL;

        mem_init(0);
        mem_init(1);
        printf("Closed the connection\n");


        }
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
    printf("End of TLS Server\n");

}
