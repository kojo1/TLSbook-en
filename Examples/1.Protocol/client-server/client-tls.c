/* 
 * client-tls.c
 * Simple Client Program
 */
#include "example_common.h"

#include <openssl/ssl.h>

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

int main(int argc, char **argv)
{
    struct sockaddr_in servAddr;
    int                sockfd = -1;
    char                *ipadd = NULL;

    char               msg[MSG_SIZE];
    size_t             sendSz;
    int                ret = SSL_FAILURE;

    /* SSL objects */
    SSL_CTX* ctx = NULL;
    SSL*     ssl = NULL;

    /* Check for proper calling convention */
    if (argc == 2) {
        ipadd = (char *)argv[1];
    } else if (argc == 1) {
        printf("Send to localhost(%s)\n", LOCALHOST);
        ipadd = LOCALHOST;
    } else {
        printf("ERROR: Too many arguments.\n");
        goto cleanup;
    }

    /* Initialize library */
    if (SSL_library_init() != SSL_SUCCESS) {
        printf("ERROR: failed to initialize the library\n");
        goto cleanup;
    }

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON(); /* Debug log when Debug Mode is enabled */
#endif
    
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

    /* 
    * Set up a TCP Socket and connect to the server 
    */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create a socket. errno %d\n", errno);
        goto cleanup;
    }
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;           /* using IPv4      */
    servAddr.sin_port = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
    if ((ret = inet_pton(AF_INET, ipadd, &servAddr.sin_addr)) != 1) {
        fprintf(stderr, "ERROR : failed inet_pton. errno %d\n", errno);
        goto cleanup;
    }
    if ((ret = connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr))) == -1) {
        fprintf(stderr, "ERROR: failed to connect. errno %d\n", errno);
        goto cleanup;
    }

    /* Create an SSL object */
    if ((ssl = SSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create an SSL object\n");
        goto cleanup;
    }

    /* Attach the socket to the SSL */
    if ((ret = SSL_set_fd(ssl, sockfd)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto cleanup;
    }
    /* SSL connect to the server */
    if ((ret = SSL_connect(ssl)) != SSL_SUCCESS) {
        print_SSL_error("failed SSL connet", ssl);
        goto cleanup;
    }

   /* 
    * Application messaging
    */
    while (1) {
        printf("Message to send: ");
        if(fgets(msg, sizeof(msg), stdin) <= 0)
            break;
        sendSz = strnlen(msg, sizeof(msg));

        /* send a message to the server */
        if ((ret = SSL_write(ssl, msg, sendSz)) != sendSz) {
            if (ret < 0) {
                print_SSL_error("failed SSL write", ssl);
                break;
            } else {
                /* only with SSL_MODE_ENABLE_PARTIAL_WRITE mode */ 
                fprintf(stderr, "%d bytes of %d bytes were sent\n",
                        ret, (int)sendSz);
            }
        }

        if (strncmp(msg, "shutdown", 8) == 0) {
            printf("Sending shutdown command\n");
            ret = SSL_SUCCESS;
            break;
        }

        /* receive a message from the server */
        if ((ret = SSL_read(ssl, msg, sizeof(msg) - 1)) > 0) {
                    msg[ret] = '\0';
                    printf("Received: %s\n", msg);
        } else {
            print_SSL_error("failed SSL read", ssl);
            break;
        }
    }

/*  Cleanup and return */
cleanup:
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    if (sockfd != -1)
        close(sockfd);
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (ret != SSL_SUCCESS)
        ret = SSL_FAILURE;
    printf("End of TLS Client\n");
    return ret;
}

