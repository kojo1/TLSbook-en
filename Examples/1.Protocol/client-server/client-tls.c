/* 
 * client-tls.c
 * Simple Client Program
 */

#include <openssl/ssl.h>

#define CA_CERT_FILE "../../certs/tb-ca-cert.pem"
#define LOCALHOST "127.0.0.1"
#define DEFAULT_PORT 11111

#define MSG_SIZE 256
#define REPLY_SIZE MSG_SIZE + 1

int main(int argc, char **argv)
{
    FILE *fin = stdin;
    struct sockaddr_in servAddr;
    char msg[MSG_SIZE];
    char reply[REPLY_SIZE];
    static char *target_add = LOCALHOST;
    char *ipadd = NULL;
    size_t sendSz;
    int sockfd = -1;
  

    /* 
    * Declare SSL objects 
    */
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int ret = SSL_FALURE;
    int err;

    /* 
    * Check for proper calling convention
    */
    if (argc != 2) {
        printf("use localhost(%s) as server ip address\n", target_add);
        ipadd = (char *)target_add;
    } else {
        ipadd = (char *)&argv[1];
    }

    /*
    * Initialize library
    */
    if (SSL_library_init() != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto cleanup;
    }

    #if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON(); /* Debug log when Debug Mode is enabled */
    #endif

    /* 
    * Create and initialize an SSL context
    */
    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create the SSL context object\n");
        goto cleanup;
    }
    /* Load CA certificate to the context */
    if ((ret = SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CA_CERT_FILE);
        goto cleanup;
    }


    /*
    * Set up a TCP Socket and connect to the server
    */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        goto cleanup;
    }
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;           /* using IPv4      */
    servAddr.sin_port = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
    if (inet_pton(AF_INET, ipadd, &servAddr.sin_addr) != 1) {
        goto cleanup;
    }
    /* TCP Connect */
    if ((ret = connect(sockfd, (struct sockaddr *)&servAddr, sizeof(servAddr))) == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        goto cleanup;
    }


    /* 
    * Create an SSL and Connect to the server
    */
    if ((ssl = SSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create the SSL object\n");
        goto cleanup;
    }

    /* Attach the socket to the SSL */
    if ((ret = SSL_set_fd(ssl, sockfd)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto cleanup;
    }
    /* SSL connect to the server */
    if ((ret = SSL_connect(ssl)) != SSL_SUCCESS) {
        err = SSL_get_error(ssl, 0);
        printf("ERROR: failed to connect to SSL(err %d, %s)\n",
               ret, ERR_error_string(err, NULL));
        goto cleanup;
    }


    /* 
    * Application messages
    */
    while (1) {
        /* write a message to the serve */
        printf("Message for server: ");
        if(fgets(msg, sizeof(msg), fin) <= 0)
            break;
        sendSz = strnlen(msg, sizeof(msg));

        if ((ret = SSL_write(ssl, msg, sendSz)) < 0) {
            err = SSL_get_error(ssl, 0);
            printf("ERROR: failed to write entire message\n");
            printf("SSL_write error %d, %s\n", err,
                   ERR_error_string(err, NULL));
            if (ret != sendSz) {
                printf("%d bytes of %d bytes were sent", ret, (int)sendSz);
            }
            goto cleanup;
        }

        if (strncmp(msg, "shutdown", 8) == 0) {
            printf("sending server shutdown command: shutdown!\n");
            ret = SSL_SUCCESS;
            break;
        }


        /* read a message from the server */
        if ((ret = SSL_read(ssl, reply, sizeof(reply) - 1)) > 0) {
            reply[ret] = 0;
            printf("Server: %s\n", reply);
        } else {
            err = SSL_get_error(ssl, 0);
            fprintf(stderr, "ERROR : failed to read entire message\n");
            fprintf(stderr, "SSL_read error %d, %s\n", err,
                    ERR_error_string(err, NULL));
            fprintf(stderr, "%d bytes of %d bytes were received",
                    ret, (int)sendSz);
            goto cleanup;
        }
    }


/* 
 * Cleanup and return 
 */
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
    return ret;
}

