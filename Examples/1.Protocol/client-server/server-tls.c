/*
 * server-tls.c
 * simple server program
 */
#include "example_common.h"

#include <openssl/ssl.h>

#define SERVER_CERT_FILE    "../../certs/tb-server-cert.pem"
#define SERVER_KEY_FILE     "../../certs/tb-server-key.pem"

#define DEFAULT_PORT        11111
#define MSG_SIZE            256

static void ssl_get_error(const char* msg, SSL* ssl)
{
    int err;

    err = SSL_get_error(ssl, 0);
    fprintf(stderr, "ERROR : %s (err %d, %s)\n", msg, err,
                    ERR_error_string(err, NULL));

}

int main(int argc, char** argv)
{
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t          size = sizeof(clientAddr);
    int                sockfd = -1;
    int                connd = -1;
    
    char               buff[MSG_SIZE];
    int                len;

    int                ret;
    const char*        reply = "I hear ya fa shizzle!";

    /* Declare SSL objects */
    SSL_CTX* ctx = NULL;
    SSL*     ssl = NULL;

    /* Initialize library */
    if (SSL_library_init() != SSL_SUCCESS) {
        printf("ERROR: Failed to initialize the library\n");
        goto cleanup;
    }

#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON(); /* Debug log when Debug Mode is enabled */
#endif

   /* Create and initialize an SSL context object */
    if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create an SSL context object\n");
        goto cleanup;
    }

   /* Load server certificates into an SSL context object */
    if ((ret = SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, 
        SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s\n", SERVER_CERT_FILE);
        goto cleanup;
    }

   /* Load server key into an SSL context object */
    if ((ret = SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, 
        SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s\n", SERVER_KEY_FILE);
        goto cleanup;
    }
    /* 
    * Create a socket, bind and listen
    */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create a socket errno %d\n", errno);
        goto cleanup;
    }
    memset(&servAddr, 0, sizeof(servAddr));

    servAddr.sin_family      = AF_INET;             /* using IPv4      */
    servAddr.sin_port        = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
    servAddr.sin_addr.s_addr = INADDR_ANY;          /* from anywhere   */

    if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to bind errno %d\n", errno);
        goto cleanup;
    }

    if (listen(sockfd, 5) == -1) {
        fprintf(stderr, "ERROR: failed to listen errno %d\n", errno);
        goto cleanup;
    }

   /* Continue to accept clients until shutdown is issued */
    while (1) {
        printf("Waiting for a connection...\n");
        
       /* Accept client connections */
        if ((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size)) == -1) {
            fprintf(stderr, "ERROR: failed to accept the connection errno %d\n", errno);
            goto cleanup;
        }
        
       /* Create an SSL object */
        if ((ssl = SSL_new(ctx)) == NULL) {
            fprintf(stderr, "ERROR: failed to create the SSL object\n");
            goto cleanup;
        }
        
       /* Attach a socket to SSL */
        SSL_set_fd(ssl, connd);
        
       /*Establish TLS connection  */
        if ((ret = SSL_accept(ssl)) != SSL_SUCCESS) {
            ssl_get_error("failed SSL accept", ssl);
            goto cleanup;
        }
        
        printf("Client connected successfully\n");
        
        while(1) {
            /* Read the client data into our buff array */
            memset(buff, 0, sizeof(buff));
            
            if ((ret = SSL_read(ssl, buff, sizeof(buff)-1)) <= 0) {
                ssl_get_error("failed SSL read", ssl);
                break;
            }
            else {
                /* Print to stdout any data the client sends  */
                printf("Client: %s\n", buff);
            }
            
           /* Check for server shutdown command */
            if (strncmp(buff, "shutdown", 8) == 0) {
                printf("Shutdown command issued!\n");
                goto cleanup;
            }
           /* Write our reply into buff */
            if ((len = sprintf(buff, "%s\n", reply)) < 0) {
                fprintf(stderr, "ERROR : failed sprintf err %d\n", len);
                goto cleanup;
            } 
            
            if ((ret = SSL_write(ssl, buff, len)) != len) {
                if (ret < 0) {
                    ssl_get_error("failed SSL write", ssl);
                    ret = SSL_FAILURE;
                    break;
                }
                fprintf(stderr, "%d bytes of %d bytes were sent\n", ret, len);
            }
        }
        if (ssl != NULL && ret <= 0) {
            SSL_shutdown(ssl);
        }
        /* Cleanup after this connection */
        SSL_free(ssl); 
        ssl = NULL;

        close(connd);
        connd = -1;
    }

    printf("Shutdown complete\n");

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
    
    return ret;
}
