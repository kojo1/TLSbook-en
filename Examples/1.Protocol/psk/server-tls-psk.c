/* 
 * psk-server.c
 */
#include "example_common.h"

#include <openssl/ssl.h>


#define SERVER_CERT_FILE    "../../certs/tb-server-cert.pem"
#define SERVER_KEY_FILE     "../../certs/tb-server-key.pem"

#define DEFAULT_PORT        11111

#define PSK_KEY_LEN         4

#define MSG_SIZE            256

 /* Identify which psk key to use.                                      */
 /* @param ssl a pointer to SSL object                                  */
 /* @param identity id to identify key                                  */
 /* @param key pre shared key                                           */
 /* @param key_max_len maximum length of the key                        */
 /* @return key length on success, otherwise 0                          */
static unsigned int my_psk_server_cb(SSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)key_max_len;

    if (strncmp(identity, "Client_identity", 15) != 0) {
        printf("error!\n");
        return 0;
    }

    key[0] = 26;
    key[1] = 43;
    key[2] = 60;
    key[3] = 77;

    return PSK_KEY_LEN;
}

/* Print SSL error message */
static void print_SSL_error(const char *msg, SSL *ssl)
{
    int err;
    err = SSL_get_error(ssl, 0);
    fprintf(stderr, "ERROR: %s (err %d, %s)\n", msg, err,
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
    const char         *reply = "I hear ya fa shizzle!";
    int                ret;

    /* Declare SSL objects */
    SSL_CTX* ctx = NULL;
    SSL*     ssl = NULL;

    len = strlen(reply);

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

    /* use psk suite for security */
    SSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);

    /* 
    * Create a socket, bind and listen
    */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create a socket. errno %d\n", errno);
        goto cleanup;
    }
    memset(&servAddr, 0, sizeof(servAddr));

    servAddr.sin_family      = AF_INET;             /* using IPv4      */
    servAddr.sin_port        = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
    servAddr.sin_addr.s_addr = INADDR_ANY;          /* from anywhere   */

    if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to bind. errno %d\n", errno);
        goto cleanup;
    }

    if (listen(sockfd, 5) == -1) {
        fprintf(stderr, "ERROR: failed to listen. errno %d\n", errno);
        goto cleanup;
    }

   /* Continue to accept clients until shutdown is issued */
    while (1) {
        printf("Waiting for a connection...\n");
        
       /* Accept client connections */
        if ((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size)) == -1) {
            fprintf(stderr, "ERROR: failed to accept. errno %d\n", errno);
            goto cleanup;
        }
        
       /* Create an SSL object */
        if ((ssl = SSL_new(ctx)) == NULL) {
            fprintf(stderr, "ERROR: failed to create an SSL object\n");
            goto cleanup;
        }
        
       /* Attach a socket to SSL */
        SSL_set_fd(ssl, connd);
        
       /*Establish TLS connection  */
        if ((ret = SSL_accept(ssl)) != SSL_SUCCESS) {
            print_SSL_error("failed SSL accept", ssl);
            goto cleanup;
        }
        
        printf("Client connected successfully\n");

        /* 
        * Application messaging
        */
        while(1) {
            memset(buff, 0, sizeof(buff));

            /* receive a message from the cliet */
            if ((ret = SSL_read(ssl, buff, sizeof(buff)-1)) <= 0) {
                print_SSL_error("failed SSL read", ssl);
                break;
            }
            else {
                /* Print to stdout any data the client sends  */
                printf("Received: %s\n", buff);
            }
            
           /* Check for server shutdown command */
            if (strncmp(buff, "shutdown", 8) == 0) {
                printf("Received shutdown command\n");
                goto cleanup;
            }

            /* send the reply to the client */
            if ((ret = SSL_write(ssl, reply, len)) != len) {
                if (ret < 0) {
                    print_SSL_error("failed SSL write", ssl);
                    ret = SSL_FAILURE;
                    break;
                }
                fprintf(stderr, "%d bytes of %d bytes were sent\n", ret, len);
            }
        }
        if (ssl != NULL && ret <= 0) {
            SSL_shutdown(ssl);
        }
        /* Cleanup after the connection */
        SSL_free(ssl); 
        ssl = NULL;
        close(connd);
        connd = -1;
        printf("Closed the connection\n");
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
    printf("End of TLS Server\n");
    return ret;
}
