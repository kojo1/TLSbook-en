/* 
 * psk-server.c
 */
#include "example_common.h"

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
int main(int argc, char** argv)
{
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t          size = sizeof(clientAddr);
    char               buff[MSG_SIZE];
    size_t             len;
    int                shutdown = 0;
    int                reply_idx = 0;
    int                sockfd;
    int                connd;
    int                ret, err;
    const char*        reply = "I hear ya fa shizzle!";

   /* 
    * Declare wolfSSL objects
    */
    SSL_CTX* ctx;
    SSL*     ssl;
   /*
    * Debugging Log On When enabled Debug Mode
    */
#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif
   /*
    * Initialize SSL 
    */
    SSL_library_init();

   /* 
    * Create a socket that uses an internet IPv4 address,
    * Sets the socket to be stream based (TCP),
    * 0 means choose the default protocol.
    */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1;
        goto end;
    }

   /*
    * Create and initialize SSL_CTX
    */
    if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create the SSL context object\n");
        ret = -1;
        goto cleanup;
    }

    /* use psk suite for security */
    SSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);

   /*
    * Load server key into SSL_CTX
    */
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM)
        != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                SERVER_KEY_FILE);
        ret = 1;
        goto cleanup;
    }

   /*
    * Initialize the server address struct with zeros
    */
    memset(&servAddr, 0, sizeof(servAddr));

   /* 
    * Fill in the server address
    */
    servAddr.sin_family      = AF_INET;             /* using IPv4      */
    servAddr.sin_port        = htons(DEFAULT_PORT); /* on DEFAULT_PORT */
    servAddr.sin_addr.s_addr = INADDR_ANY;          /* from anywhere   */

   /* 
    * Bind the server socket to our port
    */
    if (bind(sockfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) == -1) {
        fprintf(stderr, "ERROR: failed to bind\n");
        ret = 1;
        goto cleanup;
    }

   /* 
    * Listen for a new connection, allow 5 pending connections
    */
    if (listen(sockfd, 5) == -1) {
        fprintf(stderr, "ERROR: failed to listen\n");
        ret = 1;
        goto cleanup;
    }

   /* 
    * Continue to accept clients until shutdown is issued
    */
    while (!shutdown) {
        printf("Waiting for a connection...\n");
        
       /*
        * Accept client connections
        */
        if ((connd = accept(sockfd, (struct sockaddr*)&clientAddr, &size))
            == -1) {
            fprintf(stderr, "ERROR: failed to accept the connection\n\n");
            ret = 1;
            goto cleanup;
        }
        
       /*
        * Create the SSL object
        */
        if ((ssl = SSL_new(ctx)) == NULL) {
            fprintf(stderr, "ERROR: failed to create the SSL object\n");
            ret = 1;
            goto cleanup;
        }
        
       /*
        * Attach the socket to SSL
        */
        SSL_set_fd(ssl, connd);
        
       /*
        * Establish TLS connection 
        */
        err = 0;
        ret = SSL_accept(ssl);
        if (ret != SSL_SUCCESS) {
            err = SSL_get_error(ssl, 0);
        }
        
        if (ret != SSL_SUCCESS) {
            printf("SSL_accept error = %d\n",
                            SSL_get_error(ssl, ret));
            ret = 1;
            goto cleanup;
        }
        
        printf("Client connected successfully\n");
        
        while(1) {
            /* 
             * Read the client data into our buff array 
             */
            memset(buff, 0, sizeof(buff));
            
            err = 0; /* reset error */
            ret = SSL_read(ssl, buff, sizeof(buff)-1);
            if (ret <= 0) {
                err = SSL_get_error(ssl, 0);
            }
            
            if (ret > 0) {
               /* 
                * Print to stdout any data the client sends 
                */
                printf("Client: %s\n", buff);
            }
            else {
                printf("ERROR : Failed to read entire message\n");
                printf("SSL_read error %d, %s\n", err,
                                              ERR_error_string(err, NULL));
                ret = 1;
                goto cleanup;
            }
            
           /*
            * Check for server shutdown command
            */
            if (strncmp(buff, "shutdown", 8) == 0) {
                printf("Shutdown command issued!\n");
                shutdown = 1;
                goto cleanup;
            }
           /* 
            * Write our reply into buff 
            */
            memset(buff, 0, sizeof(buff));
            sprintf(buff, "%s[%d]\n", reply, reply_idx++);
            len = strnlen(buff, sizeof(buff));

            err = 0; /* reset error */
            ret = SSL_write(ssl, buff, len);
            if (ret <= 0) {
                err = SSL_get_error(ssl, 0);
            }
            if (ret != len) {
                printf("ERROR : Failed to write entire message\n");
                printf("SSL_write error %d, %s\n", err,
                                              ERR_error_string(err, NULL));
                ret = 1;
                goto cleanup;
            }
        }
        /* 
         * Cleanup after this connection 
         */
        SSL_free(ssl);      /* Free the wolfSSL object              */
        close(connd);       /* Close the connection to the client   */
        ssl = NULL;
    }

    printf("Shutdown complete\n");

/* 
 * Cleanup and return 
 */
cleanup:
    if (ssl != NULL) {
       /*
        * Shutdown SSL to try to send "close notify" alert to the peer
        */
        SSL_shutdown(ssl);
       /* 
        * Free the SSL object 
        */
        SSL_free(ssl);
    }
    
    if (ctx != NULL) {
        /* 
         * Free the SSL context object
         */
         SSL_CTX_free(ctx);
    }
    /*
     * Close the connection to the server   
     */
    close(sockfd);
end:
    return ret;
}
