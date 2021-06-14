/*
 * server-tls.c
 * simple server program
 */
#include "example_common.h"

#define SERVER_CERT_FILE    "../../certs/tb-server-cert.pem"
#define SERVER_KEY_FILE     "../../certs/tb-server-key.pem"

#define DEFAULT_PORT        11111
#define MSG_SIZE            256

int main(int argc, char** argv)
{
    int                sockfd;
    int                connd;
    struct sockaddr_in servAddr;
    struct sockaddr_in clientAddr;
    socklen_t          size = sizeof(clientAddr);
    char               buff[MSG_SIZE];
    size_t             len;
    int                shutdown = 0;
    int                reply_idx = 0;
    int                ret, err;
    const char*        reply = "I hear ya fa shizzle!";

   /* 
    * Declare wolfSSL objects
    */
    SSL_CTX* ctx;
    SSL*     ssl;

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
        fprintf(stderr, "ERROR: failed to create SSL_CTX\n");
        ret = -1;
        goto socket_cleanup;
    }

   /*
    * Load server certificates into SSL_CTX
    */
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM)
        != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                SERVER_CERT_FILE);
        ret = 1;
        goto ctx_cleanup;
    }

   /*
    * Load server key into SSL_CTX
    */
    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM)
        != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                SERVER_KEY_FILE);
        ret = 1;
        goto ctx_cleanup;
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
        goto ctx_cleanup;
    }

   /* 
    * Listen for a new connection, allow 5 pending connections
    */
    if (listen(sockfd, 5) == -1) {
        fprintf(stderr, "ERROR: failed to listen\n");
        ret = 1;
        goto ctx_cleanup;
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
        * Create a SSL object
        */
        if ((ssl = SSL_new(ctx)) == NULL) {
            fprintf(stderr, "ERROR: failed to create SSL object\n");
            ret = 1;
            goto cleanup;
        }
        
       /*
        * Attach wolfSSL to the socket
        */
        SSL_set_fd(ssl, connd);
        
       /*
        * Establish TLS connection 
        */
        do {
            err = 0;
            ret = SSL_accept(ssl);
            if (ret != SSL_SUCCESS) {
                err = SSL_get_error(ssl, 0);
            }
        } while (err == SSL_SUCCESS);
        
        if (ret != SSL_SUCCESS) {
            printf("wolfSSL_accept error = %d\n",
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
            do {
                err = 0; /* reset error */
                ret = SSL_read(ssl, buff, sizeof(buff)-1);
                if (ret <= 0) {
                    err = SSL_get_error(ssl, 0);
                }
            } while (err == SSL_SUCCESS);
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
            if (strncmp(buff, "break", 5) == 0) {
                printf("close this session\n");
                break;
            }
           /* 
            * Write our reply into buff 
            */
            memset(buff, 0, sizeof(buff));
            sprintf(buff, "%s[%d]\n", reply, reply_idx++);
            len = strnlen(buff, sizeof(buff));

            do {
                err = 0; /* reset error */
                ret = SSL_write(ssl, buff, len);
                if (ret <= 0) {
                    err = SSL_get_error(ssl, 0);
                }
            } while (err == SSL_SUCCESS);
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
    SSL_shutdown(ssl);  /* Shutdown SSL to try to send "close notify"   */
                        /* alert to the peer                            */
    SSL_free(ssl);      /* Free the SSL object                          */
ctx_cleanup:
    SSL_CTX_free(ctx);  /* Free the SSL context object                  */
socket_cleanup:
    close(sockfd);      /* Close the connection to the server           */
end:
    return ret;         /* Return reporting a success                   */
}
