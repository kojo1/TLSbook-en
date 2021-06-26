/* 
 * client-tls.c
 * Simple Client Program
 */
#include "example_common.h"

#define CA_CERT_FILE        "../../certs/tb-ca-cert.pem"
#define LOCALHOST           "127.0.0.1"
#define DEFAULT_PORT        11111

#define MSG_SIZE            256
#define REPLY_SIZE          MSG_SIZE + 1

int main(int argc, char** argv)
{
    FILE*              fin = stdin;
    struct sockaddr_in servAddr;
    char               msg[MSG_SIZE];
    char               reply[REPLY_SIZE];
    static char*       target_add = LOCALHOST;
    char*              ipadd = NULL;
    size_t             sendSz;
    int                sockfd;
    int                ret, err;

   /* 
    * Declare SSL objects 
    */
    SSL_CTX* ctx = NULL;
    SSL*     ssl = NULL;

   /* 
    * Check for proper calling convention
    */
    if (argc != 2) {
        printf("use localhost(%s) as server ip address\n", target_add);
        ipadd = (char*)target_add;
    }
    else {
        ipadd = (char*)&argv[1];
    }

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
    * Initialize the server address struct with zeros 
    */
    memset(&servAddr, 0, sizeof(servAddr));

   /* 
    * Fill in the server address 
    */
    servAddr.sin_family = AF_INET;             /* using IPv4      */
    servAddr.sin_port   = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

   /* 
    * Get the server IPv4 address from the command line call
    */
    if (inet_pton(AF_INET, ipadd, &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        ret = -1;
        goto end;
    }

   /*---------------------------------
    * Start of security
    *---------------------------------
    */
   /*
    * Debugging Log On When enabled Debug Mode
    */
#if defined(DEBUG_WOLFSSL)
    wolfSSL_Debugging_ON();
#endif

   /* 
    * Initialize SSL
    */
    if ((ret = SSL_library_init()) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto cleanup;
    }

   /* 
    * Create and initialize WOLFSSL_CTX 
    */
    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create the SSL context object\n");
        ret = -1;
        goto cleanup;
    }

   /* 
    * Load client certificates into the SSL context object 
    */
    if ((ret = SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL))
         != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to load %s, please check the file.\n",
                CA_CERT_FILE);
        goto cleanup;
    }

   /* 
    * Create the SSL object
    */
    if ((ssl = SSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create the SSL object\n");
        ret = -1;
        goto cleanup;
    }
    
   /* 
    * Connect to the server 
    */
    if ((ret = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)))
         == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        goto cleanup;
    }
   /* 
    * Attach the socket to SSL
    */
    if ((ret = SSL_set_fd(ssl, sockfd)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto cleanup;
    }
    
   /* 
    * Connect to SSL on the server side 
    */
    err = 0;
    ret = SSL_connect(ssl);
    
    if (ret != SSL_SUCCESS) {
        err = SSL_get_error(ssl, 0);
    }
    
    if (ret != SSL_SUCCESS) {
        printf("ERROR: failed to connect to SSL(err %d, %s)\n", 
            ret, ERR_error_string(err, NULL));
        goto cleanup;
    }
    
   /* 
    * Message to the server from stdin
    * Read message from the server
    */
    printf("Message for server: ");
    while (fgets(msg, sizeof(msg), fin) != 0) {
        
        sendSz = strnlen(msg, sizeof(msg));
        
       /*
        * send message to the server
        */
        err = 0;
        ret = SSL_write(ssl, msg, sendSz);
        if (ret != SSL_SUCCESS) {
            err = SSL_get_error(ssl, 0);
        }
        
        if (ret != sendSz) {
            printf("ERROR: failed to write entire message\n");
            printf("SSL_write error %d, %s\n", err,
                                              ERR_error_string(err, NULL));
            printf("%d bytes of %d bytes were sent", 
                                                        ret, (int) sendSz);
            ret = -1;
            goto cleanup;
        }
        
        if (strncmp(msg, "shutdown", 8) == 0) {
            printf("sending server shutdown command: shutdown!\n");
            break;
        }
       /*
        * read message from the server
        */
        err = 0;
        ret = SSL_read(ssl, reply, sizeof(reply)-1);
        if (ret <= 0) {
            err = SSL_get_error(ssl, 0);
        }
        
        if (ret > 0) {
            reply[ret] = 0;
           /* 
            * Print to stdout any data the server sends 
            */
            printf("Server: %s\n", reply);
        }
        else {
            fprintf(stderr, "ERROR : failed to read entire message\n");
            fprintf(stderr, "SSL_read error %d, %s\n", err,
                                              ERR_error_string(err, NULL));
            fprintf(stderr, "%d bytes of %d bytes were received", 
                                                        ret, (int) sendSz);
            ret = -1;
            goto cleanup;
        }

        printf("Message for server: ");
    }
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
