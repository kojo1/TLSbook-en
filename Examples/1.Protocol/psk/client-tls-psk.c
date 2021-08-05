
/* 
 * client-tls-psk.c
 */
#include "example_common.h"

#include <openssl/ssl.h>

#define CA_CERT_FILE        "../../certs/tb-ca-cert.pem"
#define LOCALHOST           "127.0.0.1"
#define DEFAULT_PORT        11111
#define PSK_KEY_LEN         4

#define MSG_SIZE            256

static const char* kIdentityStr = "Client_identity";

/* psk client set up */
static inline unsigned int my_psk_client_cb(SSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;

    /* The identity is OpenSSL testing default */
    strncpy(identity, kIdentityStr, id_max_len);
    /* The key is an example in OpenSSL man page */
    key = (unsigned char*)"\x1a\x2b\x3c\x4d";

    if (strlen((const char*)key) < key_max_len) {
        return strlen((const char*)key);
    }
    else {
        return 0;
    }
}

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
    int                ret = SSL_FAILURE;

    /* SSL objects */
    SSL_CTX* ctx = NULL;
    SSL*     ssl = NULL;

    /* Check for proper calling convention */
    if (argc == 2) {
        ipadd = (char *)argv[1];
    } else if (argc == 1) {
        fprintf(stderr, "Send to localhost(%s)\n", LOCALHOST);
        ipadd = LOCALHOST;
    } else {
        fprintf(stderr, "ERROR: Too many arguments.\n");
        goto cleanup;
    }

    /* Initialize library */
    if (SSL_library_init() != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to initialize the library\n");
        goto cleanup;
    }
    
    /* Create and initialize an SSL context object*/
    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create an SSL context object\n");
        goto cleanup;
    }

    /* set up pre shared keys */
    SSL_CTX_set_psk_client_callback(ctx, my_psk_client_cb);

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
    if (sockfd != -1)
        close(sockfd);
    if (ctx != NULL)
        SSL_CTX_free(ctx);
    if (ret != SSL_SUCCESS)
        ret = SSL_FAILURE;
    printf("End of TLS Client\n");
    return ret;
}

