/* psk-server.c
*/

#include "example_common.h"

#define MAXLINE     4096
#define LISTENQ     1024
#define SERV_PORT   11111
#define PSK_KEY_LEN 4

/*
 * Identify which psk key to use.
 */
static unsigned int my_psk_server_cb(SSL* ssl, const char* identity,
                           unsigned char* key, unsigned int key_max_len)
{
    (void)ssl;
    (void)key_max_len;

    if (strncmp(identity, "Client_identity", 15) != 0) {
        return 0;
    }

    key[0] = 26;
    key[1] = 43;
    key[2] = 60;
    key[3] = 77;

    return PSK_KEY_LEN;
}

int main()
{
    int  n;              /* length of string read */
    int                 listenfd, connfd, ret;
    int                 opt;
    char                buff[MAXLINE];
    char buf[MAXLINE];   /* string read from client */
    char response[] = "I hear ya for shizzle";
    char suites[]   = "PSK-AES256-GCM-SHA384:"
                      "PSK-AES128-GCM-SHA256:"
                      "PSK-AES256-CBC-SHA384:"
                      "PSK-AES128-CBC-SHA256:"
                      "PSK-AES128-CBC-SHA:"
                      "PSK-AES256-CBC-SHA:"
                      "PSK-CHACHA20-POLY1305:"
                      "TLS13-AES128-GCM-SHA256:"
                      "TLS13-AES256-GCM-SHA384:"
                      "TLS13-CHACHA20-POLY1305-SHA256:"
                      "DHE-PSK-AES256-GCM-SHA384:"
                      "DHE-PSK-AES128-GCM-SHA256:"
                      "DHE-PSK-AES256-CBC-SHA384:"
                      "DHE-PSK-AES128-CBC-SHA256:"
                      "DHE-PSK-CHACHA20-POLY1305:"
                      "ECDHE-PSK-AES128-CBC-SHA256:"
                      "ECDHE-PSK-CHACHA20-POLY1305:";

    struct sockaddr_in  cliAddr, servAddr;
    socklen_t           cliLen;
    
    SSL_CTX*         ctx;

    /* set up server address and port */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family      = AF_INET;
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servAddr.sin_port        = htons(SERV_PORT);

    /* find a socket */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listenfd < 0) {
        printf("Fatal error : socket error\n");
        return 1;
    }

    /* bind to a socket */
    opt = 1;
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&opt,
               sizeof(int)) != 0) {
        printf("Fatal error : setsockopt error\n");
        ret = -1;
        goto end;
    }
    if (bind(listenfd, (struct sockaddr *) &servAddr, sizeof(servAddr)) < 0) {
        printf("Fatal error : bind error\n");
        ret = -1;
        goto end;
    }

    /* listen to the socket */
    if (listen(listenfd, LISTENQ) < 0) {
        printf("Fatal error : listen error\n");
        ret = -1;
        goto end;
    }

    if ((ret = SSL_library_init()) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto socket_cleanup;
    }

    /* create ctx and configure certificates */
    if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
        printf("Fatal error : SSL_CTX_new error\n");
        ret = -1;
        goto socket_cleanup;
    }

    /* use psk suite for security */
    SSL_CTX_set_psk_server_callback(ctx, my_psk_server_cb);

    if ((ret = SSL_CTX_use_psk_identity_hint(ctx, "ssl server"))
         != SSL_SUCCESS) {
        printf("Fatal error : ctx use psk identity hint returned %d\n", ret);
        return ret;
    }

    if ((ret = SSL_CTX_set_cipher_list(ctx, suites)) != SSL_SUCCESS) {
        printf("Fatal error : server set cipher list returned %d\n", ret);
        return ret;
    }

    /* main loop for accepting and responding to clients */
    for ( ; ; ) {
        SSL* ssl;

        cliLen = sizeof(cliAddr);
        connfd = accept(listenfd, (struct sockaddr *) &cliAddr, &cliLen);
        if (connfd < 0) {
            printf("Fatal error : accept error\n");
            ret = -1;
            goto ctx_cleanup;
        }
        else {
            printf("Connection from %s, port %d\n",
            inet_ntop(AF_INET, &cliAddr.sin_addr, buff, sizeof(buff)),
                        ntohs(cliAddr.sin_port));

            /* create WOLFSSL object and respond */
            if ((ssl = SSL_new(ctx)) == NULL) {
                printf("Fatal error : SSL_new error\n");
                ret = -1;
                goto ctx_cleanup;
            }

            /* sets the file descriptor of the socket for the ssl session */
            SSL_set_fd(ssl, connfd);

            /* making sure buffered to store data sent from client is empty */
            memset(buf, 0, MAXLINE);

            /* reads and displays data sent by client if no errors occur */
            n = SSL_read(ssl, buf, MAXLINE);
            if (n > 0) {
                printf("%s\n", buf);
                /* server response */
                if (SSL_write(ssl, response, strlen(response)) >
                    strlen(response)) {
                    printf("Fatal error : respond: write error\n");
                    ret = -1;
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    goto ctx_cleanup;
                }
            }
            if (n < 0) {
                printf("Fatal error :respond: read error\n");
                ret = -1;
                SSL_shutdown(ssl);
                SSL_free(ssl);
                goto ctx_cleanup;
            }

            /* closes the connections after responding */
            SSL_shutdown(ssl);
            SSL_free(ssl);

            if (close(connfd) == -1) {
                printf("Fatal error : close error\n");
                ret = -1;
                goto ctx_cleanup;
            }
        }
    }
    /* free up memory used by SSL */
ctx_cleanup:
    SSL_CTX_free(ctx);  /* Free the SSL context object                  */
socket_cleanup:
    close(listenfd);      /* Close the connection to the server           */
end:
    return ret;
}

