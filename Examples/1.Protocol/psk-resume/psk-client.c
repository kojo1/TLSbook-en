
/* client-psk.c
 */

#include "example_common.h"

#define     MAXLINE 256      /* max text line length */
#define     SERV_PORT 11111  /* default port*/
#define     PSK_KEY_LEN 4

/*
 *psk client set up.
 */
static inline unsigned int My_Psk_Client_Cb(SSL* ssl, const char* hint,
        char* identity, unsigned int id_max_len, unsigned char* key,
        unsigned int key_max_len)
{
    (void)ssl;
    (void)hint;
    (void)key_max_len;

    /* identity is OpenSSL testing default for openssl s_client, keep same*/
    strncpy(identity, "Client_identity", id_max_len);

    /* test key n hex is 0x1a2b3c4d , in decimal 439,041,101, we're using
     * unsigned binary */
    key[0] = 26;
    key[1] = 43;
    key[2] = 60;
    key[3] = 77;

    return PSK_KEY_LEN;
}

int main(int argc, char **argv)
{
    int ret, sockfd;
    char sendline[MAXLINE]="Hello Server"; /* string to send to the server */
    char recvline[MAXLINE];             /* string received from the server */
    struct sockaddr_in servaddr;;

    SSL* ssl;
    SSL_CTX* ctx;

    /* must include an ip address of this will flag */
    if (argc != 2) {
        printf("Usage: tcpClient <IPaddress>\n");
        return 1;
    }

    /* create a stream socket using tcp,internet protocal IPv4,
     * full-duplex stream */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    /* places n zero-valued bytes in the address servaddr */
    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);

    /* converts IPv4 addresses from text to binary form */
    ret = inet_pton(AF_INET, argv[1], &servaddr.sin_addr);
    if (ret != 1) {
        printf("inet_pton error\n");
        ret = -1;
        goto end;
    }

    /* attempts to make a connection on a socket */
    ret = connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    if (ret != 0) {
        printf("Connection Error\n");
        goto end;
    }

    if ((ret = SSL_library_init()) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto socket_cleanup;
    }

    /* create and initialize WOLFSSL_CTX structure */
    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
        fprintf(stderr, "SSL_CTX_new error.\n");
        ret = -1;
        goto socket_cleanup;
    }

    /* set up pre shared keys */
    SSL_CTX_set_psk_client_callback(ctx, My_Psk_Client_Cb);

    /* creat wolfssl object after each tcp connct */
    if ( (ssl = SSL_new(ctx)) == NULL) {
        fprintf(stderr, "SSL_new error.\n");
        ret = -1;
        goto ctx_cleanup;
    }

    /* associate the file descriptor with the session */
    ret = SSL_set_fd(ssl, sockfd);
    if (ret != SSL_SUCCESS) {
        ret = -1;
        goto cleanup;
    }

    /* write string to the server */
    if (SSL_write(ssl, sendline, MAXLINE) != sizeof(sendline)) {
        printf("Write Error to Server\n");
        ret = -1;
        goto cleanup;
    }

    /* check if server ended before client could read a response  */
    if (SSL_read(ssl, recvline, MAXLINE) < 0 ) {
        printf("Client: Server Terminated Prematurely!\n");
        ret = -1;
        goto cleanup;
    }

    /* show message from the server */
    printf("Server Message: %s\n", recvline);

    /* when completely done using SSL/TLS, free the
     * wolfssl_ctx object */
cleanup:
    SSL_shutdown(ssl);  /* Shutdown SSL to try to send "close notify"   */
                        /* alert to the peer                            */
    SSL_free(ssl);      /* Free the SSL object                          */
ctx_cleanup:
    SSL_CTX_free(ctx);  /* Free the SSL context object                  */
socket_cleanup:
    close(sockfd);      /* Close the connection to the server           */
end:
    /* exit client */
    return ret;
}
