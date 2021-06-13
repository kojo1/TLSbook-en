/*
* common header file
*/
#ifndef _EXAMPLE_COMMON_H_
#define _EXAMPLE_COMMON_H_

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#undef  SSL_SUCCESS
#define SSL_SUCCESS 1
#undef  SSL_FAILURE
#define SSL_FAILURE 0

#define DEFAULT_PORT 11111

#define CA_CERT_FILE        "../../certs/tb-ca-cert.pem"
#define SERVER_CERT_FILE    "../../certs/tb-server-cert.pem"
#define SERVER_KEY_FILE     "../../certs/tb-server-key.pem"

#endif /* _EAMPLE_COMMON_H_ */
