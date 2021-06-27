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


#include <openssl/err.h>

#undef  SSL_SUCCESS
#define SSL_SUCCESS 1
#undef  SSL_FAILURE
#define SSL_FAILURE 0



#endif /* _EAMPLE_COMMON_H_ */
