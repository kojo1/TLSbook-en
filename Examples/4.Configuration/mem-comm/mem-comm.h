/* 
 * mem_comms.h
 * Memory communication
 */

void  mem_init(int);
void *mem_getCH(int no);

int mem_send(SSL *ssl, char *buff, int sz, void *ctx);
int mem_recv(SSL *ssl, char *buff, int sz, void *ctx);
