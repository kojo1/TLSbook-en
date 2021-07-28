#include <openssl/ssl.h>
#include "mem-comm.h"

void client_main(void);
void server_main(void);

int main(int argc, char **argv)
{

    mem_init(0);
    mem_init(1);

    while (1)
    {
        client_main();
        server_main();
    }
}