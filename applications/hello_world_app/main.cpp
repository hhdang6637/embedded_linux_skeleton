/* Compile with: gcc -Wall -lfcgi fastcgi.c -o fastcgi
 */

#include <stdio.h>
#include <stdlib.h>

#include "rpcUnixClient.h"
#include "rpcMessageResourceHistory.h"

int main(void) {

    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();

    app::rpcMessageResourceHistory msg;

    if (rpcClient->doRpc(&msg)) {
        for(auto &i : msg.get_cpu_history()) {
            std::cout << i.total << std::endl;
        }
    }
    return EXIT_SUCCESS;
}
