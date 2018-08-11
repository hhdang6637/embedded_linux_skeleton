/* Compile with: gcc -Wall -lfcgi fastcgi.c -o fastcgi
 */

#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <unistd.h>
#include <syslog.h>

#include "rpcUnixClient.h"
#include "rpcMessageUsers.h"

int main(void) {

    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageUsers msgUser;

    if (rpcClient->doRpc(&msgUser) == false) {
        std::cout << "something went wrong: doRpc\n";
        return EXIT_FAILURE;
    }

    std::list<app::user> users = msgUser.getUsers();
    for(auto &u : users) {
        std::cout << u.getName() << "\n";
    }

    return EXIT_SUCCESS;
}
