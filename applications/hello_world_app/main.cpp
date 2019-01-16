/* Compile with: gcc -Wall -lfcgi fastcgi.c -o fastcgi
 */

#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <unistd.h>
#include <syslog.h>

#include "rpcUnixClient.h"
#include "rpcMessageUsers.h"

static bool openssl_genrsa(const char *dst_key, int bitsize) {
    // ex: openssl genrsa -des3 -out ca.key 4096
    std::string command_genrsakey;

    command_genrsakey += "openssl genrsa -out ";
    command_genrsakey += dst_key;
    command_genrsakey += " ";
    command_genrsakey += std::to_string(bitsize);
    printf("Command genRSA: %s\n", command_genrsakey.c_str());
    if(system(command_genrsakey.c_str()) == 0)
    {
        return true;
    }

    return false;
}

static bool openssl_req(const char *src_key, const char* dst_csr, int days) {
    // ex: openssl req -days 365 -new -key server.key -out server.csr
    std::string command_gen_req;

    command_gen_req += " openssl req -new -x509 -days ";
    command_gen_req += std::to_string(days);
    command_gen_req += " -key ";
    command_gen_req += src_key;
    command_gen_req += " ";
    command_gen_req += " -out ";
    command_gen_req += dst_csr;

    if(system(command_gen_req.c_str()) == 0)
    {
        return true;
    }
    return false;
}

static bool openssl_gen_ca(const char* ca_key, const char* ca_crt, int days)
{
    // openssl req -new -x509 -days 365 -key ca.key -out ca.crt
    if(openssl_genrsa(ca_key, 4096) == true)
    {
        std::string command_gen_ca_crt;
        command_gen_ca_crt += "openssl req -new -x509 -days ";
        command_gen_ca_crt += std::to_string(days);
        command_gen_ca_crt += " -key ";
        command_gen_ca_crt += ca_key;
        command_gen_ca_crt += " -out ";
        command_gen_ca_crt += ca_crt;
        printf("Gen ca Certificate: %s\n", command_gen_ca_crt.c_str());
        if(system(command_gen_ca_crt.c_str()) == 0)
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    return false;
}

static bool openssl_sign(const char* src_csr, const char* dst_crt, const char* ca_key, const char* ca_crt)
{
    // ex: openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt
    std::string command_sign;
    command_sign += "openssl x509 -req -in ";
    command_sign += src_csr;
    command_sign +=" -CA ";
    command_sign += ca_crt;
    command_sign += " -CAkey ";
    command_sign += ca_key;
    command_sign += " -out ";
    command_sign += dst_crt;
    printf("Sign command: %s\n", command_sign.c_str());
    if(system(command_sign.c_str()) == 0)
    {
        return true;
    }

    return false;
}

int main(void) {
    /*
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageUsers msgUser;

    app::user u1("test", "test", "test user", "test@gmail.com");
    msgUser.setUser(u1);

    if (rpcClient->doRpc(&msgUser) == false) {
        std::cout << "something went wrong: doRpc\n";
        return EXIT_FAILURE;
    }

    std::list<app::user> users = msgUser.getUsers();
    for(auto &u : users) {
        std::cout << u.getName() << "\n";
    }

    */

   const char* caKey = "/tmp/ca.key";
   const char* caCrt = "/tmp/ca.crt";
   const char* serverKey = "/tmp/server.key";
   const char* serverCSR = "/tmp/server.csr";
   const char* serverCrt = "/tmp/server.crt";

   if(openssl_gen_ca(caKey, caCrt, 365) == true)
   {
       printf("Generated CA in /tmp/ \n");
   }
   else
   {
       printf("Generate CA Error\n");
   }

    if(openssl_genrsa(serverKey, 1024) == true)
    {
        printf("Generated server.key\n");
    }
    else
    {
        printf("Generate server Error\n");
    }

    if(openssl_req(serverKey, serverCSR, 365) == true)
    {
        printf("Generated server.csr\n");
    }
    else
    {
        printf("Generate server.csr Error\n");
    }

    if(openssl_sign(serverCSR, serverCrt, caKey, caCrt) == true)
    {
        printf("Signatured for server.crt\n");
    }
    else
    {
        printf("Server.crt NOT sign\n");
    }
    return EXIT_SUCCESS;
}
