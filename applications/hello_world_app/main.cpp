/* Compile with: gcc -Wall -lfcgi fastcgi.c -o fastcgi
 */

#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <unistd.h>
#include <syslog.h>

#include "rpcUnixClient.h"
#include "rpcMessageUsers.h"

static bool openssl_init()
{
    system("mkdir -p /tmp/myCA");
    system("mkdir -p /tmp/myCA/certs");
    system("mkdir -p /tmp/myCA/keys");
    system("mkdir -p /tmp/myCA/reqs");
    system("touch /tmp/myCA/index.txt");
    system("echo 01 >> /tmp/myCA/serial");
    return true;
}

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

static bool openssl_req(const char *dst_key, const char* dst_csr, int days, int bitSize) {
    // ex: openssl req -nodes -newkey rsa:1024 -keyout /tmp/myCA/keys/server.pem -config /tmp/myCA/server.cnf -days 365 -keyform PEM -out /tmp/myCA/reqs/server.pem -outform PEM

    std::string command_gen_req;

    command_gen_req += " openssl req -nodes -newkey rsa:";
    command_gen_req += std::to_string(bitSize);
    command_gen_req += " -keyout ";
    command_gen_req += dst_key;
    command_gen_req += " -config /tmp/myCA/server.cnf -days ";
    command_gen_req += std::to_string(days);
    command_gen_req += " -keyform PEM -out  ";
    command_gen_req += dst_csr;
    command_gen_req += " -outform PEM ";
    printf("Command Gen REQ: %s\n", command_gen_req.c_str());
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
        command_gen_ca_crt += "openssl req -config /tmp/myCA/CA.cnf -new -x509 -days ";
        command_gen_ca_crt += std::to_string(days);
        command_gen_ca_crt += " -key ";
        command_gen_ca_crt += ca_key;
        command_gen_ca_crt += " -out ";
        command_gen_ca_crt += ca_crt;
        command_gen_ca_crt += " -outform PEM ";
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

static bool openssl_sign(const char* src_csr, const char* dst_crt, int days)
{
    // ex: openssl ca -config configCA.cnf -in req/server.csr -out cert/server.crt
    std::string command_sign;
    command_sign += "openssl ca -config /tmp/myCA/CA.cnf -in ";
    command_sign += src_csr;
    command_sign += " -days ";
    command_sign += std::to_string(days);
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

   const char* caKey = "/tmp/myCA/keys/ca.key";
   const char* caCrt = "/tmp/myCA/certs/ca.crt";
   const char* serverKey = "/tmp/myCA/keys/server.key";
   const char* serverCSR = "/tmp/myCA/reqs/server.csr";
   const char* serverCrt = "/tmp/myCA/certs/server.crt";

   openssl_init();

   if(openssl_gen_ca(caKey, caCrt, 365) == true)
   {
       printf("Generated CA: %s && %s\n", caKey, caCrt);
   }
   else
   {
       printf("Generate CA Error\n");
   }

    if(openssl_req(serverKey, serverCSR, 365, 1024) == true)
    {
        printf("Generated server: %s && %s\n", serverKey, serverCrt);
    }
    else
    {
        printf("Generate server.csr Error\n");
    }

    if(openssl_sign(serverCSR, serverCrt, 365) == true)
    {
        printf("Signatured for server.crt OK\n");
    }
    else
    {
        printf("Server.crt NOT sign\n");
    }
    return EXIT_SUCCESS;
}
