/*
 * openVpnManager.cpp
 *
 *  Created on: Jan 13, 2019
 *      Author: hhdang6637
 */

#include "openVpnManager.h"
#include <sys/stat.h>
#include <string>

static app::openvpnCfg_t openvpnCfg;

static bool openVpnManager_store() {
    return false;
}

static bool openVpnManager_load() {
    return false;
}

static void openvpnCfg_get_default(app::openvpnCfg_t *openvpnCfg_ptr) {
}

static void openvpnCfg_set_default(app::openvpnCfg_t *openvpnCfg_ptr) {
    openvpnCfg_ptr->state = 0;
    openvpnCfg_ptr->port = 5000;
}

static bool openvpnCfg_valid(app::openvpnCfg_t *openvpnCfg_ptr) {
    return false;
}

static bool openvpn_cfg_handler(int socket_fd)
{
    app::rpcMessageOpenvpnCfg msgOpenvpnCfg;

    if (msgOpenvpnCfg.deserialize(socket_fd)) {

        if (msgOpenvpnCfg.getMsgAction() == app::rpcMessageOpenvpnCfgActionType::GET_OPENVPN_CFG) {
            app::openvpnCfg_t openvpnCfg_data;
            openVpnManager_openvpnCfg_get(&openvpnCfg_data); // nerver fail
            msgOpenvpnCfg.setOpenvpnCfg_data(openvpnCfg_data);
            msgOpenvpnCfg.setMsgResult(app::rpcMessageOpenvpnResultType::SUCCESS);
        } else {
            // TODO
            msgOpenvpnCfg.setMsgResult(app::rpcMessageOpenvpnResultType::FAILED);
        }

        return msgOpenvpnCfg.serialize(socket_fd);
    }

    return false;
}

void openVpnManager_init(app::rpcUnixServer &rpcServer) {
    openvpnCfg_set_default(&openvpnCfg);
    rpcServer.registerMessageHandler(app::rpcMessage::rpcMessageType::handle_openvpn_cfg, openvpn_cfg_handler);
}

bool openVpnManager_openvpnCfg_get(app::openvpnCfg_t *openvpnCfg_ptr) {

    if (openvpnCfg_ptr == NULL) {
        return false;
    }

    *openvpnCfg_ptr = openvpnCfg;

    return true;
}

bool openVpnManager_openvpnCfg_set(app::openvpnCfg_t *openvpnCfg_ptr){
    return false;
}

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

static bool openssl_req(const char *dst_key, const char* dst_csr, int days, int bitSize) {
    // ex: openssl req -nodes -newkey rsa:1024 -keyout /tmp/myCA/keys/server.pem -days 365 -keyform PEM -out /tmp/myCA/reqs/server.pem -outform PEM 
        //-subj "/C=VN/ST=HCM/L=HCM/O=Example Security/OU=IT Department/CN=example.com"

    std::string command_gen_req;

    command_gen_req += " openssl req  -newkey rsa:";
    command_gen_req += std::to_string(bitSize);
    command_gen_req += " -keyout ";
    command_gen_req += dst_key;
    command_gen_req += "  -days ";
    command_gen_req += std::to_string(days);
    command_gen_req += " -keyform PEM -out  ";
    command_gen_req += dst_csr;
    command_gen_req += " -outform PEM ";
    command_gen_req += " -subj \"/C=VN/ST=HCM/L=HCM/O=Example Security/OU=IT Department/CN=example.com/emailAddress=server@gmail.com\" ";
    printf("Command Gen REQ: %s\n", command_gen_req.c_str());
    if(system(command_gen_req.c_str()) == 0)
    {
        return true;
    }
    return false;
}

static bool openssl_gen_ca(const char* ca_key, const char* ca_crt, int days, int bitsize)
{
    std::string command_gen_ca_key;

    command_gen_ca_key += "openssl genrsa -out ";
    command_gen_ca_key += ca_key;
    command_gen_ca_key += " ";
    command_gen_ca_key += std::to_string(bitsize);
    printf("Command CA: %s\n", command_gen_ca_key.c_str());
    if(system(command_gen_ca_key.c_str()) == 0)
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
    command_sign += "yes | openssl ca -config /tmp/myCA/CA.cnf -in ";
    command_sign += src_csr;
    command_sign += " -days ";
    command_sign += std::to_string(days);
    command_sign += " -out ";
    command_sign += dst_crt;
    printf("Command sign: %s\n", command_sign.c_str());
    if(system(command_sign.c_str()) == 0)
    {
        return true;
    }

    return false;
}