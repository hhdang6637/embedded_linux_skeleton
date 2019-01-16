/*
 * openVpnManager.cpp
 *
 *  Created on: Jan 13, 2019
 *      Author: hhdang6637
 */

#include "openVpnManager.h"

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
    openvpnCfg_ptr->port = 1194;
}

static bool openvpnCfg_valid(app::openvpnCfg_t *openvpnCfg_ptr) {
    return false;
}

static bool openvpn_cfg_handler(int socket_fd)
{
    app::rpcMessageOpenvpnCfg msgOpenvpnCfg;

    printf("%s recevie RPC request\n", __FUNCTION__);

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