/*
 * openVpnManager.cpp
 *
 *  Created on: Jan 13, 2019
 *      Author: hhdang6637
 */

#include "rpcMessageOpenvpn.h"
#include "openVpnManager.h"

static bool openvpn_cfg_handler(int socket_fd)
{
    app::rpcMessageOpenvpnCfg msgOpenvpnCfg;

    if (msgOpenvpnCfg.deserialize(socket_fd)) {
        // msgOpenvpnCfg.setAuthenticationMsgResult(recognize_account(msgOpenvpnCfg.getUsername(), msgOpenvpnCfg.getPasswd()));
        return msgOpenvpnCfg.serialize(socket_fd);
    }

    return false;
}

void openVpnManager_init(app::rpcUnixServer &rpcServer) {
    rpcServer.registerMessageHandler(app::rpcMessage::rpcMessageType::handle_openvpn_cfg, openvpn_cfg_handler);
}