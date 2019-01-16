/*
 * openVpnManager.h
 *
 *  Created on: Jan 13, 2019
 *      Author: hhdang6637
 */

#ifndef APPLICATIONS_OPENVPNMANAGER_H_
#define APPLICATIONS_OPENVPNMANAGER_H_

#include "rpcMessageOpenvpn.h"
#include "rpcUnixServer.h"

#define CA_DIR "/tmp/ca"

void openVpnManager_init(app::rpcUnixServer &rpcServer);

bool openVpnManager_openvpnCfg_get(app::openvpnCfg_t *openvpnCfg_ptr);
bool openVpnManager_openvpnCfg_set(app::openvpnCfg_t *openvpnCfg_ptr);

#endif /* APPLICATIONS_OPENVPNMANAGER_H_ */