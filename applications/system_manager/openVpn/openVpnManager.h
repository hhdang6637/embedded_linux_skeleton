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

void openVpnManager_init(app::rpcUnixServer &rpcServer);

bool openVpnManager_openvpnCfg_get(app::openvpnCfg_t *openvpnCfg_ptr);
bool openVpnManager_openvpnCfg_set(app::openvpnCfg_t *openvpnCfg_ptr);
bool openVpnManager_rsa_info_get(app::openvpn_rsa_info_t *openvpn_rsa_info);

#endif /* APPLICATIONS_OPENVPNMANAGER_H_ */