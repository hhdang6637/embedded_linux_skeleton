/*
 * network_manager.h
 *
 *  Created on: Jul 26, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_NETWORK_MANAGER_NETWORK_MANAGER_H_
#define APPLICATIONS_NETWORK_MANAGER_NETWORK_MANAGER_H_

#define SERVICE_NAME    "network_manager"
#define PID_FILE_NAME   "/var/run/network_manager.pid"

void network_manager_init();

#endif /* APPLICATIONS_NETWORK_MANAGER_NETWORK_MANAGER_H_ */
