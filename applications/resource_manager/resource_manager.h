/*
 * resource_manager.h
 *
 *  Created on: Aug 14, 2018
 *      Author: nmhien
 */

#ifndef APPLICATIONS_RESOURCE_MANAGER_RESOURCE_MANAGER_H_
#define APPLICATIONS_RESOURCE_MANAGER_RESOURCE_MANAGER_H_


#define SERVICE_NAME    "resource_manager"
#define PID_FILE_NAME   "/var/run/resource_manager.pid"

void resource_manager_init();
void resource_manager_service_loop();


#endif /* APPLICATIONS_RESOURCE_MANAGER_RESOURCE_MANAGER_H_ */
