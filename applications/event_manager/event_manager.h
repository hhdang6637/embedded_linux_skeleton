/*
 * event_manager.h
 *
 *  Created on: Aug 28, 2018
 *      Author: nmhien
 */

#ifndef APPLICATIONS_EVENT_MANAGER_EVENT_MANAGER_H_
#define APPLICATIONS_EVENT_MANAGER_EVENT_MANAGER_H_


#define SERVICE_NAME    "event_manager"
#define PID_FILE_NAME   "/var/run/event_manager.pid"

void event_manager_init();
void event_manager_service_loop();


#endif /* APPLICATIONS_EVENT_MANAGER_EVENT_MANAGER_H_ */
