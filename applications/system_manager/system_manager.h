#ifndef _SYSTEM_MANAGER_H_
#define _SYSTEM_MANAGER_H_

#define SERVICE_NAME    "system_manager"
#define PID_FILE_NAME   "/var/run/system_manager.pid"

void system_manager_init();
void system_manager_service_loop();

#endif // _SYSTEM_MANAGER_H_
