/*
 * eventNotification.h
 *
 *  Created on: Aug 28, 2018
 *      Author: nmhien
 */

#ifndef APPLICATIONS_EVENT_MANAGER_EVENTNOTIFICATION_H_
#define APPLICATIONS_EVENT_MANAGER_EVENTNOTIFICATION_H_

#include <stdint.h>

namespace app {

class eventNotification {
private:
    eventNotification();

    static eventNotification* s_instance;
    uint16_t                  events;

public:
    virtual ~eventNotification();

    static eventNotification* getInstance();
    void                      setEvents(const uint16_t);
    uint16_t                  getEvents();
};

} /* namespace app */


#endif /* APPLICATIONS_EVENT_MANAGER_EVENTNOTIFICATION_H_ */
