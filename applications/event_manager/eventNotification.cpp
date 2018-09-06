/*
 * eventNotification.cpp
 *
 *  Created on: Aug 28, 2018
 *      Author: nmhien
 */

#include "eventNotification.h"
namespace app {

eventNotification::eventNotification() {
    // TODO Auto-generated constructor stub

}

eventNotification::~eventNotification() {
    // TODO Auto-generated destructor stub
}

eventNotification *eventNotification::s_instance = 0;

eventNotification* eventNotification::getInstance()
{
    if (s_instance == 0) {
        s_instance = new eventNotification();
    }

    return s_instance;
}

void eventNotification::setEvents(const uint16_t events)
{
    this->events = events;
}

uint16_t eventNotification::getEvents()
{
    return this->events;
}

} /* namespace app */
