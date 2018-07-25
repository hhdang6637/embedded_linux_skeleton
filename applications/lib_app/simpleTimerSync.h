/*
 * simpleTimerSync.h
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_SIMPLETIMERSYNC_H_
#define APPLICATIONS_LIB_APP_SIMPLETIMERSYNC_H_

#include <list>
#include <functional>

namespace app
{

class simpleTimerSync
{
    typedef std::function<void(void)> callbackf;
    class timerCallback
    {
        int tick_base;
        int tick_counter;
        callbackf callback;
    public:
        timerCallback(int bc, callbackf cb) :
                tick_base(bc), tick_counter(0), callback(cb)
        {
        };
        void tick() {
            if (this->tick_counter++ >= this->tick_base){
                this->tick_counter = 0;
                this->callback();
            }
        }
    };
private:
    simpleTimerSync();

    int timer_pipe[2];
    bool initialized;
    int base_tick;  // miliseconds
    bool running;
    void actual_start();
    std::list<timerCallback> listCallback;

    static void signal_handler(int sig);

    static simpleTimerSync* s_instance;

public:
    virtual ~simpleTimerSync();
    static simpleTimerSync* getInstance();
    void init(int miliseconds);
    bool start();
    void stop();
    int getTimterFd();
    bool addCallback(int milisecond, callbackf f);
    void do_schedule();
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_SIMPLETIMERSYNC_H_ */
