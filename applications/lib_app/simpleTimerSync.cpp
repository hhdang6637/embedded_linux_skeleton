/*
 * simpleTimerSync.cpp
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>

#include "simpleTimerSync.h"

namespace app
{

simpleTimerSync::simpleTimerSync()
{
    this->initialized = false;
    this->running = false;
    this->base_tick = 100;

    pipe(this->timer_pipe);

    // nonblocking read
    fcntl(this->timer_pipe[0], F_SETFL, fcntl(this->timer_pipe[0], F_GETFL) | O_NONBLOCK);
    // nonblocking write
    fcntl(this->timer_pipe[1], F_SETFL, fcntl(this->timer_pipe[1], F_GETFL) | O_NONBLOCK);
}

simpleTimerSync::~simpleTimerSync()
{
    this->stop();
    close(this->timer_pipe[0]);
    close(this->timer_pipe[1]);
}

simpleTimerSync *simpleTimerSync::s_instance = 0;

simpleTimerSync* simpleTimerSync::getInstance()
{
    if (s_instance == 0) {
        s_instance = new simpleTimerSync();
    }

    return s_instance;
}
void simpleTimerSync::signal_handler(int sig)
{
    if (simpleTimerSync::getInstance()->timer_pipe[1] != -1)
    {
        char i = 1;
        write(simpleTimerSync::getInstance()->timer_pipe[1], &i, 1);
    }
}

void simpleTimerSync::actual_start()
{
    struct itimerval itv;
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = this->signal_handler;
    if (sigaction(SIGALRM, &sa, NULL) == -1) {
        // TODO
    }

    itv.it_value.tv_sec = this->base_tick / 1000;
    itv.it_value.tv_usec = 1000 * (this->base_tick%1000);
    itv.it_interval.tv_sec = this->base_tick / 1000;
    itv.it_interval.tv_usec = 1000 * (this->base_tick%1000);

    if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
        // TODO
    }
}

void simpleTimerSync::init(int miliseconds) {
    this->base_tick = miliseconds;
    this->initialized = true;
}

bool simpleTimerSync::start()
{
    if (this->initialized) {
        if (this->running != true) {
            this->running = true;
            this->actual_start();
        }
    }

    return this->running;
}

void simpleTimerSync::stop()
{
    struct itimerval itv;

    itv.it_value.tv_sec = 0;
    itv.it_value.tv_usec = 0;
    itv.it_interval.tv_sec = 0;
    itv.it_interval.tv_usec = 0;

    if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
        // TODO
    }

    this->running = false;
}

int simpleTimerSync::getTimterFd()
{
    return this->timer_pipe[0];
}

bool simpleTimerSync::addCallback(int milisecond, callbackf f)
{
    if (this->initialized != true) {
        return false;
    }

    this->listCallback.push_back(simpleTimerSync::timerCallback(milisecond / this->base_tick, f));

    return true;
}

void simpleTimerSync::do_schedule()
{
    char i;
    if (read(this->timer_pipe[0], &i, 1) == 1) {
        std::list<timerCallback>::iterator itr;
        for (itr = this->listCallback.begin(); itr != this->listCallback.end(); itr++) {
            itr->tick();
        }
    }
}

} /* namespace app */
