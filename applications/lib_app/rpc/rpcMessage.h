/*
 * rpcMessage.h
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_RPCMESSAGE_H_
#define APPLICATIONS_LIB_APP_RPCMESSAGE_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <syslog.h>
#include <iostream>
#include <list>
#include <string>

#include "rpcMessageAddr.h"

namespace app
{
class rpcUnixClient;
class rpcUnixServer;

class rpcMessage
{
public:
    enum rpcMessageType : uint16_t
    {
        get_resource_history,
        get_event_notification,
        handle_firmware_action,
        handle_users_action,
        handle_users_login,
        handle_wifi_setting,
        handle_time_cfg,
    };
protected:
    rpcMessageType  msgType;
    rpcMessageAddr::rpcMessageAddrType  msgAddrType;

public:
    rpcMessage(rpcMessageType, rpcMessageAddr::rpcMessageAddrType);
    virtual ~rpcMessage();

    virtual bool serialize(int fd) = 0;
    virtual bool deserialize(int fd) = 0;

    bool send(int fd);
    bool receive(int fd);

    static int bufferAppendU16(void*dst, uint16_t t)
    {
        memcpy(dst, &t, sizeof(t));
        return sizeof(t);
    }

    template<typename T> static int bufferAppend(void*dst, T const &t)
    {
        memcpy(dst, &t, sizeof(t));
        return sizeof(t);
    }

    static int bufferAppendBool(void*dst, bool t)
    {
        memcpy(dst, &t, sizeof(t));
        return sizeof(t);
    }

    static int bufferAppendStr(void*dst, std::string &str)
    {
        int len = 0;
        len += rpcMessage::bufferAppendU16(dst, (uint16_t)str.length());
        memcpy((char*) dst + len, str.c_str(), str.length());
        return len + str.length();
    }

    template<typename T> static int bufferAppendList(char*dst, T const &list)
    {
        int len = 0;
        len += rpcMessage::bufferAppendU16(dst, (uint16_t)list.size());
        for (auto &i : list) {
            memcpy(dst + len, &i, sizeof(i));
            len += sizeof(i);
        }
        return len;
    }

    template<typename T> static void ListFromBuff(T *src, std::list<T> &list, int max)
    {
        for (int i = 0; i < max; ++i) {
            list.push_back(*(src + i));
        }
    }

    static inline bool sendInterruptRetry(int fd, const void *buf, ssize_t bufLen)
    {
        ssize_t sent = 0;
        ssize_t byet_sent = 0;
        const char *ptr = (const char *) buf;

        while (sent != bufLen) {
            byet_sent = ::send(fd, ptr + sent, bufLen - sent, 0);
            if (byet_sent == -1) {
                if (errno == EINTR) {
                    continue;
                }

                char buff[256];
                snprintf(buff, sizeof(buff), "%s-%u: cannot send buff successful, %s", __FUNCTION__, __LINE__,
                        strerror(errno));
                syslog(LOG_ERR, buff);
                return false;
            }
            if (byet_sent == 0) {
                return false;
            }
            sent += byet_sent;
        }

        return true;
    }

    static inline bool recvInterruptRetry(int fd, void *buf, ssize_t bufLen)
    {
        ssize_t recv = 0;
        ssize_t byte_recv = 0;
        char * ptr = (char*) buf;

        while (recv != bufLen) {
            byte_recv = ::recv(fd, ptr + recv, bufLen - recv, 0);
            if (byte_recv == -1) {
                if (errno == EINTR) {
                    continue;
                }

                char buff[256];
                snprintf(buff, sizeof(buff), "%s-%u: cannot recv successful, %s", __FUNCTION__, __LINE__,
                        strerror(errno));
                syslog(LOG_ERR, buff);
                return false;
            }
            if (byte_recv == 0) {
                return false;
            }
            recv += byte_recv;
        }
        return true;
    }

    friend class rpcUnixClient;
    friend class rpcUnixServer;
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPCMESSAGE_H_ */
