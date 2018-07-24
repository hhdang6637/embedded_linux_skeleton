/*
 * rpcMessage.h
 *
 *  Created on: Jul 24, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_RPCMESSAGE_H_
#define APPLICATIONS_LIB_APP_RPCMESSAGE_H_

#include <sys/types.h>
#include <stdint.h>
#include <iostream>
#include <list>

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
        get_cpu_history
    };
protected:
    rpcMessageType  msgType;
    rpcMessageAddr::rpcMessageAddrType  msgAddrType;

public:
    rpcMessage(rpcMessageType);
    virtual ~rpcMessage();

    virtual bool serialize(int fd) = 0;
    virtual bool deserialize(int fd) = 0;

    bool send(int fd);
    bool receive(int fd);

    template <typename T> static int bufferAppend(void*dst, T const &src) {
        memcpy(dst, &src, sizeof(src));
        return sizeof(src);
    }

	template<typename T> static int bufferAppendList(char*dst, T const &list) {
        int len = 0;
        for (auto &i : list) {
            memcpy(dst + len, &i, sizeof(i));
            len += sizeof(i);
        }
        return len;
	}

	template<typename T> static void ListFromBuff(T *src, std::list<T> &list, int max) {
        for (int i = 0; i < max; ++i) {
            list.push_back(*(src + i));
        }
	}

    friend class rpcUnixClient;
    friend class rpcUnixServer;
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPCMESSAGE_H_ */
