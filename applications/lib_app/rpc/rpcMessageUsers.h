/*
 * rpcMessageUsers.h
 *
 *  Created on: Aug 11, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_RPC_RPCMESSAGEUSERS_H_
#define APPLICATIONS_LIB_APP_RPC_RPCMESSAGEUSERS_H_

#include <list>

#include "user.h"
#include "rpcMessage.h"

namespace app
{

enum class rpcMessageUsersActionType : uint16_t
{
    GET_USERS,
    SET_USERS
};

enum class rpcMessageUsersResultType : uint16_t
{
    SUCCEEDED,
    FAILED
};

class rpcMessageUsers: public rpcMessage
{
    app::rpcMessageUsersActionType msgAction;
    app::rpcMessageUsersResultType msgResult;
    std::list<app::user> users;

public:
    virtual bool serialize(int fd);
    virtual bool deserialize(int);

    rpcMessageUsers();
    virtual ~rpcMessageUsers();

    std::list<app::user> getUsers();
    void setUsers(std::list<app::user> &users);
    void setUser(app::user &user);
    app::rpcMessageUsersActionType getMsgAction();
    app::rpcMessageUsersResultType getMsgResult();
    void setMsgResult(rpcMessageUsersResultType type);
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPC_RPCMESSAGEUSERS_H_ */
