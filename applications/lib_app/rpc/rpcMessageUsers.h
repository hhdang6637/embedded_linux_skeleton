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

enum rpcMessageUsersActionType : uint16_t
{
    GET_USERS,
    ADD_USER,
    EDIT_USER,
    DELETE_USER
};

enum rpcMessageUsersResultType : uint16_t
{
    SUCCEEDED,
    USER_NOT_VALID,
    USERNAME_EXISTED,
    EMAIL_EXISTED,
    ERROR_MAX_USER,
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
    void setMsgAction(rpcMessageUsersActionType type);
    app::rpcMessageUsersResultType getMsgResult();
    void setMsgResult(rpcMessageUsersResultType type);

};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPC_RPCMESSAGEUSERS_H_ */
