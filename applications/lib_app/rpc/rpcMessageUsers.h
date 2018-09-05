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
    USER_INVALID,
    USERNAME_EXISTED,
    USER_NOT_EXISTED,
    EMAIL_EXISTED,
    ERROR_MAX_USER,
    UNKNOWN_ERROR
};

class rpcMessageUsers: public rpcMessage
{
    app::rpcMessageUsersActionType msgAction;
    app::rpcMessageUsersResultType msgResult;
    uint16_t                       m_changePasswd;
    std::list<app::user>           users;

public:
    virtual bool serialize(int fd);
    virtual bool deserialize(int);

    rpcMessageUsers();
    virtual ~rpcMessageUsers();

    std::list<app::user>           getUsers() const;
    void                           setUsers(const std::list<app::user> &users);
    app::user&                     getUser();
    void                           setUser(const app::user &user);

    uint16_t                       changePasswd() const;
    void                           setChangePasswd(const uint16_t changePasswd);

    app::rpcMessageUsersActionType getMsgAction() const;
    void                           setMsgAction(const rpcMessageUsersActionType action);

    app::rpcMessageUsersResultType getMsgResult() const;
    void                           setMsgResult(const rpcMessageUsersResultType result);

};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPC_RPCMESSAGEUSERS_H_ */
