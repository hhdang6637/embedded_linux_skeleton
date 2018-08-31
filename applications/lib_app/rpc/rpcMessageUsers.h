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

// we should move this function to conversion.cpp after the netlink_event branch merged into master
std::string userMsgResult2Str(const app::rpcMessageUsersResultType type);

class rpcMessageUsers: public rpcMessage
{
    app::rpcMessageUsersActionType msgAction;
    app::rpcMessageUsersResultType msgResult;
    bool editPwd;
    std::list<app::user> users;

public:
    virtual bool serialize(int fd);
    virtual bool deserialize(int);

    rpcMessageUsers();
    virtual ~rpcMessageUsers();

    std::list<app::user>           getUsers();
    void                           setUsers(const std::list<app::user> &users);
    app::user&                     getUser();
    void                           setUser(const app::user &user);

    bool                           getEditPwd();
    void                           setEditPwd(const bool editPwd_t);

    app::rpcMessageUsersActionType getMsgAction();
    void                           setMsgAction(const rpcMessageUsersActionType type);

    app::rpcMessageUsersResultType getMsgResult();
    void                           setMsgResult(const rpcMessageUsersResultType type);

};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPC_RPCMESSAGEUSERS_H_ */
