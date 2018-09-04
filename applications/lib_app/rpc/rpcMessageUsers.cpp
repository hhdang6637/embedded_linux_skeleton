/*
 * rpcMessageUsers.cpp
 *
 *  Created on: Aug 11, 2018
 *      Author: hhdang
 */

#include <memory>

#include "rpcMessageUsers.h"

namespace app
{

rpcMessageUsers::rpcMessageUsers() :
        rpcMessage(rpcMessageType::handle_users_action, rpcMessageAddr::system_manager_addr_t),
        msgAction(rpcMessageUsersActionType::GET_USERS),
        msgResult(rpcMessageUsersResultType::SUCCEEDED)
{
    // TODO Auto-generated constructor stub

}

rpcMessageUsers::~rpcMessageUsers()
{
    // TODO Auto-generated destructor stub
}

bool rpcMessageUsers::serialize(int fd)
{
    uint16_t tmpValue;
    // just write the state
    int buff_len = 0;
    int offset = 0;

    tmpValue = (uint16_t)this->msgAction;
    if (rpcMessage::sendInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
        return false;
    }

    tmpValue = (uint16_t)this->msgResult;
    if (rpcMessage::sendInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
        return false;
    }

    switch (this->msgAction) {
        case app::rpcMessageUsersActionType::GET_USERS:
        case app::rpcMessageUsersActionType::ADD_USER:
        case app::rpcMessageUsersActionType::EDIT_USER:
        case app::rpcMessageUsersActionType::DELETE_USER:
        {
            buff_len += sizeof(uint16_t) + this->users.size() * sizeof(app::user);

            std::unique_ptr<char> buff_ptr(new char[buff_len]);

            offset += rpcMessage::bufferAppendList(buff_ptr.get() + offset, this->users);

            if (buff_len != offset) {

                syslog(LOG_ERR, "%s-%u something wrong happened", __FUNCTION__, __LINE__);
                return false;

            }

            if (rpcMessage::sendInterruptRetry(fd, buff_ptr.get(), offset) != true) {
                return false;
            }

            if (rpcMessage::sendInterruptRetry(fd, &this->m_changePasswd, sizeof(this->m_changePasswd)) != true) {
                return false;
            }
            break;
        }
        default:
            break;
    }

    return true;
}

bool rpcMessageUsers::deserialize(int fd)
{
    uint16_t tmpValue;
    if (rpcMessage::recvInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
        return false;
    }
    this->msgAction = app::rpcMessageUsersActionType(tmpValue);

    if (rpcMessage::recvInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
        return false;
    }
    this->msgResult = app::rpcMessageUsersResultType(tmpValue);

    switch (this->msgAction)
    {
        case app::rpcMessageUsersActionType::GET_USERS:
        case app::rpcMessageUsersActionType::ADD_USER:
        case app::rpcMessageUsersActionType::EDIT_USER:
        case app::rpcMessageUsersActionType::DELETE_USER:
        {
            uint16_t users_size;

            if (rpcMessage::recvInterruptRetry(fd, &users_size, sizeof(users_size)) != true) {
                return false;
            }

            if (users_size > 0) {
                std::unique_ptr<char> buff_ptr(new char[users_size * sizeof(app::user)]);

                if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), users_size * sizeof(app::user)) != true) {
                    return false;
                }

                rpcMessage::ListFromBuff((app::user*) buff_ptr.get(), this->users, users_size);
            }

            if (rpcMessage::recvInterruptRetry(fd, &this->m_changePasswd, sizeof(this->m_changePasswd)) != true) {
                return false;
            }

            break;
        }

        default:
            break;
    }

    return true;
}

std::list<app::user> rpcMessageUsers::getUsers()
{
    return this->users;
}

app::user& rpcMessageUsers::getUser()
{
    return this->users.front();
}

void rpcMessageUsers::setUsers(const std::list<app::user> &users)
{
    this->msgAction = rpcMessageUsersActionType::ADD_USER;
    this->users = users;
}
void rpcMessageUsers::setUser(const app::user &user)
{
    this->users.clear();
    this->users.push_back(user);
}

uint16_t rpcMessageUsers::changePasswd()
{
    return this->m_changePasswd;
}

void rpcMessageUsers::setChangePasswd(const uint16_t changePasswd)
{
    this->m_changePasswd = changePasswd;
}

app::rpcMessageUsersActionType rpcMessageUsers::getMsgAction()
{
    return this->msgAction;
}

void rpcMessageUsers::setMsgAction(const rpcMessageUsersActionType action)
{
    this->msgAction = action;
}

app::rpcMessageUsersResultType rpcMessageUsers::getMsgResult()
{
    return this->msgResult;
}

void rpcMessageUsers::setMsgResult(const rpcMessageUsersResultType result)
{
    this->msgResult = result;
}


// we should move this function to conversion.cpp after the netlink_event branch merged into master
std::string userMsgResult2Str(const app::rpcMessageUsersResultType type)
{
    std::string str;
    if (type == app::rpcMessageUsersResultType::SUCCEEDED) {
        str = "succeeded";
    } else if (type == app::rpcMessageUsersResultType::ERROR_MAX_USER) {
        str = "Error max user";
    } else if (type == app::rpcMessageUsersResultType::USER_INVALID) {
        str = "User information not valid";
    } else if (type == app::rpcMessageUsersResultType::USER_NOT_EXISTED) {
        str = "User doesn't exist";
    } else if (type == app::rpcMessageUsersResultType::USERNAME_EXISTED) {
        str = "User name existed";
    } else if (type == app::rpcMessageUsersResultType::EMAIL_EXISTED) {
        str = "Email existed";
    } else if (type == app::rpcMessageUsersResultType::UNKNOWN_ERROR) {
        str = "Unknown error";
    }

    return str;
}

} /* namespace app */
