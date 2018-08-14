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
        msgAction(rpcMessageUsersActionType::GET_USERS)
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

    switch (this->msgAction) {
        case app::rpcMessageUsersActionType::GET_USERS:
        case app::rpcMessageUsersActionType::SET_USERS:
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
    switch (this->msgAction)
    {
        case app::rpcMessageUsersActionType::GET_USERS:
        case app::rpcMessageUsersActionType::SET_USERS:
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

void rpcMessageUsers::setUsers(std::list<app::user> &users)
{
    this->users = users;
}

app::rpcMessageUsersActionType rpcMessageUsers::getMsgAction()
{
    return this->msgAction;
}

} /* namespace app */
