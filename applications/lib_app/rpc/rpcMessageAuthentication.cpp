
#include "rpcMessageAuthentication.h"

namespace app
{
    rpcMessageAuthentication::rpcMessageAuthentication() :
        rpcMessage(rpcMessageType::handle_users_login, rpcMessageAddr::system_manager_addr_t),
        msgResult(rpcMessageAuthenticationResultType::SUCCEEDED_LOGIN)
    {
        // TODO Auto-generated constructor stub

    }

    rpcMessageAuthentication::~rpcMessageAuthentication()
    {
        // TODO Auto-generated destructor stub
    }

    bool rpcMessageAuthentication::serialize(int fd)
    {
        uint16_t tmpValue;
        int buff_len = 0;
        int offset = 0;

        tmpValue = (uint16_t)this->msgResult;
        if (rpcMessage::sendInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }

        buff_len += sizeof(uint16_t) + this->username.length();
        buff_len += sizeof(uint16_t) + this->password.length();

        std::unique_ptr<char> buff_ptr(new char[buff_len]);

        offset += rpcMessage::bufferAppendStr(buff_ptr.get() + offset, this->username);
        offset += rpcMessage::bufferAppendStr(buff_ptr.get() + offset, this->password);

        if (buff_len != offset) {

            syslog(LOG_ERR, "%s-%u something wrong happened", __FUNCTION__, __LINE__);
            return false;

        }

        if (rpcMessage::sendInterruptRetry(fd, buff_ptr.get(), offset) != true) {
            return false;
        }

        return true;
    }

    bool rpcMessageAuthentication::deserialize(int fd)
    {
        uint16_t tmpValue;

        if (rpcMessage::recvInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }
        this->msgResult = app::rpcMessageAuthenticationResultType(tmpValue);

        uint16_t username_size, password_size;

        if (rpcMessage::recvInterruptRetry(fd, &username_size, sizeof(username_size)) != true) {
            return false;
        }

        if (username_size > 0) {
            std::unique_ptr<char> buff_ptr(new char[username_size + 1]());

            if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), username_size) != true) {
                return false;
            }

            this->username = buff_ptr.get();
        }

        if (rpcMessage::recvInterruptRetry(fd, &password_size, sizeof(password_size)) != true) {
            return false;
        }

        if (password_size > 0) {
            std::unique_ptr<char> buff_ptr(new char[password_size + 1]());

            if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), password_size) != true) {
                return false;
            }

            this->password = buff_ptr.get();
        }

        return true;
    }

    app::rpcMessageAuthenticationResultType rpcMessageAuthentication::getAuthenticationMsgResult() const
    {
        return this->msgResult;
    }

    void rpcMessageAuthentication::setAuthenticationMsgResult(const rpcMessageAuthenticationResultType result)
    {
        this->msgResult = result;
    }

    std::string rpcMessageAuthentication::getUsername()
    {
        return this->username;
    }

    void rpcMessageAuthentication::setUsername(std::string username)
    {
        this->username = username;
    }

    std::string rpcMessageAuthentication::getPasswd()
    {
        return this->password;
    }

    void rpcMessageAuthentication::setPasswd(std::string passwd)
    {
        this->password = passwd;
    }

} /* namespace app */
