

#ifndef APPLICATIONS_LIB_APP_RPC_RPCMESSAGEAUTHENTICATION_H_
#define APPLICATIONS_LIB_APP_RPC_RPCMESSAGEAUTHENTICATION_H_

#include <memory>

#include "rpcMessage.h"

namespace app
{

    enum rpcMessageAuthenticationResultType : uint16_t
    {
        SUCCEEDED_LOGIN,
        FAILED_LOGIN,
        UNKNOWN_ERROR_LOGIN
    };

    class rpcMessageAuthentication: public rpcMessage
    {
        app::rpcMessageAuthenticationResultType msgResult;
        std::string username;
        std::string password;

        public:
            virtual bool serialize(int fd);
            virtual bool deserialize(int);

            rpcMessageAuthentication();
            virtual ~rpcMessageAuthentication();

            app::rpcMessageAuthenticationResultType       getAuthenticationMsgResult() const;
            void setAuthenticationMsgResult(const rpcMessageAuthenticationResultType result);

            std::string              getUsername();
            void setUsername(std::string username);

            std::string            getPasswd();
            void setPasswd(std::string passwd);
    };
}

#endif //APPLICATIONS_LIB_APP_RPC_RPCMESSAGEAUTHENTICATION_H_
