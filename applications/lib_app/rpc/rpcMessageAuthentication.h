

#ifndef APPLICATIONS_LIB_APP_RPC_RPCMESSAGEAUTHENTICATION_H_
#define APPLICATIONS_LIB_APP_RPC_RPCMESSAGEAUTHENTICATION_H_

#include <memory>

#include "rpcMessage.h"

namespace app
{

    enum rpcMessageAuthenticationResultType : uint16_t
    {
        SUCCEEDED,
        FAILED,
    };

    class rpcMessageAuthentication: public rpcMessage
    {

        app::rpcMessageAuthenticationResultType msgResult;
        std::string username;
        std::string password;

        virtual bool serialize(int fd);
        virtual bool deserialize(int);

        rpcMessageAuthentication();
        virtual ~rpcMessageAuthentication();


        public:
            app::rpcMessageAuthenticationResultType       getAuthenticationMsgResult() const;
            void setAuthenticationMsgResult(const rpcMessageAuthenticationResultType result);
    };
}

#endif //APPLICATIONS_LIB_APP_RPC_RPCMESSAGEAUTHENTICATION_H_
