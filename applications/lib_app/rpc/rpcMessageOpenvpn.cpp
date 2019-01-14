#include "rpcMessageOpenvpn.h"

namespace app{

    bool rpcMessageOpenvpn::serialize(int fd)
    {
        return true;
    }

    bool rpcMessageOpenvpn::deserialize(int fd)
    {
        return true;
    }

    app::rpcMessageOpenvpnActionType rpcMessageOpenvpn::getMsgAction() const
    {
        return this->msgAction;
    }

    void rpcMessageOpenvpn::setMsgAction(const rpcMessageOpenvpnActionType action)
    {
        this->msgAction = action;
    }

    app::rpcMessageOpenvpnResultType rpcMessageOpenvpn::getMsgResult() const
    {
        return this->msgResult;
    }

    void rpcMessageOpenvpn::setMsgResult(const app::rpcMessageOpenvpnResultType result)
    {
        this->msgResult = result;
    }

    std::string openMsgResult2Str(const app::rpcMessageOpenvpnResultType &result)
    {
        std::string outStr;

        switch (result)
        {
            case app::rpcMessageOpenvpnResultType::FAILED:
                outStr = "Failed";
                break;

            case app::rpcMessageOpenvpnResultType::SUCCESS:
                outStr = "Success";
                break;

            case app::rpcMessageOpenvpnResultType::UNKNOW:
                outStr = "Unknow";
                break;
        }

        return outStr;
    }

}