
#include <memory>
#include "rpcUnixClient.h"
#include "rpcMessageOpenvpn.h"

namespace app{

    rpcMessageOpenvpnCfg::rpcMessageOpenvpnCfg() :
            rpcMessage(rpcMessageType::handle_openvpn_cfg, rpcMessageAddr::system_manager_addr_t),
            msgResult(app::rpcMessageOpenvpnResultType::UNKNOW),
            msgAction(app::rpcMessageOpenvpnCfgActionType::GET_OPENVPN_CFG),
            openvpnCfg_data()
    {
        //TO-DO
    }

    rpcMessageOpenvpnCfg::~rpcMessageOpenvpnCfg()
    {
        //TO-DO
    }

    bool rpcMessageOpenvpnCfg::serialize(int fd)
    {
        int         buff_len;
        int         offset;
        uint16_t    tmpValue;

        buff_len = 0;
        offset = 0;

        tmpValue = (uint16_t)this->msgAction;
        if (rpcMessage::sendInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }

        switch (this->msgAction)
        {
            case app::rpcMessageOpenvpnCfgActionType::SET_OPENVPN_CFG:
            case app::rpcMessageOpenvpnCfgActionType::GET_OPENVPN_CFG:
            {
                buff_len += sizeof(app::rpcMessageOpenvpnResultType);
                buff_len += sizeof(app::rpcMessageOpenvpnCfgActionType);
                buff_len += sizeof(app::openvpnCfg_t);

                std::unique_ptr<char> buff_ptr(new char[buff_len]());

                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, (uint16_t)this->msgResult);
                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, (uint16_t)this->msgAction);

                memcpy(buff_ptr.get() + offset, &this->openvpnCfg_data, sizeof(this->openvpnCfg_data));
                offset += sizeof(this->openvpnCfg_data);

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

    bool rpcMessageOpenvpnCfg::deserialize(int fd)
    {
        uint16_t tmpValue;
        if (rpcMessage::recvInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }

        this->msgAction = app::rpcMessageOpenvpnCfgActionType(tmpValue);

        switch (this->msgAction)
        {
            case app::rpcMessageOpenvpnCfgActionType::SET_OPENVPN_CFG:
            case app::rpcMessageOpenvpnCfgActionType::GET_OPENVPN_CFG:
            {
                if (rpcMessage::recvInterruptRetry(fd, &this->msgResult,
                        sizeof(this->msgResult)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &this->msgAction,
                        sizeof(this->msgAction)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &this->openvpnCfg_data,
                        sizeof(this->openvpnCfg_data)) != true) {
                    return false;
                }
                break;
            }
            default:
                break;
        }

        return true;
    }

    app::rpcMessageOpenvpnCfgActionType rpcMessageOpenvpnCfg::getMsgAction() const
    {
        return this->msgAction;
    }

    void rpcMessageOpenvpnCfg::setMsgAction(const rpcMessageOpenvpnCfgActionType action)
    {
        this->msgAction = action;
    }

    app::rpcMessageOpenvpnResultType rpcMessageOpenvpnCfg::getMsgResult() const
    {
        return this->msgResult;
    }

    void rpcMessageOpenvpnCfg::setMsgResult(const app::rpcMessageOpenvpnResultType result)
    {
        this->msgResult = result;
    }

    void rpcMessageOpenvpnCfg::getOpenvpnCfg_data(app::openvpnCfg_t &openvpnCfg_data) {
        openvpnCfg_data = this->openvpnCfg_data;
    }

    void rpcMessageOpenvpnCfg::setOpenvpnCfg_data(app::openvpnCfg_t &openvpnCfg_data){
        this->openvpnCfg_data = openvpnCfg_data;
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

    bool rpcMessageOpenvpnCfg::rpcGetOpenvpnCfg_data(app::rpcUnixClient &rpcClient, app::openvpnCfg_t &openvpnCfg_data) {
        app::rpcMessageOpenvpnCfg msg;

        msg.setMsgAction(app::rpcMessageOpenvpnCfgActionType::GET_OPENVPN_CFG);

        if (rpcClient.doRpc(&msg) == false &&
                msg.getMsgResult() == app::rpcMessageOpenvpnResultType::SUCCESS) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return false;
        }

        msg.getOpenvpnCfg_data(openvpnCfg_data);

        return true;
    }

}