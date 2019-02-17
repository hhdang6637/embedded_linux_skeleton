
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

        if (rpcClient.doRpc(&msg) == false ||
                msg.getMsgResult() != app::rpcMessageOpenvpnResultType::SUCCESS) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return false;
        }

        msg.getOpenvpnCfg_data(openvpnCfg_data);

        return true;
    }

    bool rpcMessageOpenvpnCfg::rpcSetOpenvpnCfg_data(app::rpcUnixClient &rpcClient, app::openvpnCfg_t &openvpnCfg_data) {
        app::rpcMessageOpenvpnCfg msg;

        msg.setMsgAction(app::rpcMessageOpenvpnCfgActionType::SET_OPENVPN_CFG);
        msg.setOpenvpnCfg_data(openvpnCfg_data);

        if (rpcClient.doRpc(&msg) == false ||
                msg.getMsgResult() != app::rpcMessageOpenvpnResultType::SUCCESS) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return false;
        }

        return true;

    }

    //rpcMessageOpenvpnRsaInfo

    rpcMessageOpenvpnRsaInfo::rpcMessageOpenvpnRsaInfo() :
            rpcMessage(rpcMessageType::handle_openvpn_rsa_info, rpcMessageAddr::system_manager_addr_t),
            msgResult(app::rpcMessageOpenvpnResultType::UNKNOW),
            msgAction(app::rpcMessageOpenvpnRsaInfoActionType::GET_OPENVPN_RSA_INFO),
            openvpn_rsa_info()
    {
        //TO-DO
    }

    rpcMessageOpenvpnRsaInfo::~rpcMessageOpenvpnRsaInfo()
    {
        //TO-DO
    }

    bool rpcMessageOpenvpnRsaInfo::serialize(int fd)
    {
        int buff_len;
        int offset;
        uint16_t tmpValue;

        buff_len = 0;
        offset = 0;

        tmpValue = (uint16_t)this->msgAction;
        if (rpcMessage::sendInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }

        switch (this->msgAction)
        {
            case app::rpcMessageOpenvpnRsaInfoActionType::SET_OPENVPN_RSA_INFO:
            case app::rpcMessageOpenvpnRsaInfoActionType::GET_OPENVPN_RSA_INFO:
            {
                buff_len += sizeof(app::rpcMessageOpenvpnResultType);
                buff_len += sizeof(app::rpcMessageOpenvpnRsaInfoActionType);
                buff_len += sizeof(app::openvpn_rsa_info_t);

                std::unique_ptr<char> buff_ptr(new char[buff_len]());

                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, (uint16_t)this->msgResult);
                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, (uint16_t)this->msgAction);

                memcpy(buff_ptr.get() + offset, &this->openvpn_rsa_info, sizeof(this->openvpn_rsa_info));
                offset += sizeof(this->openvpn_rsa_info);

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

    bool rpcMessageOpenvpnRsaInfo::deserialize(int fd)
    {
        uint16_t tmpValue;
        if (rpcMessage::recvInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }

        this->msgAction = app::rpcMessageOpenvpnRsaInfoActionType(tmpValue);

        switch (this->msgAction)
        {
            case app::rpcMessageOpenvpnRsaInfoActionType::SET_OPENVPN_RSA_INFO:
            case app::rpcMessageOpenvpnRsaInfoActionType::GET_OPENVPN_RSA_INFO:
            {
                if (rpcMessage::recvInterruptRetry(fd, &this->msgResult,
                        sizeof(this->msgResult)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &this->msgAction,
                        sizeof(this->msgAction)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &this->openvpn_rsa_info,
                        sizeof(this->openvpn_rsa_info)) != true) {
                    return false;
                }
                break;
            }
            default:
                break;
        }

        return true;
    }

    app::rpcMessageOpenvpnRsaInfoActionType rpcMessageOpenvpnRsaInfo::getMsgAction() const
    {
        return this->msgAction;
    }

    void rpcMessageOpenvpnRsaInfo::setMsgAction(const rpcMessageOpenvpnRsaInfoActionType action)
    {
        this->msgAction = action;
    }

    app::rpcMessageOpenvpnResultType rpcMessageOpenvpnRsaInfo::getMsgResult() const
    {
        return this->msgResult;
    }

    void rpcMessageOpenvpnRsaInfo::setMsgResult(const rpcMessageOpenvpnResultType result)
    {
        this->msgResult = result;
    }

    void rpcMessageOpenvpnRsaInfo::getOpenvpnRsaInfo(app::openvpn_rsa_info_t &openvpn_rsa_info)
    {
        openvpn_rsa_info = this->openvpn_rsa_info;
    }

    void rpcMessageOpenvpnRsaInfo::setOpenvpnRsaInfo(app::openvpn_rsa_info_t &openvpn_rsa_info)
    {
        this->openvpn_rsa_info = openvpn_rsa_info;
    }

    bool rpcMessageOpenvpnRsaInfo::rpcGetOpenvpnRsaInfo(app::rpcUnixClient &rpcClient, app::openvpn_rsa_info_t &openvpn_rsa_info)
    {
        app::rpcMessageOpenvpnRsaInfo msg;

        msg.setMsgAction(app::rpcMessageOpenvpnRsaInfoActionType::GET_OPENVPN_RSA_INFO);

        if (rpcClient.doRpc(&msg) == false ||
                msg.getMsgResult() != app::rpcMessageOpenvpnResultType::SUCCESS) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return false;
        }

        msg.getOpenvpnRsaInfo(openvpn_rsa_info);

        return true;
    }

    bool rpcMessageOpenvpnRsaInfo::rpcReGenOpevpnRsaInfo(app::rpcUnixClient &rpcClient)
    {
        app::rpcMessageOpenvpnRsaInfo msg;

        msg.setMsgAction(app::rpcMessageOpenvpnRsaInfoActionType::SET_OPENVPN_RSA_INFO);

        if (rpcClient.doRpc(&msg) == false ||
                msg.getMsgResult() != app::rpcMessageOpenvpnResultType::SUCCESS) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return false;
        }

        return true;
    }


    //rpcMessageOpenvpnCertClients

    rpcMessageOpenvpnClientCerts::rpcMessageOpenvpnClientCerts() :
            rpcMessage(rpcMessageType::handle_openvpn_cert_clients, rpcMessageAddr::system_manager_addr_t),
            msgResult(app::rpcMessageOpenvpnResultType::UNKNOW),
            msgAction(app::rpcMessageOpenvpnClientCertActionType::GET_OPENVPN_CLIENT_CERT),
            client_certs()
    {
        //TO-DO
    }

    rpcMessageOpenvpnClientCerts::~rpcMessageOpenvpnClientCerts()
    {
        //TO-DO
    }

    bool rpcMessageOpenvpnClientCerts::serialize(int fd)
    {
        int buff_len;
        int offset;
        uint16_t tmpValue;

        buff_len = 0;
        offset = 0;

        tmpValue = (uint16_t) this->msgAction;
        if (rpcMessage::sendInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }

        switch (this->msgAction)
        {
            case app::rpcMessageOpenvpnClientCertActionType::GEN_OPENVPN_CLIENT_CERT:
            case app::rpcMessageOpenvpnClientCertActionType::GET_OPENVPN_CLIENT_CERT:
            case app::rpcMessageOpenvpnClientCertActionType::REVOKE_OPENVPN_CLIENT_CERT:
            {
                buff_len += sizeof(app::rpcMessageOpenvpnResultType);
                buff_len += sizeof(uint16_t); // list size
                buff_len += this->client_certs.size() * sizeof(app::openvpn_client_cert_t);

                std::unique_ptr<char> buff_ptr(new char[buff_len]());

                offset += rpcMessage::bufferAppendU16(buff_ptr.get() + offset, (uint16_t) this->msgResult);
                offset += rpcMessage::bufferAppendList(buff_ptr.get() + offset, this->client_certs);

                if (buff_len != offset) {
                    syslog(LOG_ERR, "%s-%u something wrong happened", __FUNCTION__, __LINE__);
                    return false;
                }

                if (rpcMessage::sendInterruptRetry(fd, buff_ptr.get(), offset) != true) {
                    return false;
                }

                break;
            }

            case app::rpcMessageOpenvpnClientCertActionType::GEN_OPENVPN_CLIENT_CONFIG:
            {
                buff_len += sizeof(app::rpcMessageOpenvpnResultType);
                buff_len += sizeof(this->client_config.common_name);
                buff_len += sizeof(uint16_t); // config_str length
                buff_len += this->client_config.config_str.length();

                std::unique_ptr<char> buff_ptr(new char[buff_len]());

                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, (uint16_t) this->msgResult);
                offset += rpcMessage::bufferAppend(buff_ptr.get() + offset, this->client_config.common_name);
                offset += rpcMessage::bufferAppendStr(buff_ptr.get() + offset, this->client_config.config_str);

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

    bool rpcMessageOpenvpnClientCerts::deserialize(int fd)
    {
        uint16_t tmpValue;
        if (rpcMessage::recvInterruptRetry(fd, &tmpValue, sizeof(tmpValue)) != true) {
            return false;
        }

        this->msgAction = app::rpcMessageOpenvpnClientCertActionType(tmpValue);

        switch (this->msgAction)
        {
            case app::rpcMessageOpenvpnClientCertActionType::GEN_OPENVPN_CLIENT_CERT:
            case app::rpcMessageOpenvpnClientCertActionType::GET_OPENVPN_CLIENT_CERT:
            case app::rpcMessageOpenvpnClientCertActionType::REVOKE_OPENVPN_CLIENT_CERT:
            {
                uint16_t list_size;
                if (rpcMessage::recvInterruptRetry(fd, &this->msgResult, sizeof(this->msgResult)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &list_size, sizeof(list_size)) != true) {
                    return false;
                }

                if (list_size > 0) {
                    std::unique_ptr<char> buff_ptr(new char[list_size * sizeof(app::openvpn_client_cert_t)]);

                    if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), list_size * sizeof(app::openvpn_client_cert_t)) != true) {
                        return false;
                    }

                    rpcMessage::ListFromBuff((app::openvpn_client_cert_t*) buff_ptr.get(), this->client_certs, list_size);
                }

                break;
            }

            case app::rpcMessageOpenvpnClientCertActionType::GEN_OPENVPN_CLIENT_CONFIG:
            {
                uint16_t len;
                if (rpcMessage::recvInterruptRetry(fd, &this->msgResult, sizeof(this->msgResult)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, this->client_config.common_name, sizeof(this->client_config.common_name)) != true) {
                    return false;
                }

                if (rpcMessage::recvInterruptRetry(fd, &len, sizeof(len)) != true) {
                    return false;
                }

                if (len > 0) {
                    std::unique_ptr<char> buff_ptr(new char[len + 1]());

                    if (rpcMessage::recvInterruptRetry(fd, buff_ptr.get(), len) != true) {
                        return false;
                    }

                    this->client_config.config_str = buff_ptr.get();
                }

                break;
            }
            default:
                break;
        }

        return true;
    }

    app::rpcMessageOpenvpnClientCertActionType rpcMessageOpenvpnClientCerts::getMsgAction() const
    {
        return this->msgAction;
    }

    void rpcMessageOpenvpnClientCerts::setMsgAction(const rpcMessageOpenvpnClientCertActionType action)
    {
        this->msgAction = action;
    }

    app::rpcMessageOpenvpnResultType rpcMessageOpenvpnClientCerts::getMsgResult() const
    {
        return this->msgResult;
    }

    void rpcMessageOpenvpnClientCerts::setMsgResult(const rpcMessageOpenvpnResultType result)
    {
        this->msgResult = result;
    }

    const std::list<app::openvpn_client_cert_t>& rpcMessageOpenvpnClientCerts::getOpenvpnClientCerts()
    {
        return this->client_certs;
    }
    void rpcMessageOpenvpnClientCerts::setOpenvpnClientCerts(const std::list<app::openvpn_client_cert_t> &client_certs)
    {
        this->client_certs = client_certs;
    }

    const openvpn_client_cert_t& rpcMessageOpenvpnClientCerts::getOpenvpnClientCert()
    {
        return this->client_certs.front();
    }

    void rpcMessageOpenvpnClientCerts::setOpenvpnClientCert(const openvpn_client_cert_t &client_cert)
    {
        this->client_certs.clear();
        this->client_certs.push_back(client_cert);
    }

    const openvpn_client_config_t& rpcMessageOpenvpnClientCerts::getOpenvpnClientConfig()
    {
        return this->client_config;
    }

    void rpcMessageOpenvpnClientCerts::setOpenvpnClientConfig(const openvpn_client_config_t &config)
    {
        this->client_config = config;
    }

    bool rpcMessageOpenvpnClientCerts::rpcGetOpenvpnClientCerts(app::rpcUnixClient &rpcClient,
                                                                std::list<app::openvpn_client_cert_t> &client_certs)
    {
        app::rpcMessageOpenvpnClientCerts msg;

        msg.setMsgAction(app::rpcMessageOpenvpnClientCertActionType::GET_OPENVPN_CLIENT_CERT);

        if (rpcClient.doRpc(&msg) == false ||
                msg.getMsgResult() != app::rpcMessageOpenvpnResultType::SUCCESS) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return false;
        }

        client_certs = msg.getOpenvpnClientCerts();

        return true;
    }

    bool rpcMessageOpenvpnClientCerts::rpcGenOpevpnClientCert(app::rpcUnixClient &rpcClient, const openvpn_client_cert_t &client_cert)
    {
        app::rpcMessageOpenvpnClientCerts msg;

        msg.setMsgAction(app::rpcMessageOpenvpnClientCertActionType::GEN_OPENVPN_CLIENT_CERT);
        msg.setOpenvpnClientCert(client_cert);

        if (rpcClient.doRpc(&msg) == false ||
                msg.getMsgResult() != app::rpcMessageOpenvpnResultType::SUCCESS) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return false;
        }

        return true;
    }

    bool rpcMessageOpenvpnClientCerts::rpcRevokeOpevpnClientCert(app::rpcUnixClient &rpcClient, const openvpn_client_cert_t &client_cert)
    {
        app::rpcMessageOpenvpnClientCerts msg;

        msg.setMsgAction(app::rpcMessageOpenvpnClientCertActionType::REVOKE_OPENVPN_CLIENT_CERT);
        msg.setOpenvpnClientCert(client_cert);

        if (rpcClient.doRpc(&msg) == false ||
                msg.getMsgResult() != app::rpcMessageOpenvpnResultType::SUCCESS) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return false;
        }

        return true;
    }

    bool rpcMessageOpenvpnClientCerts::rpcGenOpevpnClientConfig(app::rpcUnixClient &rpcClient, openvpn_client_config_t &config)
    {
        app::rpcMessageOpenvpnClientCerts msg;

        msg.setMsgAction(app::rpcMessageOpenvpnClientCertActionType::GEN_OPENVPN_CLIENT_CONFIG);
        msg.setOpenvpnClientConfig(config);

        if (rpcClient.doRpc(&msg) == false ||
                msg.getMsgResult() != app::rpcMessageOpenvpnResultType::SUCCESS) {
            syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
            return false;
        }

        config.config_str = msg.getOpenvpnClientConfig().config_str;

        return true;
    }

    std::string rpcMessageOpenvpnClientCerts::openVpnClientCertStateChar2Str(const char state)
    {
        if (state == 'V') {
            return "Valid";
        } else if (state == 'R') {
            return "Revoked";
        } else if (state == 'E') {
            return "Expired";
        } else {
            return "Unknown";
        }
    }
}
