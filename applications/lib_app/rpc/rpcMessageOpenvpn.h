#ifndef APPLICATIONS_LIB_APP_RPC_RPCMESSAGEWIFI_H_
#define APPLICATIONS_LIB_APP_RPC_RPCMESSAGEWIFI_H_

#include "rpcMessage.h"

namespace app
{
    enum rpcMessageOpenvpnResultType: int16_t {
        FAILED = 0,
        SUCCESS,
        UNKNOW
    };

    enum rpcMessageOpenvpnCfgActionType: int16_t {
        GET_OPENVPN_CFG,
        SET_OPENVPN_CFG
    };

    typedef struct {
        int16_t     state; // Enable or Disable
        uint16_t    port;
    } openvpnCfg_t;

    std::string openMsgResult2Str(const rpcMessageOpenvpnResultType &result);

    class rpcMessageOpenvpnCfg : public rpcMessage
    {
    private:
        app::rpcMessageOpenvpnResultType    msgResult;
        app::rpcMessageOpenvpnCfgActionType msgAction;
        app::openvpnCfg_t                   openvpnCfg_data;

    public:
                                            rpcMessageOpenvpnCfg(/* args */);
        virtual                             ~rpcMessageOpenvpnCfg();
        virtual bool                        serialize(int fd);
        virtual bool                        deserialize(int);

        app::rpcMessageOpenvpnCfgActionType getMsgAction() const;
        void                                setMsgAction(const rpcMessageOpenvpnCfgActionType action);

        app::rpcMessageOpenvpnResultType    getMsgResult() const;
        void                                setMsgResult(const rpcMessageOpenvpnResultType result);

        void                                getOpenvpnCfg_data(app::openvpnCfg_t &openvpnCfg_data);
        void                                setOpenvpnCfg_data(app::openvpnCfg_t &openvpnCfg_data);

        static bool                         rpcGetOpenvpnCfg_data(app::rpcUnixClient &rpcClient,
                                                app::openvpnCfg_t &openvpnCfg_data);
        static bool                         rpcSetOpenvpnCfg_data(app::rpcUnixClient &rpcClient,
                                                app::openvpnCfg_t &openvpnCfg_data);
    };

    enum rpcMessageOpenvpnRsaInfoActionType: int16_t {
        GET_OPENVPN_RSA_INFO,
        SET_OPENVPN_RSA_INFO
    };

    typedef struct  {
        char ca_subjects[256];
        char server_subjects[256];
    } openvpn_rsa_info_t;

    class rpcMessageOpenvpnRsaInfo : public rpcMessage
    {
    private:
        app::rpcMessageOpenvpnResultType    msgResult;
        app::rpcMessageOpenvpnRsaInfoActionType msgAction;
        app::openvpn_rsa_info_t             openvpn_rsa_info;

    public:
                                            rpcMessageOpenvpnRsaInfo(/* args */);
        virtual                             ~rpcMessageOpenvpnRsaInfo();
        virtual bool                        serialize(int fd);
        virtual bool                        deserialize(int);

        app::rpcMessageOpenvpnRsaInfoActionType getMsgAction() const;
        void                                setMsgAction(const rpcMessageOpenvpnRsaInfoActionType action);

        app::rpcMessageOpenvpnResultType    getMsgResult() const;
        void                                setMsgResult(const rpcMessageOpenvpnResultType result);

        void                                getOpenvpnRsaInfo(app::openvpn_rsa_info_t &openvpn_rsa_info);
        void                                setOpenvpnRsaInfo(app::openvpn_rsa_info_t &openvpn_rsa_info);

        static bool                         rpcGetOpenvpnRsaInfo(app::rpcUnixClient &rpcClient,
                                                app::openvpn_rsa_info_t &openvpn_rsa_info);
    };
}

#endif
