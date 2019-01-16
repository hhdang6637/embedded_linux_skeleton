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

    typedef struct  {
        char caCrtName[50];         // ca.crt
    } openvpnCfg_Ca_t;

    typedef struct {
        char clientCrtName[50];
    } openvpnCfg_Ca_Client_t;

    typedef struct {
        char serverCrtName[50];
    } openvpnCfg_Ca_Server_t;

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
    };
}

#endif
