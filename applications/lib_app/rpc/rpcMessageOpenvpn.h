#ifndef APPLICATIONS_LIB_APP_RPC_RPCMESSAGEWIFI_H_
#define APPLICATIONS_LIB_APP_RPC_RPCMESSAGEWIFI_H_

#include "rpcMessage.h"

namespace app
{
    enum openvpnState:int16_t{
        DISABLE = 0,
        ENABLE
    };

    enum rpcMessageOpenvpnResultType: int16_t{
        FAILED = 0,
        SUCCESS,
        UNKNOW
    };

    enum rpcMessageOpenvpnActionType: int16_t {
        GET_SERVER_CFG
    };

    typedef
    struct openvpn_cfg{
        int16_t state; // Enable or Disable
        char port[6];

        // CA informations
        char caCrtName[50]; // ca.crt
        char caCrtEndDate[30]; // Jan  7 06:47:40 2020 GMT
        char caCrtStartDate[30];

    } openvpnCfg_t;

    typedef
    struct openvpn_cfg_client
    {
        openvpnCfg_t openvpnCfg;

    // Client informations
        char clientCrtName[50];
        char clientCrtEndDate[30]; // Jan  7 06:47:40 2020 GMT
        char clientCrtStartDate[30]; // Jan  7 06:47:40 2020 GMT
        char clientCountry[3]; // 2 + '\n'
        char clientProvince[50];
        char clientLocality[50];
        char clientOrganization[50];
        char clientCommonName[65]; // 64 + '\n'
        char clientEmail[65]; // 64 + '\n'

    } openvpnCfgClient_t;

    typedef
    struct openvpn_cfg_server
    {
        openvpnCfg_t openvpnCfg;
    // Server informations
        char serverCrtName[50];
        char serverCrtEndDate[30]; // Jan  7 06:47:40 2020 GMT
        char serverCrtStartDate[30]; // Jan  7 06:47:40 2020 GMT

    } openvpnCfgServer_t;

    std::string openMsgResult2Str(const rpcMessageOpenvpnResultType &result);

    class rpcMessageOpenvpn : public rpcMessage
    {
    private:
        app::rpcMessageOpenvpnResultType msgResult;
        app::rpcMessageOpenvpnActionType msgAction;

    public:
                                          rpcMessageOpenvpn(/* args */);
    virtual                               ~rpcMessageOpenvpn();
    virtual bool                          serialize(int fd);
    virtual bool                          deserialize(int);

    app::rpcMessageOpenvpnActionType      getMsgAction() const;
    void                                  setMsgAction(const rpcMessageOpenvpnActionType action);

    app::rpcMessageOpenvpnResultType      getMsgResult() const;
    void                                  setMsgResult(const rpcMessageOpenvpnResultType result);
    };
}

#endif
