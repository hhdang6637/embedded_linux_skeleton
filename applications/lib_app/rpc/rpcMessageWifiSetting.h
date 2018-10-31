/*
 * rpcMessageWifiSetting.h
 *
 *  Created on: Aug 11, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_RPC_RPCMESSAGEWIFI_H_
#define APPLICATIONS_LIB_APP_RPC_RPCMESSAGEWIFI_H_

#include <list>
#include "rpcMessage.h"

namespace app
{

enum rpcMessageWifiSettingResultType : uint16_t
{
    SUCCEEDED,
    PRESHAREDKEY_CHARACTER_INVALID,
    PRESHAREDKEY_LENGTH_INVALID,
    PRESHAREDKEY_IS_NULL,
    SSID_CHARACTER_INVALID,
    SSID_LENGTH_INVALID,
    SSID_IS_NULL,
    UNKNOWN_ERROR
};

enum rpcMessageWifiSettingActionType : uint16_t
{
    GET_WIFI_SETTING,
    EDIT_WIFI_SETTING
};

typedef struct {
    std::string presharedKey;
    std::string ssid;
    uint16_t    accessPoint;
    uint16_t    securityType;
} rpcMessageWifiSettingData_t;

class rpcMessageWifiSetting: public rpcMessage
{
    app::rpcMessageWifiSettingActionType    msgAction;
    app::rpcMessageWifiSettingResultType    msgResult;
    rpcMessageWifiSettingData_t             msgData;

public:
                                          rpcMessageWifiSetting();
    virtual                               ~rpcMessageWifiSetting();
    virtual bool                          serialize(int fd);
    virtual bool                          deserialize(int);

    app::rpcMessageWifiSettingActionType  getMsgAction() const;
    void                                  setMsgAction(const rpcMessageWifiSettingActionType action);

    app::rpcMessageWifiSettingResultType  getMsgResult() const;
    void                                  setMsgResult(const rpcMessageWifiSettingResultType result);

    app::rpcMessageWifiSettingData_t      getWifiSettingMsgData() const;
    void                                  setWifiSettingMsgData(const app::rpcMessageWifiSettingData_t msgData);

    std::string                           wifiMsgResult2Str();

};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPC_RPCMESSAGEWIFI_H_ */
