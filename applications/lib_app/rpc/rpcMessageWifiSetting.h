/*
 * rpcMessageWifiSetting.h
 *
 *  Created on: Aug 11, 2018
 *      Author: hhdang
 */
#define SSID_LENGTH             32
#define PRESHARED_KEY_LENGTH    64

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
    HOSTAPD_NOT_START,
    UNKNOWN_ERROR
};

enum rpcMessageWifiSettingActionType : uint16_t
{
    GET_WIFI_SETTING,
    EDIT_WIFI_SETTING
};

std::string wifiMsgResult2Str(const rpcMessageWifiSettingResultType &result);

typedef struct {
    char presharedKey[PRESHARED_KEY_LENGTH];
    char ssid[SSID_LENGTH];
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
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_RPC_RPCMESSAGEWIFI_H_ */
