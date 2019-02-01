/*
 * simplewebfactory_url_js_map.cpp
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */
#include "simplewebfactory.h"
#include "firmware_manager_js.h"
#include "openvpn_js.h"
#include "time_ntp_js.h"
#if defined (pi_3_b) || defined (orange_pi_zero)
#include "wifisetting_js.h"
#endif

extern std::string json_resource_usage_history(FCGX_Request *request);
extern std::string json_handle_users(FCGX_Request *request);
extern std::string json_handle_syslog(FCGX_Request *request);
extern std::string json_general_info(FCGX_Request *request);

void simpleWebFactory::init_url_js_map()
{
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/resource_usage_history", json_resource_usage_history));
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/general_info", json_general_info));
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/firmware_upgrade", json_handle_firmware_upgrade));
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/firmware_status", json_handle_firmware_status));
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/firmware_info", json_handle_firmware_info));
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/users", json_handle_users));
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/syslog", json_handle_syslog));
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/openvpn_cfg", json_handle_openvpn_cfg));
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/openvpn_rsa", json_handle_openvpn_rsa));
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/openvpn_client_cert", json_handle_openvpn_client_cert));
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/time_ntp", json_handle_time_ntp));
#if defined (pi_3_b) || defined (orange_pi_zero)
    this->url_js_map.insert(std::pair<std::string, jsCallback>("/json/wifisetting", json_handle_wifisetting));
#endif
}
