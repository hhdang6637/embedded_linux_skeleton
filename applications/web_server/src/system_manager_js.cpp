/*
 * system_manager_js.cpp
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */
#include <string>
#include <sstream>
#include <list>          // std::queue

#include <stdlib.h>
#include <fcgiapp.h>
#include <syslog.h>

#include "fcgi.h"
#include "simplewebfactory.h"
#include "rpcUnixClient.h"
#include "rpcMessageResourceHistory.h"
#include "rpcMessageUsers.h"
#include "firmware_manager_js.h"
#include "MPFDParser/Parser.h"
#include "MPFDParser/Field.h"
#include "MPFDParser/Exception.h"
#include "user.h"
#include "conversion.h"

#define TO_KBIT(a) ((a * 8 ) / 1000)

typedef std::list<float> tx_rates_t;
typedef std::list<float> rx_rates_t;

static std::pair<tx_rates_t, rx_rates_t> calculate_rates(const std::list<struct rtnl_link_stats> &stats)
{
    tx_rates_t    tx_rates;
    rx_rates_t    rx_rates;
    unsigned long tx_bytes_old = stats.begin()->tx_bytes;
    unsigned long rx_bytes_old = stats.begin()->rx_bytes;

    for (auto it = stats.begin(); it != stats.end(); ++it) {
        // skip the first sample
        if (it == stats.begin())
            continue;

        float tx_rate = 0, rx_rate = 0;
        if (it->tx_bytes != 0 && (tx_bytes_old != it->tx_bytes)) {
            tx_rate = it->tx_bytes - tx_bytes_old;
            tx_bytes_old = it->tx_bytes;
        }

        if (it->rx_bytes != 0 && (rx_bytes_old != it->rx_bytes)) {
            rx_rate = it->rx_bytes - rx_bytes_old;
            rx_bytes_old = it->rx_bytes;
        }

        tx_rates.push_back(TO_KBIT(tx_rate));
        rx_rates.push_back(TO_KBIT(rx_rate));
    }

    return std::make_pair(tx_rates, rx_rates);
}

std::string json_resource_usage_history(FCGX_Request *request)
{
    std::ostringstream ss_json;
    ss_json << "{";

    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageResourceHistory msg;
    std::string interface_name = "eth0"; // TODO: The user will choose the interface name with WEB UI
    msg.set_interface_name(interface_name);
    if (rpcClient->doRpc(&msg)) {

        cpu_stat_t pre, cur;
        std::list<cpu_stat_t> cpu_usage_history = msg.get_cpu_history();

        ss_json << "\"json_cpu_usage_history\":[";

        size_t counter = 0;
        for(std::list<cpu_stat_t>::iterator it = cpu_usage_history.begin();
                it != cpu_usage_history.end(); ++it) {

            counter++;

            if (it == cpu_usage_history.begin()) {
                pre = *it;
                continue;
            }

            cur = *it;

            long double total_diff = cur.total - pre.total;
            long double busy_diff = cur.busy - pre.busy;

            ss_json << (long)(busy_diff / total_diff * 100);

            if (counter < cpu_usage_history.size()) {
                ss_json << ",";
            }

            pre = cur;
        }

        ss_json << "]";

        std::list<struct sysinfo> ram_history = msg.get_ram_history();
        ss_json << ",\"json_ram_history\":[";

        struct sysinfo sysinfoLatest = {0};
        counter = 0;
        for (std::list<struct sysinfo>::iterator it = ram_history.begin();
                it != ram_history.end(); ++it) {

            counter++;

            ss_json << (((long long)it->totalram - it->freeram) * 100) / it->totalram;

            if (counter < ram_history.size()) {
                ss_json << ",";
            } else {
                sysinfoLatest = *it;
            }
        }
        ss_json << "]";
        ss_json << ",\"json_ram_total\": " << sysinfoLatest.totalram;
        ss_json << ",\"json_ram_free\": " << sysinfoLatest.freeram;

        std::pair<tx_rates_t, rx_rates_t> rates = calculate_rates(msg.get_network_history());

        ss_json << ",\"json_network_history\": {";
        ss_json << "\"tx_bytes\":[";

        counter = 0;
        for (auto const &tx_rate : rates.first) {
            counter++;

            ss_json << tx_rate;

            if (counter < rates.first.size()) {
                ss_json << ",";
            }
        }

        ss_json << "]";
        ss_json << ",\"rx_bytes\":[";

        counter = 0;
        for (auto const &rx_rate : rates.second) {
            counter++;

            ss_json << rx_rate;

            if (counter < rates.second.size()) {
                ss_json << ",";
            }
        }

        ss_json << "]}";
    }

    ss_json << "}";

    return ss_json.str();
}

static inline std::string build_user_rsp_json(const std::string &status, const std::string &message = "")
{
    std::ostringstream ss_json;
    ss_json << "{";
    ss_json << "\"status\": \"" << status << "\",";
    ss_json << "\"message\": \"" << message << "\"";
    ss_json << "}";

    return ss_json.str();
}

static app::rpcMessageUsersResultType do_add_user(app::user &user)
{
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageUsers msg;

    msg.setMsgAction(app::rpcMessageUsersActionType::ADD_USER);
    msg.setUser(user);

    if (rpcClient->doRpc(&msg) == false) {
        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
        return app::rpcMessageUsersResultType::UNKNOWN_ERROR;
    }

    return msg.getMsgResult();
}

static app::rpcMessageUsersResultType do_edit_user(app::user &user, uint16_t changePasswd)
{
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageUsers msg;

    msg.setMsgAction(app::rpcMessageUsersActionType::EDIT_USER);
    msg.setUser(user);
    msg.setChangePasswd(changePasswd);

    if (rpcClient->doRpc(&msg) == false) {
        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
        return app::rpcMessageUsersResultType::UNKNOWN_ERROR;
    }

    return msg.getMsgResult();
}

static app::rpcMessageUsersResultType do_delete_user(app::user &user) {
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageUsers msg;

    msg.setMsgAction(app::rpcMessageUsersActionType::DELETE_USER);
    msg.setUser(user);

    if (rpcClient->doRpc(&msg) == false) {
        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
        return app::rpcMessageUsersResultType::UNKNOWN_ERROR;
    }

    return msg.getMsgResult();
}

std::string json_handle_users(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);
    std::ostringstream ss_json;
    const std::string failed_str = "failed";

    if (method && (strcmp(method, "GET") == 0)) {
        char filterUser[32];
        if (fcgi_form_varable_str(request, "user", filterUser, sizeof(filterUser)) <= 0) {
            filterUser[0] = '\0';
        }

        app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
        app::rpcMessageUsers msgUser;

        if (rpcClient->doRpc(&msgUser) == true) {

            std::list<app::user> users = msgUser.getUsers();
            ss_json << "{\"json_users_list\": ";
            ss_json << "[";
            size_t counter = 0;
            for (auto &u : users) {

                if (filterUser[0] != '\0') {

                    if (strcmp(filterUser, u.getName().c_str()) == 0) {
                        ss_json << "{";
                        ss_json << "\"name\":\"" << u.getName() << "\"";
                        ss_json << ",";
                        ss_json << "\"fullname\":\"" << u.getFullName() << "\"";
                        ss_json << ",";
                        ss_json << "\"email\":\"" << u.getEmail() << "\"";
                        ss_json << "}";
                        break;
                    }

                } else {

                    ss_json << "{";
                    ss_json << "\"name\":\"" << u.getName() << "\"";
                    ss_json << ",";
                    ss_json << "\"fullname\":\"" << u.getFullName() << "\"";
                    ss_json << ",";
                    ss_json << "\"email\":\"" << u.getEmail() << "\"";
                    ss_json << "}";

                    if (++counter < users.size()) {
                        ss_json << ",";
                    }
                }
            }
            ss_json << "]";
            ss_json << "}";
        } else {
            syslog(LOG_ERR, "can't call rpc to get user list");
        }
        return ss_json.str();
    }

    if (method && (strcmp(method, "POST") == 0) && contentType) {

        std::string data;

        if (simpleWebFactory::get_post_data(request, data))
        {
            app::user user;
            std::string action;
            std::string username;
            uint16_t changePasswd = 0;
            try {
                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());

                action = POSTParser.GetFieldText("action");

                if (action == "delete")
                {
                    user.setName(POSTParser.GetFieldText("username").c_str());

                } else {
                    user.setFullName(POSTParser.GetFieldText("fullname").c_str());
                    user.setName(POSTParser.GetFieldText("user_name").c_str());
                    user.setPassword(POSTParser.GetFieldText("password").c_str());
                    user.setEmail(POSTParser.GetFieldText("email").c_str());

                    if (action == "edit") {
                        if (POSTParser.GetFieldText("edit_pwd") == "enabled") {
                            changePasswd = 1;
                        }
                    }
                }

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());

                return build_user_rsp_json(failed_str, "Failed to get data from browser");
            }

            app::rpcMessageUsersResultType result;

            if (action == "add") {
                result = do_add_user(user);
            } else if (action == "edit") {
                result = do_edit_user(user, changePasswd);
            } else {
                result = do_delete_user(user);
            }

            if (result == app::rpcMessageUsersResultType::SUCCEEDED) {
                return build_user_rsp_json(userMsgResult2Str(result));
            } else {
                return build_user_rsp_json(failed_str, userMsgResult2Str(result));
            }

        }
    }

    syslog(LOG_ERR, "Failed to add user\n");

    return build_user_rsp_json(failed_str, userMsgResult2Str(app::rpcMessageUsersResultType::UNKNOWN_ERROR));
}

std::string json_general_info(FCGX_Request *request)
{
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageResourceHistory msg;

    msg.setMsgAction(app::rpcResourceActionType::GET_GENERAL_INFO);

    if (rpcClient->doRpc(&msg) == false) {
        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
        return "";
    }

    app::resourceGeneralInfo_t general_info = msg.get_general_info();
    std::ostringstream ss_json;

    ss_json << "{\"json_general_info\": {";

    ss_json << "\"fw_description\": ";
    ss_json << "\"";
    ss_json << general_info.fw_description;
    ss_json << "\", ";

    ss_json << "\"temperature\": ";
    ss_json << "\"";
    ss_json << general_info.temperature;
    ss_json << "\", ";

    ss_json << "\"current_total_ram\": ";
    ss_json << "\"";
    ss_json << (int)(general_info.current_ram.totalram/(1024*1024));
    ss_json << "\", ";

    ss_json << "\"current_usage_ram\": ";
    ss_json << "\"";
    ss_json << (int)((general_info.current_ram.totalram - general_info.current_ram.freeram)/(1024*1024));
    ss_json << "\", ";

    ss_json << "\"current_cpu\": ";
    ss_json << "\"";
    ss_json << (int) ((general_info.current_cpu.busy*100)/general_info.current_cpu.total);
    ss_json << "\", ";

    ss_json << "\"current_time\": ";
    ss_json << "\"";
    ss_json << time2String(general_info.current_time);
    ss_json << "\"";

    ss_json << "}}";

    return ss_json.str();
}
