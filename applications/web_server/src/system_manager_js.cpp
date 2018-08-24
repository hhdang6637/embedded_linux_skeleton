/*
 * system_manager_js.cpp
 *
 *  Created on: Jul 23, 2018
 *      Author: hhdang
 */
#include <string>
#include <sstream>
#include <stdlib.h>
#include <list>          // std::queue

#include "fcgi.h"
#include "simplewebfactory.h"
#include "rpcUnixClient.h"
#include "rpcMessageResourceHistory.h"
#include "rpcMessageUsers.h"

#include <fcgiapp.h>
#include <syslog.h>

#include "firmware_manager_js.h"
#include "MPFDParser/Parser.h"
#include "MPFDParser/Field.h"
#include "MPFDParser/Exception.h"
#include "user.h"

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


//don't forget to delete
// ========================================================================================================= //

static int valid_user(std::string fullname, std::string user_name, std::string password, std::string repassword,
                        std::string email)
{
    //compare password and repassword
    if (password.compare(repassword) != 0) {
        return 0;
    }

    return 1;
}

static int do_add_user(app::user &user)
{
    app::rpcUnixClient* rpcClient = app::rpcUnixClient::getInstance();
    app::rpcMessageUsers msg;

    if (rpcClient->doRpc(&msg) == false) {
        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
        return 0;
    }

    std::list<app::user> users = msg.getUsers();

    for(auto &u : users) {
        if (user.getName().compare(u.getName()) == 0) {
            return 0;
        }
    }

    msg.setUser(user);

    if (rpcClient->doRpc(&msg) == false) {
        syslog(LOG_ERR, "%s:%d - something went wrong: doRpc\n", __FUNCTION__, __LINE__);
        return 0;
    }

    return 1;
}

static bool get_post_data(FCGX_Request *request, std::string &data)
{
    const char *contentLenStr = FCGX_GetParam("CONTENT_LENGTH", request->envp);
    int         contentLength = 0;

    if (contentLenStr) {
        contentLength = strtol(contentLenStr, NULL, 10);
    }

    for (int len = 0; len < contentLength; len++) {
        int ch = FCGX_GetChar(request->in);

        if (ch < 0) {

            syslog(LOG_ERR, "Failed to get file content\n");
            return false;

        } else {
            data += ch;
        }
    }

    return true;
}

std::string json_handle_users(FCGX_Request *request)
{
    const char *method      = FCGX_GetParam("REQUEST_METHOD", request->envp);
    const char *contentType = FCGX_GetParam("CONTENT_TYPE", request->envp);

    if (method && (strcmp(method, "GET") == 0)) {
        std::ostringstream ss_json;

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
            for(auto &u : users) {

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

                    if(++counter < users.size()) {
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

        if (get_post_data(request, data))
        {
            app::user user;
            std::string fullname, user_name, password, repassword, email;
            try
            {
                MPFD::Parser POSTParser;

                POSTParser.SetContentType(contentType);

                POSTParser.AcceptSomeData(data.c_str(), data.size());

                fullname = POSTParser.GetField("fullname")->GetTextTypeContent();
                user_name = POSTParser.GetField("user_name")->GetTextTypeContent();
                password = POSTParser.GetField("password")->GetTextTypeContent();
                repassword = POSTParser.GetField("repassword")->GetTextTypeContent();
                email = POSTParser.GetField("email")->GetTextTypeContent();

            } catch (MPFD::Exception &e) {
                syslog(LOG_ERR, "%s\n", e.GetError().c_str());
                return "failed";
            }

            if (valid_user(fullname, user_name, password, repassword, email))
            {
                user.setFullName(fullname.c_str());
                user.setName(user_name.c_str());
                user.setPassword(password.c_str());
                user.setEmail(email.c_str());

                if (do_add_user(user)) {
                    return "succeeded";
                }
            }
        }
    }

    syslog(LOG_ERR, "Failed to add user\n");

    return "failed";
}
