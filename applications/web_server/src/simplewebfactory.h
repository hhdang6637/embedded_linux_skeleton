/*
 * simplewebfactory.h
 *
 *  Created on: Jul 20, 2018
 *      Author: hhdang
 */

#ifndef _SIMPLE_WEB_FACTORY_H_
#define _SIMPLE_WEB_FACTORY_H_

#include <fcgiapp.h>
#include <string>
#include <map>
#include <functional>

#define INTERNAL_RESOURCE "/var/www/hiawatha/private/"

typedef std::function<std::string(FCGX_Request *request)> jsCallback;

class simpleWebFactory
{
private:
    simpleWebFactory();

    static simpleWebFactory* s_instance;

    std::string html_header_str;
    std::string html_footer_str;
    std::string html_navbar_str;

    std::map<std::string,std::string>   url_html_map;
    std::map<std::string,jsCallback> url_js_map;

    void init_url_html_map();
    void init_url_js_map();

public:
    virtual ~simpleWebFactory();
    static simpleWebFactory* getInstance();
    void handle_request(FCGX_Request *request);
    const char* get_html_str(const char* url);
    const char* get_js_str(FCGX_Request *request);
    void redirect(FCGX_Request *request, std::string url);
    void login_header_reponse(FCGX_Request *request, bool validate_login);

    static bool file_to_string(std::string filename, std::string &output);
};

#endif /* _SIMPLE_WEB_FACTORY_H_ */
