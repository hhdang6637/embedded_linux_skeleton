/*
 * simplewebfactory.h
 *
 *  Created on: Jul 20, 2018
 *      Author: hhdang
 */

#ifndef _SIMPLE_WEB_FACTORY_H_
#define _SIMPLE_WEB_FACTORY_H_

#include <string>
#include <map>

class simpleWebFactory
{
private:

    simpleWebFactory();

    static simpleWebFactory* s_instance;

    std::string html_header_str;
    std::string html_footer_str;
    std::string html_navbar_str;

    std::map<std::string,std::string> url_map;

    void init_url_map();

public:
    virtual ~simpleWebFactory();
    static simpleWebFactory* getInstance();
    const char* get_html_header_str();
    const char* get_html_footer_str();
    const char* get_html_navbar_str();
    const char* get_html_str(const char* url);
};

#endif /* _SIMPLE_WEB_FACTORY_H_ */
