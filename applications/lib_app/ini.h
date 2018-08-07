/*
 * ini.h
 *
 *  Created on: Aug 6, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_INI_H_
#define APPLICATIONS_LIB_APP_INI_H_

#include <stdint.h>
#include <string>
#include <map>

namespace app
{

class ini
{
    class section
    {
        std::map<std::string, std::string> properties;
        friend class ini;
    };

private:
    std::map<std::string, section> sections;
    void destroy();

public:
    ini();
    bool loadFromFile(const char*);
    bool writeToFile(const char*);

    bool get_string(const char *section, const char *key, std::string &value);
    bool get_bool(const char *section, const char *key, bool &value);
    bool get_int(const char *section, const char *key, int &value);
    bool get_uint16(const char *section, const char *key, uint16_t &value);

    bool set_string(const char *section, const char *key, std::string &value);
    bool set_bool(const char *section, const char *key, bool value);
    bool set_int(const char *section, const char *key, int value);
    bool set_uint16(const char *section, const char *key, uint16_t value);

    virtual ~ini();

    void dump();
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_INI_H_ */
