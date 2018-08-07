/*
 * ini.cpp
 *
 *  Created on: Aug 6, 2018
 *      Author: hhdang
 */

#include <string.h>
#include <syslog.h>

#include <iostream>     // std::cout
#include <fstream>      // std::ifstream

#include "ini.h"

namespace app
{

ini::ini()
{
    // TODO Auto-generated constructor stub
}

ini::~ini()
{
    this->destroy();
}

inline static char* rightstrip(char* s)
{
    char* p = s + strlen(s);
    while (p > s && isspace((unsigned char) (*--p)))
    {
        *p = '\0';
    }
    return s;
}

inline static char* leftstrip(const char* s)
{
    while (*s && isspace((unsigned char) (*s)))
    {
        s++;
    }
    return (char*) s;
}

inline static char * strlower(char * s)
{
    char *p = s;

    while (*p) {
        *p = tolower(*p);
        p++;
    }

    return s;
}

bool ini::loadFromFile(const char* filename)
{
    this->destroy();

    std::ifstream infile(filename);

    if (infile.is_open() == false) {
        return false;
    }

    char buff[512];
    char sect[512];

    sect[0] = 0;

    while (infile.good()) {
        infile.getline(buff, sizeof(buff));

        char *line = leftstrip(rightstrip(buff));
        char key[512];
        char value[512];

        size_t len = strlen(line);

        if (*line == ';' || *line == '#' || *line == 0) {

            continue; /* Comment lines */

        } else if (line[0] == '[' && line[len - 1] == ']') {

            sscanf(line, "[%[^]]", sect);
            strlower(sect);

            std::map<std::string, section>::iterator it = this->sections.find(sect);
            if (it == this->sections.end()) {
                section s;
                this->sections.insert(std::pair<std::string, section>(sect, s));
            }
        } else if (sscanf(line, "%[^=] = \"%[^\"]\"", key, value) == 2
                || sscanf(line, "%[^=] = '%[^\']'", key, value) == 2
                || sscanf(line, "%[^=] = %[^;#]", key, value) == 2) {

            std::map<std::string, section>::iterator it = this->sections.find(sect);
            if (it == this->sections.end()) {
                continue;
            }

            strlower(key);
            strlower(value);
            std::cout << "key :" << key << ", value :" << value << std::endl;

            it->second.properties.insert(
                    std::pair<std::string, std::string>(leftstrip(rightstrip(key)), leftstrip(rightstrip(value))));
         } else {
             syslog(LOG_WARNING, "ini: cannot hanlde line (%s)", line);
         }
    }

    infile.close();

    return true;
}

void ini::destroy()
{
    this->sections.clear();
}

void ini::dump() {
    for (std::map<std::string, section>::iterator it = this->sections.begin();
            it != this->sections.end(); it++) {
        std::cout << std::endl << "[" << it->first.c_str() << "]" << std::endl;

        std::map<std::string, std::string> &section = it->second.properties;

        for (std::map<std::string, std::string>::iterator subit = section.begin();
                subit != section.end(); subit++) {
            std::cout << subit->first.c_str() << "=" << subit->second.c_str() << std::endl;
        }
    }
}

} /* namespace app */
