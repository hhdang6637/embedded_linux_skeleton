/*
 * user.h
 *
 *  Created on: Aug 8, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_USER_H_
#define APPLICATIONS_LIB_APP_USER_H_

#include <string>

namespace app
{

class user
{
    std::string name;
    std::string password;

public:
    user();
    virtual ~user();

    void setName(const char *name) {this->name = name; };
    void setPassword(const char *pass) {this->password = pass;};
    std::string getName() {return this->name; };
    bool isValid();     // veryfi user information
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_USER_H_ */
