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
    char name[32];
    char fullName[32];
    char password[32];
    char email[32];

public:
    user();
    virtual ~user();

    void setName(const char *name);
    std::string getName();
    void setFullName(const char *fullName);
    std::string getFullName();
    void setPassword(const char *pass);
    std::string getPassword();
    void setEmail(const char *email);
    std::string getEmail();
    bool isValid();     // verify user information
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_USER_H_ */
