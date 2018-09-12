/*
 * user.h
 *
 *  Created on: Aug 8, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_LIB_APP_USER_H_
#define APPLICATIONS_LIB_APP_USER_H_

#include <string>
#include "defines.h"

namespace app
{

enum rpcMessageUsersResultType : uint16_t
{
    SUCCEEDED,
    VALID,
    USER_INVALID,
    USERNAME_EXISTED,
    USER_NOT_EXISTED,
    EMAIL_EXISTED,
    EMAIL_EMPTY,
    EMAIL_INVALID,
    USER_NAME_INVALID,
    USER_NAME_EMPTY,
    PASSWORD_LENGTH_INVALID,
    PASSWORD_CHARACTER_INVALID,
    PASSWORD_NULL,
    ERROR_MAX_USER,
    UNKNOWN_ERROR
};

class user
{
    char name[USR_NAME_LENGTH];
    char password[PWD_LENGTH];
    char fullName[FULL_NAME_LENGTH];
    char email[EMAIL_LENGTH];

public:
    user();
    user(const char*name, const char*pass, const char*fullname = 0, const char*email = 0);
    virtual ~user();

    void setName(const char *name);
    std::string getName() const;
    void setFullName(const char *fullName);
    std::string getFullName() const;
    void setPassword(const char *pass);
    std::string getPassword() const;
    void setEmail(const char *email);
    std::string getEmail() const;
    app::rpcMessageUsersResultType isValid() const;     // verify user information
};

} /* namespace app */

#endif /* APPLICATIONS_LIB_APP_USER_H_ */
