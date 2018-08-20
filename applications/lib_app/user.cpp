/*
 * user.cpp
 *
 *  Created on: Aug 8, 2018
 *      Author: hhdang
 */

#include "user.h"

namespace app
{

user::user()
{
    this->name[0] = '\0';
    this->password[0] = '\0';
    this->fullName[0] = '\0';
    this->email[0] = '\0';
}

user::user(const char*name, const char*pass, const char*fullName, const char*email) :
        user()
{
    if (name)
        snprintf(this->name, sizeof(this->name), "%s", name);

    if (pass)
        snprintf(this->password, sizeof(this->password), "%s", pass);

    if (fullName)
        snprintf(this->fullName, sizeof(this->fullName), "%s", fullName);

    if (email)
        snprintf(this->email, sizeof(this->email), "%s", email);
}

user::~user()
{
    // TODO Auto-generated destructor stub
}

void user::setName(const char *name)
{
    snprintf(this->name, sizeof(this->name), "%s", name);
}

std::string user::getName()
{
    return std::string(this->name);
}

void user::setFullName(const char *fullName)
{
    snprintf(this->fullName, sizeof(this->fullName), "%s", fullName);
}

std::string user::getFullName()
{
    return std::string(this->fullName);
}

void user::setPassword(const char *pass)
{
    snprintf(this->password, sizeof(this->password), "%s", pass);
}

std::string user::getPassword()
{
    return std::string(this->password);
}

void user::setEmail(const char *email)
{
    snprintf(this->email, sizeof(this->email), "%s", email);
}

std::string user::getEmail()
{
    return std::string(this->email);
}

bool user::isValid()
{
    bool rc = true;

    if (this->name[0] == '\0' || this->password[0] == '\0') {
        rc = false;
    }

    return rc;
}

} /* namespace app */
