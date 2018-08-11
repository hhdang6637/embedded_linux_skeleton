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
    // TODO Auto-generated constructor stub

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
    snprintf(this->password, sizeof(this->password), "%s", password);
}

std::string user::getPassword()
{
    return std::string(this->password);
}

bool user::isValid()
{
    return this->name[0] != '\0' && this->password[0] != '\0';
}

} /* namespace app */
