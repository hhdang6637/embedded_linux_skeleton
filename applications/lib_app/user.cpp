/*
 * user.cpp
 *
 *  Created on: Aug 8, 2018
 *      Author: hhdang
 */

#include "user.h"
#include <string.h>

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

std::string user::getName() const
{
    return std::string(this->name);
}

void user::setFullName(const char *fullName)
{
    snprintf(this->fullName, sizeof(this->fullName), "%s", fullName);
}

std::string user::getFullName() const
{
    return std::string(this->fullName);
}

void user::setPassword(const char *pass)
{
    snprintf(this->password, sizeof(this->password), "%s", pass);
}

std::string user::getPassword() const
{
    return std::string(this->password);
}

void user::setEmail(const char *email)
{
    snprintf(this->email, sizeof(this->email), "%s", email);
}

std::string user::getEmail() const
{
    return std::string(this->email);
}

static app::rpcMessageUsersResultType validateEmail(const char* email)
{
    const char *permis_special_local = "!#$&*~`?_-/{}|=.";
    const char *permis_special_domain = ".";

    int index_isolate = -1;
    char *c;

    if(email == NULL)
        return rpcMessageUsersResultType::EMAIL_EMPTY;

    if(strlen(email) > 32)
        return rpcMessageUsersResultType::EMAIL_INVALID;

    if(email[0] == '@') /* @example.com */
        return rpcMessageUsersResultType::EMAIL_INVALID;

    if(email[strlen(email)-1] == '@') /* abc@ */
        return rpcMessageUsersResultType::EMAIL_INVALID;

    int i =  strlen(email);
    for(; i >= 0; i--)
    {
        if(email[i] == '@')
        {
            index_isolate = i;
            break;
        }
    }

    if(index_isolate == -1)
        return rpcMessageUsersResultType::EMAIL_INVALID;

    if(email[ index_isolate + 1 ] == '.' || email[ strlen(email) - 1 ] == '.') /* abc@.example.vn*/
        return rpcMessageUsersResultType::EMAIL_INVALID;

    /* valid domain */
    for(i = index_isolate + 1; i < (int)strlen(email); i++)
    {
        c = (char*) strchr(permis_special_domain, email[i]);

        if(c == NULL)
        {
            //in range [0-9]
            if(email[i] >= 48 && email[i] <= 57)
                continue;

            //in range [A-Z]
            if(email[i] >= 65 && email[i] <= 90)
                continue;

            //in range[a-z]
            if(email[i] >= 97 && email[i] <= 122)
                continue;

            return rpcMessageUsersResultType::EMAIL_INVALID;
        }
    }

    /* valid local */
    for(i = 0; i < index_isolate; i++)
    {
        c = (char*) strchr(permis_special_local, email[i]);

        if(c == NULL)
        {
            //in range [0-9]
            if(email[i] >= 48 && email[i] <= 57)
                continue;

            //in range [A-Z]
            if(email[i] >= 65 && email[i] <= 90)
                continue;

            //in range[a-z]
            if(email[i] >= 97 && email[i] <= 122)
                continue;

            return rpcMessageUsersResultType::EMAIL_INVALID;
        }
    }

    return rpcMessageUsersResultType::SUCCEEDED;
}

static app::rpcMessageUsersResultType validatePassword(const char* pass)
{
    const char *permis_special = "!@#$^&()_-+={}[];:<>,.?/";

    if(pass == NULL)
        return rpcMessageUsersResultType::PASSWORD_NULL;

    if(strlen(pass) < 4 || strlen(pass) > 32)
        return rpcMessageUsersResultType::PASSWORD_LENGTH_INVALID;

    size_t i = 0;
    char *c = NULL;

    for(; i < strlen(pass); i++)
    {
        c = (char*) strchr(permis_special, pass[i]);

        if(c == NULL)
        {
            //in range [0-9]
            if(pass[i] >= 48 && pass[i] <= 57)
                continue;

            //in range [A-Z]
            if(pass[i] >= 65 && pass[i] <= 90)
                continue;

            //in range[a-z]
            if(pass[i] >= 97 && pass[i] <= 122)
                continue;

            return rpcMessageUsersResultType::PASSWORD_CHARACTER_INVALID;
        }
    }

    return rpcMessageUsersResultType::SUCCEEDED;
}

app::rpcMessageUsersResultType user::isValid()
{
    app::rpcMessageUsersResultType rc = rpcMessageUsersResultType::SUCCEEDED;
    size_t index;

    for(index = 0; index < strlen(this->name); index++) {
        if (this->name[index] == ' ') {
            return rpcMessageUsersResultType::USER_NAME_INVALID;
        }
    }

    if (this->name[0] == '\0') {
        return rpcMessageUsersResultType::USER_NAME_EMPTY;
    }

    rc = validateEmail(this->email);
    if(rc != rpcMessageUsersResultType::SUCCEEDED)
        return rc;

    rc = validatePassword(this->password);
    if(rc != rpcMessageUsersResultType::SUCCEEDED)
        return rc;

    return rc;
}

} /* namespace app */
