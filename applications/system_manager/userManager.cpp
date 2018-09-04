/*
 * userManager.cpp
 *
 *  Created on: Aug 7, 2018
 *      Author: hhdang
 */
#include <iostream>
#include <list>
#include <syslog.h>
#include <string.h>

#include "userManager.h"

namespace app
{

userManager::userManager()
{
    // TODO Auto-generated constructor stub
}

userManager::~userManager()
{
    // TODO Auto-generated destructor stub
}

const int userManager::MAX_USERS = 10;
userManager *userManager::s_instance = 0;

userManager* userManager::getInstance()
{
    if (s_instance == 0) {
        s_instance = new userManager();
    }

    return s_instance;
}

void userManager::initDefaultUsers()
{
    this->users.clear();

    FILE *fp;

    if ((fp = fopen("/etc/passwd", "w")) == NULL) {
        syslog(LOG_EMERG, "Cannot add default users to linux\n");
        return;
    }

    fprintf(fp,
        "root:x:0:0:root:/root:/bin/sh\n"
        "daemon:x:1:1:daemon:/usr/sbin:/bin/false\n"
        "bin:x:2:2:bin:/bin:/bin/false\n"
        "sys:x:3:3:sys:/dev:/bin/false\n"
        "sync:x:4:100:sync:/bin:/bin/sync\n"
        "mail:x:8:8:mail:/var/spool/mail:/bin/false\n"
        "www-data:x:33:33:www-data:/var/www:/bin/false\n"
        "operator:x:37:37:Operator:/var:/bin/false\n"
        "nobody:x:65534:65534:nobody:/home:/bin/false\n"
    );

    fclose(fp);

    std::list<app::user> defaultUsers;
    app::user user;
    user.setName("root");
    user.setFullName("root");
    user.setPassword("root");
    user.setEmail("root@gmail.com");
    defaultUsers.push_back(user);

    user.setName("admin");
    user.setFullName("admin");
    user.setPassword("admin");
    user.setEmail("admin@gmail.com");
    defaultUsers.push_back(user);

    for(auto &u : defaultUsers) {
        this->addUser(u);
    }
}

void userManager::createUser(app::user &user)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "adduser "
//            "-h /home " // set home dir
            "-s /bin/sh "
//            "-H "// Don't create home dir
            "-D "// Don't assign a password
            "-G "// add user to group users
            "users "
            "%s >/dev/null 2>&1", user.getName().c_str());

    system(cmd);
}

void userManager::changeUserPass(app::user &user)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "echo -e \"%s\\n%s\" | passwd %s >/dev/null 2>&1",
            user.getPassword().c_str(),
            user.getPassword().c_str(),
            user.getName().c_str());

    system(cmd);
}

bool userManager::usernameExisted(std::string user_name)
{
    for (auto &u : this->users) {
        if (u.first.compare(user_name) == 0) {
            return true;
        }
    }

    return false;
}

bool userManager::emailExisted(std::string email)
{
    for (auto &u : this->users) {
        if (u.second.getEmail().compare(email) == 0) {
            return true;
        }
    }

    return false;
}

app::rpcMessageUsersResultType userManager::addUser(app::user &user)
{
    if (users.size() >= userManager::MAX_USERS) {
        syslog(LOG_NOTICE, "maximum user is reached %d, cannot add more", userManager::MAX_USERS);
        return app::rpcMessageUsersResultType::ERROR_MAX_USER;
    }

    if (user.isValid()) {
        if (usernameExisted(user.getName())) {
            syslog(LOG_NOTICE, "user existed");
            return app::rpcMessageUsersResultType::USERNAME_EXISTED;

        } else if (emailExisted(user.getEmail())) {
            syslog(LOG_NOTICE, "email existed");
            return app::rpcMessageUsersResultType::EMAIL_EXISTED;
        }

        this->users.insert(std::pair<std::string, app::user>(user.getName(), user));
        this->createUser(user);
        this->changeUserPass(user);

        if (this->writeToFile() == false) {
            syslog(LOG_ERR, "cannot update the user.conf");
        }

        syslog(LOG_NOTICE, "created user %s successfully", user.getName().c_str());
        return app::rpcMessageUsersResultType::SUCCEEDED;
    }

    syslog(LOG_NOTICE, "user not valid for add");
    return app::rpcMessageUsersResultType::USER_INVALID;
}

app::rpcMessageUsersResultType userManager::editUser(app::user &user, uint16_t changPasswd)
{
    auto it = this->users.find(user.getName());

    if (it == this->users.end()) {
        syslog(LOG_NOTICE, "user doesn't exist");
        return app::rpcMessageUsersResultType::USER_NOT_EXISTED;
    }

    if (!changPasswd) {
        user.setPassword(it->second.getPassword().c_str());
    }

    if (user.isValid()) {

        if (it->second.getEmail() != user.getEmail() && emailExisted(user.getEmail())) {
            syslog(LOG_NOTICE, "email existed");
            return app::rpcMessageUsersResultType::EMAIL_EXISTED;
        }

        it->second = user;
        this->changeUserPass(user);

        if (this->writeToFile() == false) {
            syslog(LOG_ERR, "cannot update the user.conf");
        }

        syslog(LOG_NOTICE, "edit user %s succeed", user.getName().c_str());
        return app::rpcMessageUsersResultType::SUCCEEDED;
    }

    syslog(LOG_NOTICE, "user not valid for edit");
    return app::rpcMessageUsersResultType::USER_INVALID;
}

app::rpcMessageUsersResultType userManager::deleteUser(app::user &user)
{
    if (user.getName().compare("admin") == 0) {
        syslog(LOG_WARNING, "cannot delete user admin");
        return app::rpcMessageUsersResultType::UNKNOWN_ERROR;
    }

    auto it = this->users.find(user.getName());

    if (it != this->users.end()) {
        this->users.erase(it);

        if (this->writeToFile() == false) {
            syslog(LOG_ERR, "cannot update the user.conf");
        }

        syslog(LOG_NOTICE, "delete user %s succeed", user.getName().c_str());
        return app::rpcMessageUsersResultType::SUCCEEDED;
    } else {
        syslog(LOG_NOTICE, "user don't existed");
        return app::rpcMessageUsersResultType::USER_NOT_EXISTED;
    }

    return app::rpcMessageUsersResultType::UNKNOWN_ERROR;
}

void userManager::initFromFile()
{
    initDefaultUsers();

    app::ini userConf;

    if (userConf.loadFromFile("/data/users.conf")) {

        for(int i = 0; i < userManager::MAX_USERS; i++) {

            char sect[32];
            std::string value;

            snprintf(sect, sizeof(sect), "user_%d", i);
            if (userConf.get_string(sect, "name", value)) {

                syslog(LOG_NOTICE, "found user %s from /data/users.conf", value.c_str());

                app::user user;
                user.setName(value.c_str());

                if (userConf.get_string(sect, "password", value)) {
                    user.setPassword(value.c_str());
                }

                if (userConf.get_string(sect, "fullname", value)) {
                    user.setFullName(value.c_str());
                }

                if (userConf.get_string(sect, "email", value)) {
                    user.setEmail(value.c_str());
                }

                this->addUser(user);
            }
        }

    } else {
        syslog(LOG_NOTICE, "cannot load user config from /data/users.conf, use default users");
    }

    if (this->writeToFile() != true) {
        syslog(LOG_WARNING, "cannot write user config to /data/users.conf");
    }
}

bool userManager::writeToFile()
{
    app::ini userConf;
    int i = 0;
    for (auto it = this->users.begin(); it != this->users.end(); it++)
    {
        char sect[32];
        std::string value;

        snprintf(sect, sizeof(sect), "user_%d", i++);

        value = it->second.getName();
        userConf.set_string(sect, "name", value);

        value = it->second.getPassword();
        userConf.set_string(sect, "password", value);

        value = it->second.getFullName();
        userConf.set_string(sect, "fullname", value);

        value = it->second.getEmail();
        userConf.set_string(sect, "email", value);
    }

    return userConf.writeToFile("/data/users.conf");
}

std::list<app::user> userManager::getUsers()
{
    std::list<app::user> users;
    for (auto it = this->users.begin(); it != this->users.end(); it++)
    {
        if (it->second.getName() == "root") {
            continue;
        }
        users.push_back(it->second);
    }

    return users;
}

} /* namespace app */
