/*
 * userManager.cpp
 *
 *  Created on: Aug 7, 2018
 *      Author: hhdang
 */
#include <iostream>
#include <syslog.h>
#include <list>

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
    this->userConf.destroy();

    app::user root;
    root.setName("root");
    root.setPassword("root");

    // we don't need store root user into config file
    this->users.insert(std::pair<std::string, app::user>(root.getName(), root));

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
}

void userManager::createUser(app::user &user)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "adduser "
            "-h /home " // set home dir
            "-s /bin/sh "
            "-H "// Don't create home dir
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

bool userManager::initFromFile()
{
    initDefaultUsers();

    if (this->userConf.loadFromFile("/data/users.conf")) {

        for(int i = 0; i < 50; i++) {

            char sect[32];
            std::string value;

            snprintf(sect, sizeof(sect), "user_%d", i);
            if (this->userConf.get_string(sect, "name", value)) {

                syslog(LOG_NOTICE, "found user %s from /data/users.conf", value.c_str());

                app::user user;
                user.setName(value.c_str());

                if (this->userConf.get_string(sect, "password", value)) {
                    user.setPassword(value.c_str());
                }

                if (user.isValid()) {

                    auto it = this->users.find(user.getName());

                    if (it == this->users.end()) {

                        this->users.insert(std::pair<std::string, app::user>(user.getName(), user));
                        this->createUser(user);

                    } else {
                        it->second = user;
                    }

                    this->changeUserPass(user);

                    syslog(LOG_NOTICE, "add user %s to the user list", user.getName().c_str());
                }
            }
        }

        return true;
    } else {
        syslog(LOG_NOTICE, "cannot load user config from /data/users.conf");
    }

    return false;
}

bool userManager::writeToFile()
{
    return this->userConf.writeToFile("/data/users.conf");
}

std::list<app::user> userManager::getUsers()
{
    std::list<app::user> list_users;
    for (auto it = this->users.begin(); it != this->users.end(); it++)
    {
        list_users.push_back(it->second);
    }

    return list_users;
}

} /* namespace app */
