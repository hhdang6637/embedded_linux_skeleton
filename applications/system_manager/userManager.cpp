/*
 * userManager.cpp
 *
 *  Created on: Aug 7, 2018
 *      Author: hhdang
 */

#include <syslog.h>

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

bool userManager::initFromFile(const char*fileName)
{
    initDefaultUsers();

    return true;
}

} /* namespace app */
