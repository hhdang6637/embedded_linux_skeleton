/*
 * userManager.h
 *
 *  Created on: Aug 7, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_SYSTEM_MANAGER_USERMANAGER_H_
#define APPLICATIONS_SYSTEM_MANAGER_USERMANAGER_H_

#include <string>
#include <map>

#include "ini.h"
#include "user.h"
#include "rpcMessageUsers.h"

namespace app
{

class userManager
{
private:
    userManager();
    static userManager* s_instance;

    std::map<std::string, app::user> users;

    void initDefaultUsers();

    void createUser(const app::user &user);
    void removeUser(const app::user &user);
    void changeUserPass(const app::user &user);
public:
    virtual ~userManager();

    static userManager* getInstance();
    static const int MAX_USERS;

    bool usernameExisted(const std::string &user_name);
    bool emailExisted(const std::string &email);

    app::rpcMessageUsersResultType addUser(const app::user &user);
    app::rpcMessageUsersResultType editUser(app::user &user, bool changPasswd);
    app::rpcMessageUsersResultType deleteUser(const app::user &user);

    void initFromFile();
    bool writeToFile();

    std::list< app::user> getUsers();
};

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_USERMANAGER_H_ */
