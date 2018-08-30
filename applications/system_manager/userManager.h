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

    void createUser(app::user &user);
    void changeUserPass(app::user &user);
public:
    virtual ~userManager();

    static userManager* getInstance();
    static const int MAX_USERS;

    bool is_username_existed(std::string user_name);
    bool is_email_existed(std::string email);

    app::rpcMessageUsersResultType addUser(app::user &user);
    app::rpcMessageUsersResultType editUser(app::user &user);
    bool                           deleteUser(app::user &user);

    void initFromFile();
    bool writeToFile();

    void getUsers(std::list< app::user> &users);
};

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_USERMANAGER_H_ */
