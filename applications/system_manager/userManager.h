/*
 * userManager.h
 *
 *  Created on: Aug 7, 2018
 *      Author: hhdang
 */

#ifndef APPLICATIONS_SYSTEM_MANAGER_USERMANAGER_H_
#define APPLICATIONS_SYSTEM_MANAGER_USERMANAGER_H_

namespace app
{

class userManager
{
private:
    userManager();
    static userManager* s_instance;

public:
    virtual ~userManager();

    static userManager* getInstance();
};

} /* namespace app */

#endif /* APPLICATIONS_SYSTEM_MANAGER_USERMANAGER_H_ */
