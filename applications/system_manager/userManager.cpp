/*
 * userManager.cpp
 *
 *  Created on: Aug 7, 2018
 *      Author: hhdang
 */

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

} /* namespace app */
