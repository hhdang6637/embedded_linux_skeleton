/*
 * ini.cpp
 *
 *  Created on: Aug 6, 2018
 *      Author: hhdang
 */


#include <iostream>     // std::cout
#include <fstream>      // std::ifstream

#include "ini.h"

namespace app
{

ini::ini()
{
    // TODO Auto-generated constructor stub

}

ini::~ini()
{
    this->destroy();
}

bool ini::loadFromFile(const char* filename)
{
    this->destroy();

    std::ifstream infile(filename);

    if (infile.is_open() == false) {
        return false;
    }

    // TODO

    infile.close();

    return true;
}

} /* namespace app */
