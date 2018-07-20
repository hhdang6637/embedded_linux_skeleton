/*
 * simplewebfactory.cpp
 *
 *  Created on: Jul 20, 2018
 *      Author: hhdang
 */

#include <string.h>

#include <iostream>
#include <vector>
#include <algorithm>

#include "simplewebfactory.h"

simpleWebFactory *simpleWebFactory::s_instance = 0;

simpleWebFactory::simpleWebFactory()
{
    extern unsigned char _binary_header_html_start[];
    extern unsigned char _binary_header_html_end[];

    char * header_buffer = new char [(_binary_header_html_end - _binary_header_html_start) + 1];
    memcpy(header_buffer, _binary_header_html_start, (_binary_header_html_end - _binary_header_html_start));
    header_buffer[(_binary_header_html_end - _binary_header_html_start)] = '\0';

    this->html_header_str = header_buffer;

    delete []header_buffer;

    extern unsigned char _binary_footer_html_start[];
    extern unsigned char _binary_footer_html_end[];

    char * footer_buffer = new char [(_binary_footer_html_end - _binary_footer_html_start) + 1];
    memcpy(footer_buffer, _binary_footer_html_start, (_binary_footer_html_end - _binary_footer_html_start));
    footer_buffer[(_binary_footer_html_end - _binary_footer_html_start)] = '\0';

    this->html_footer_str = footer_buffer;

    delete []footer_buffer;

    extern unsigned char _binary_navbar_html_start[];
    extern unsigned char _binary_navbar_html_end[];

    char * navbar_buffer = new char [(_binary_navbar_html_end - _binary_navbar_html_start) + 1];
    memcpy(navbar_buffer, _binary_navbar_html_start, (_binary_navbar_html_end - _binary_navbar_html_start));
    navbar_buffer[(_binary_navbar_html_end - _binary_navbar_html_start)] = '\0';

    this->html_navbar_str = navbar_buffer;

    delete []navbar_buffer;

}

simpleWebFactory::~simpleWebFactory()
{

}

simpleWebFactory* simpleWebFactory::getInstance()
{
    if (s_instance == 0) {
        s_instance = new simpleWebFactory();
    }

    return s_instance;
}

const char* simpleWebFactory::get_html_header_str()
{
    return this->html_header_str.c_str();
}

const char* simpleWebFactory::get_html_footer_str()
{
    return this->html_footer_str.c_str();
}
const char* simpleWebFactory::get_html_navbar_str()
{
    return this->html_navbar_str.c_str();
}
