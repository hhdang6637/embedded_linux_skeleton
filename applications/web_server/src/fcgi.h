/*
 * fcgi.h
 *
 *  Created on: Jul 21, 2018
 *      Author: hhdang
 */

#ifndef _FCGI_H_
#define _FCGI_H_

#include <fcgiapp.h>

void fcgi_start();

unsigned int fcgi_form_varable_str(FCGX_Request *request, const char *name, char *buff, unsigned int len);

bool get_post_data(FCGX_Request *request, std::string &data);

#endif /* _FCGI_H_ */
