#ifndef _OPENVPN_JS_H_
#define _OPENVPN_JS_H_

#include <fcgiapp.h>

std::string json_handle_openvpn_cfg(FCGX_Request *request);
std::string json_handle_openvpn_cert(FCGX_Request *request);

#endif /* _OPENVPN_JS_H_ */