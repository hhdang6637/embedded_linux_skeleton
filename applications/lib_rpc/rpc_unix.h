/*
 * rpc_unix.h
 *
 *  Created on: Jul 22, 2018
 *      Author: hhdang
 */

#ifndef _RPC_RPC_UNIX_H_
#define _RPC_RPC_UNIX_H_

int open_server_socket(const char*socket_path);
int connect_to_server(const char*socket_path);

#endif /* _RPC_RPC_UNIX_H_ */
