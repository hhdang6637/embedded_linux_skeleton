/*
 * serviceDhcpC.h
 *
 *  Created on: Jul 27, 2018
 *      Author: hhdang
 */

#ifndef __APPLICATIONS_CLOUD_CAM_H__
#define __APPLICATIONS_CLOUD_CAM_H__

typedef struct
{
    char macs[6];
    char mac_vendor[64];
} mac_addr;

typedef struct
{
    unsigned char ips[4];
    mac_addr      mac;
} host_info;

#endif