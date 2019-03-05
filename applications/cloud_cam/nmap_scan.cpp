#include <stdio.h>
#include <list>

#include "opencv2/core/core.hpp"
#include "opencv2/gpu/gpu.hpp"
#include "opencv2/highgui/highgui.hpp"
#include "opencv2/contrib/contrib.hpp"

#include "cloud_cam.h"

void scan_camera_rtsp(const char* subnet, std::list<host_info> &list_found_ips) {
    char nmap_cmd[256];
    char buff[512];
    FILE* nmap_out_stream;
    host_info host;

    memset(&host, 0, sizeof(host));

    list_found_ips.clear();

    snprintf(nmap_cmd, 256, "nmap -n -T5 %s -p T:554 --open -oN -", subnet);
    nmap_out_stream = popen(nmap_cmd, "r");

    if (nmap_out_stream) {
        while (fgets(buff, sizeof(buff), nmap_out_stream) != NULL) {
            unsigned char ips[4];
            char macs[6];
            char mac_vendor[64];

            if (sscanf (buff,"Nmap scan report for %hhu.%hhu.%hhu.%hhu",
                    &ips[0], &ips[1], &ips[2],
                    &ips[3]) == 4) {

                if (host.ips[0] != 0) {
                    // store the old host info
                    list_found_ips.push_back(host);
                }

                memset(&host, 0, sizeof(host));
                memcpy(host.ips, ips, 4);
            } else if (sscanf (buff,"MAC Address: %hhx:%hhx:%hhx:%hhx:%hhx:%hhx %[^\t\n]",
                     &macs[0], &macs[1], &macs[2], &macs[3], &macs[4], &macs[5], mac_vendor) == 7) {
                memcpy(host.mac.macs, macs, 6);
                memcpy(host.mac.mac_vendor, mac_vendor, 64);
            }
        }

        if (host.ips[0] != 0) {
            // store the old host info
            list_found_ips.push_back(host);
        }

        pclose(nmap_out_stream);

    }
}

void find_list_accesable_camera(std::list<host_info> &list_found_ips, std::list<host_info> &list_accesable_camera) {
    char buff[256];

    list_accesable_camera.clear();

    for (std::list<host_info>::iterator i = list_found_ips.begin(); i != list_found_ips.end(); ++i) {

        snprintf(buff, sizeof(buff), "%hhu.%hhu.%hhu.%hhu",
            i->ips[0], i->ips[1], i->ips[2],
            i->ips[3]);

        printf("checking %s ", buff);

        snprintf(buff, sizeof(buff), "rtsp://%hhu.%hhu.%hhu.%hhu/",
            i->ips[0], i->ips[1], i->ips[2],
            i->ips[3]);

        cv::VideoCapture reader(buff);
        if (reader.isOpened()) {
            printf("is OK");
            list_accesable_camera.push_back(*i);
        }
        printf("\n");
    }

    printf("\n===================================================\n\n");

    for (std::list<host_info>::iterator i = list_accesable_camera.begin(); i != list_accesable_camera.end(); ++i) {
        printf("rtsp://%hhu.%hhu.%hhu.%hhu/\n",
            i->ips[0], i->ips[1], i->ips[2],
            i->ips[3]);
    }

    printf("\n===================================================\n\n");

}
