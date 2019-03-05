#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <list>

#include "opencv2/core/core.hpp"
#include "opencv2/gpu/gpu.hpp"
#include "opencv2/highgui/highgui.hpp"
#include "opencv2/contrib/contrib.hpp"

#include "cloud_cam.h"

extern void scan_camera_rtsp(const char* subnet, std::list<host_info> &list_found_ips);
extern void find_list_accesable_camera(std::list<host_info> &list_found_ips, std::list<host_info> &list_accesable_camera);

static void send_rstp_to_jpg_buff(host_info &host);

extern void mqtt_init();
extern void MQTTClient_loop();
extern void mqtt_publish_topic(const char *topic, unsigned char *buff, size_t size);

#define JPG_STREAM "jpg_stream"

std::list<host_info> list_found_ips;
std::list<host_info> list_accesable_camera;

int main(int argc, char const *argv[])
{
    std::string subnet = argv[1];

    scan_camera_rtsp(subnet.c_str(), list_found_ips);
    find_list_accesable_camera(list_found_ips, list_accesable_camera);

    mqtt_init();

    MQTTClient_loop();

    return 0;
}

void send_rstp_to_jpg_buff(host_info &host) {
    char buff[64];

    snprintf(buff, sizeof(buff), "rtsp://%hhu.%hhu.%hhu.%hhu/",
        host.ips[0], host.ips[1], host.ips[2],
        host.ips[3]);

    cv::VideoCapture reader(buff);
    cv::Mat image;

    int n = 0;

    printf("collecting frame from %s\n", buff);

    if (reader.isOpened()) {
        while(1) {
            if (reader.read(image)) {

                n++;

                printf("\rread frame #%05d\t", n);
                std::vector<uchar> buff;

                if (cv::imencode(".jpg", image, buff)) {
                    // hangs
                    // Mat im2 = imdecode(buff,CV_LOAD_IMAGE_ANYDEPTH);
                    printf("buff size is %d\t", buff.size());
                    fflush(stdout);
                    mqtt_publish_topic(JPG_STREAM, &buff[0], buff.size());
                }

            } else {
                fprintf(stderr,"cannot read frame #%d\n", n);
                break;
            }
        }

        reader.release();
    }
}
