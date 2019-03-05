#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include <list>
#include <vector>

#include "MQTTClient.h"
#include "opencv2/core/core.hpp" // for uchar

#define ADDRESS     "tcp://192.168.81.31:1883"
#define CLIENTID    "rtsp2jpg"
#define PAYLOAD     "Hello World!"
#define QOS         0
#define TIMEOUT     10000L

static MQTTClient client;
static MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
static MQTTClient_message pubmsg = MQTTClient_message_initializer;

volatile MQTTClient_deliveryToken deliveredtoken;

void delivered(void *context, MQTTClient_deliveryToken dt)
{
    printf("Message with token value %d delivery confirmed\n", dt);
    deliveredtoken = dt;
}
int msgarrvd(void *context, char *topicName, int topicLen, MQTTClient_message *message)
{
    int i;
    char* payloadptr;
    printf("Message arrived\n");
    printf("     topic: %s\n", topicName);
    printf("   message: ");
    payloadptr = (char*)message->payload;
    for(i=0; i<message->payloadlen; i++)
    {
        putchar(*payloadptr++);
    }
    putchar('\n');
    MQTTClient_freeMessage(&message);
    MQTTClient_free(topicName);
    return 1;
}

static void connlost(void *context, char *cause)
{
    int rc;

    printf("\nConnection lost\n");
    printf("     cause: %s\n", cause);

    if (!MQTTClient_isConnected(client)) {

        conn_opts.keepAliveInterval = 30;
        conn_opts.cleansession = 1;

        MQTTClient_setCallbacks(client, NULL, connlost, NULL, delivered);

        if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
            printf("Failed to connect, return code %d\n", rc);
            exit(EXIT_FAILURE);
        }
    }
}

void mqtt_init() {
    int rc;

    if (client == NULL) {
        MQTTClient_create(&client, ADDRESS, CLIENTID,
            MQTTCLIENT_PERSISTENCE_NONE, NULL);
    }

    if (!MQTTClient_isConnected(client)) {

        conn_opts.keepAliveInterval = 30;
        conn_opts.cleansession = 1;

        MQTTClient_setCallbacks(client, NULL, connlost, NULL, delivered);

        if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
            printf("Failed to connect, return code %d\n", rc);
            exit(EXIT_FAILURE);
        }
    }
    
}

void mqtt_destroy() {
    MQTTClient_disconnect(client, 10000);
    MQTTClient_destroy(&client);
}

void mqtt_publish_topic(const char *topic, unsigned char *buff, size_t size) {
    MQTTClient_deliveryToken token;

    pubmsg.payload = (void*)buff;
    pubmsg.payloadlen = size;

    pubmsg.qos = QOS;
    pubmsg.retained = 0;
    deliveredtoken = 0;

    MQTTClient_publishMessage(client, topic, &pubmsg, &token);

}

void MQTTClient_loop() {
    int rc;

    rc = MQTTClient_subscribe(client, "camera_ip_stream_jpg", 0);
    if (rc != MQTTCLIENT_SUCCESS) {
        printf("%s:%d rc was %d\n", __FUNCTION__, __LINE__, rc);
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    while (true) {
        char* topicName = NULL;
        int topicLen;
        MQTTClient_message* message = NULL;

        rc = MQTTClient_receive(client, &topicName, &topicLen, &message, 1000);
        if (message) {

            printf("%s\t", topicName);
            printf("%.*s\n", message->payloadlen, (char*)message->payload);

            fflush(stdout);
            MQTTClient_freeMessage(&message);
            MQTTClient_free(topicName);
        }

        if (rc != 0) {
            if ((rc = MQTTClient_connect(client, &conn_opts)) != MQTTCLIENT_SUCCESS) {
                printf("Failed to connect, return code %d\n", rc);
                exit(EXIT_FAILURE);
            }
        }
    }
}
