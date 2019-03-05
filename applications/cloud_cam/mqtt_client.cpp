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

MQTTClient client;
MQTTClient_message pubmsg = MQTTClient_message_initializer;
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
    printf("\nConnection lost\n");
    printf("     cause: %s\n", cause);
}

void MQTTClient_publish_jpg_buff(const char *topic, std::vector<uchar> &buff) {
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_deliveryToken token;
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

#if 0
    pubmsg.payload = (void*)PAYLOAD;
    pubmsg.payloadlen = strlen(PAYLOAD);
#else
    pubmsg.payload = &buff[0];
    pubmsg.payloadlen = buff.size();
#endif
    pubmsg.qos = QOS;
    pubmsg.retained = 0;
    deliveredtoken = 0;

    MQTTClient_publishMessage(client, topic, &pubmsg, &token);
#if 0
    printf("Waiting for publication of %s\n"
            "on topic %s for client with ClientID: %s\n",
            PAYLOAD, TOPIC, CLIENTID);

    while(deliveredtoken != token) usleep(1000);
#endif

    // MQTTClient_disconnect(client, 10000);
    // MQTTClient_destroy(&client);
}
