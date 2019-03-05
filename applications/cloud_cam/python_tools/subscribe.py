import paho.mqtt.client as mqtt
import base64
import cv2
import numpy

def convertImageToBase64(filename, b64encode_data):
    with open(filename, "wb") as image_file:
        image_file.write(base64.b64decode(b64encode_data))
    image_file.close()

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    print("Connected with result code "+str(rc))

    # Subscribing in on_connect() means that if we lose the connection and
    # reconnect then subscriptions will be renewed.
    client.subscribe("jpg_171.245.198.163", 0)

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    # convertImageToBase64("pic.jpg", msg.payload)
    print ("received file pic.ipg")
    nparr = numpy.fromstring(msg.payload, numpy.uint8)
    cv2.imshow('image', cv2.imdecode(nparr, cv2.IMREAD_COLOR))
    cv2.waitKey(1)

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect("192.168.81.31", 1883, 60)

# Blocking call that processes network traffic, dispatches callbacks and
# handles reconnecting.
# Other loop*() functions are available that give a threaded interface and a
# manual interface.
client.loop_forever()