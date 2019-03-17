import time
import paho.mqtt.client as paho
import hashlib
import base64

def convertImageToBase64(filename):
    with open(filename, "rb") as image_file:
        encoded = base64.b64encode(image_file.read())
    return encoded

import cv2
vcap = cv2.VideoCapture("rtsp://127.0.0.1:9554/")

import paho.mqtt.client as mqtt
import pickle
import time
import numpy


broker_address="192.168.81.31"
client = mqtt.Client("P1")                                # Start MQTT Client
client.connect("192.168.81.31", 1883, 60)                 # Connect to server

client.loop_start()                                       # initial start before loop
i = 0
while True:
    i = i + 1
    print("publishing it to the MQ queue frame #", i)
    # client.publish(topic="camera/pics/jpg2base64", payload=convertImageToBase64("image_test.jpg"), qos=0)  # publish it to the MQ queue
    ret, frame = vcap.read()
    # frame_data = pickle.dumps(frame) ### new code
    ret, jpeg = cv2.imencode('.jpg', frame)

    client.publish(topic="camera/pics/jpg2base64", payload=jpeg.tostring(), qos=0)  # publish it to the MQ queue

    # nparr = numpy.fromstring(jpeg.tostring(), numpy.uint8)
    # cv2.imshow('image', cv2.imdecode(nparr, cv2.IMREAD_COLOR))
    # cv2.waitKey(1)
    # time.sleep(0.05)                                                       # wait for next image
