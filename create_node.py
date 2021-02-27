from datetime import time
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import datetime
import sys
import os
from shutil import copyfile
from socket import SHUT_RDWR
import socket

# encode message in UTF-8
def en(message):
    try:
        message = message.encode('utf-8')
    except (UnicodeEncodeError, AttributeError) as e:
        pass
    return message

# de-encoding message from utf-8 after encoding it with base-64 encoding
# used with Encryption function
def dn(message):
    try:
        message = b64encode(message).decode('utf-8')
        return message
    except (UnicodeDecodeError, AttributeError,TypeError) as e:
        return message

# de-encoding message from utf-8
# used with sockets
def dne(message):
    try:
        message = message.decode('utf-8')
        return message
    except (UnicodeDecodeError, AttributeError,TypeError) as e:
        return message

# creating dictionary from string
def string_json(message):
    try:
        data = json.loads(message)
    except (ValueError,TypeError):
        data = message
    return data

# creating string from dictionary
def json_string(message):
    try:
        data = json.dumps(message)
    except (ValueError,TypeError) as e:
        data = message
    return data

def create_client(user_id,password):
    # create or overwrite a file to save credentials
    file = open(user_id+".txt",'w')
    file.write(password+'\n')
    # genrate salt
    salt = get_random_bytes(32)
    file.write(dn(salt))
    file.close()

    # read the list of clients
    file = open('client.txt','r')
    line = file.readline()
    file.close()

    # update the list of client
    file = open('client.txt','w')
    line = line.strip()
    line = string_json(line)
    line[user_id] = dn(salt)
    line = json_string(line)
    file.write(line)
    file.close()


def create_service(user_id,password,host,port):
    # create or overwrite a file to save credentials
    file = open(user_id+".txt",'w')
    file.write(password+'\n')
    # genrate salt
    salt = get_random_bytes(32)
    file.write(dn(salt))
    file.write('\n')
    file.write(host+'\n')
    file.write(port+'\n')
    file.close()

    # read the list of server
    file = open('service.txt','r')
    line = file.readline()
    file.close()

    # update the list of server
    file = open('service.txt','w')
    line = line.strip()
    line = string_json(line)
    line[user_id] = dn(salt)
    line = json_string(line)
    file.write(line)
    file.close()

    # read server port mapping 
    file = open('folders.txt','r')
    line = file.readline()
    file.close()
    # update server port mapping
    file = open('folders.txt','w')
    line = line.strip()
    line = string_json(line)
    line[user_id] = int(port)
    line = json_string(line)
    file.write(line)
    file.close()

    # read port server mapping
    file = open('ports.txt','r')
    line = file.readline()
    file.close()
    # read port server mapping
    file = open('ports.txt','w')
    line = line.strip()
    line = string_json(line)
    line[int(port)] = user_id
    print(port)
    print(line)
    line = json_string(line)
    file.write(line)
    file.close()

# verify that the person is authorised to create clients and server
def verify():
    password = input("Enter password: ")
    if(password=='abcd'):
        return True
    return False

def register():
    # verify the user
    while 1 :
        val = verify()
        if(val):
            break
        print('Wrong password\n')
    print("User Verified\n")
    base_path = ""
    while 1 :
        # take input from user
        choice = input("Enter 1 for creating client\nEnter 2 for creating server\n")
        if(int(choice)==1):
            user_id = input("Enter User ID: ")
            password = input("Enter Password: ")
            # create client
            create_client(user_id,password)
            print("Done\n")
        elif(int(choice)==2):
            user_id = input("Enter User ID: ")
            password = input("Enter Password: ")
            host = input("Enter host: ")
            port = input("Enter Port: ")
            # create server
            create_service(user_id,password,host,port)
            # create path for server directory
            path = os.path.join(base_path,user_id)
            # create server directory
            os.mkdir(path)
            print("Done\n")
        else :
            break

if __name__ == '__main__':
    register()


            

            

