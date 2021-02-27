from datetime import time
import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import datetime
import platform
import sys
import os
import socket
from shutil import copyfile
from socket import SHUT_RDWR
AU_HOST = '127.0.0.1'
AU_PORT = 3500
TGS_HOST = '127.0.0.1'
TGS_PORT = 3600
PATH = os.getcwd()

SALT_TGS = b'\x8a\xfe\x1f\xa7aY}\xa3It=\xc3\xccT\xc8\x94\xc11%w]A\xb7\x87G\xd8\xba\x9e\xf8\xec&\xf0'

# Create key using Salt and Password
def create_key(password,SALT=SALT_TGS):
    key = PBKDF2(password, SALT, dkLen=32)
    return key

# encoding message in utf-8
def en(message):
    try:
        message = message.encode('utf-8')
        return message
    except (UnicodeEncodeError, AttributeError):
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
    except (UnicodeDecodeError, AttributeError) as e:
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
    except (ValueError,TypeError):
        data = message
    return data

# decrypt client information using server secret key
def decrypt_message(message,key): 
    message = string_json(message)
    nonce = message['nonce']
    tag = message['tag']
    data = message['cipher']
    try:
        cipher = AES.new(key, AES.MODE_EAX, nonce=b64decode(en(nonce)))
        # decrypt and verify using the server secret key
        message = cipher.decrypt_and_verify(b64decode(en(data)),b64decode(en(tag)))
        message = dne(message)
        message = string_json(message)
        return message['client'], message['host'], message['port'],message['validity'],message['key']
    except (ValueError, KeyError):
        return None,None,None,None,None

# decrypt authenticator using session key
def decrypt_authenticator(message,key):
    message = string_json(message)
    nonce = message['nonce']
    tag = message['tag']
    data = message['cipher']
    try:
        cipher = AES.new(b64decode(en(key)), AES.MODE_EAX, nonce=b64decode(en(nonce)))
        # decrypt and verify using session key
        message = cipher.decrypt_and_verify(b64decode(en(data)),b64decode(en(tag)))
        message = dne(message)
        message = string_json(message)
        return message['client_id'], message['timestamp']
    except (ValueError, KeyError):
        return None,None

# encrypt rpc using session key
def encrypt_rpc(message,key):
    cipher = AES.new(key, AES.MODE_EAX)
    # encrypt the data
    ciphertext, tag = cipher.encrypt_and_digest(en(message))
    nonce = cipher.nonce
    rpc = {'rpc':dn(ciphertext), 'tag':dn(tag), 'nonce':dn(nonce)}
    rpc = json_string(rpc)
    rpc = en(rpc)
    return rpc

# decrypt rpc using session key
def decrypt_rpc(message, key):
    message = string_json(message)
    rpc = en(message['rpc'])
    nonce = en(message['nonce'])
    tag = en(message['tag'])
    try:
        cipher = AES.new(key, AES.MODE_EAX, nonce=b64decode(nonce))
        #decrypt the data
        data = cipher.decrypt_and_verify(b64decode(rpc),b64decode(tag))
        data = dne(data)
        return data
    except (ValueError, KeyError):
        print("Incorrect decryption")

def encrypt_auth(timestamp,session_key):
    cipher = AES.new(b64decode(en(session_key)), AES.MODE_EAX)
    # encrypt timestamp for verification
    ciphertext, tag = cipher.encrypt_and_digest(en(str(timestamp)))
    nonce = cipher.nonce
    data_json = {'cipher':dn(ciphertext),'tag':dn(tag),'nonce':dn(nonce)}
    data_string = json_string(data_json)
    data_bytes = en(data_string)
    print(data_bytes)
    return data_bytes

def grant_access(password,salt):
    # create udp socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # set option for reuse
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # bind socket
    sock.bind((HOST, PORT))
    while 1 :
        message_e, addr = sock.recvfrom(4096)
        message_f, addr = sock.recvfrom(4096)
        # create key using password and salt
        key = create_key(password,salt)

        # retrieve the message from TGS using secret key
        client_d,host,port,ts,session_key = decrypt_message(dne(message_e),key)
        if client_d is None:
            break

        # retrieve the message using session key
        client_id, timestamp = decrypt_authenticator(dne(message_f),session_key)
        if client_id is None:
            break

        # verify that the both client is authorised by TGS
        if client_d==client_id and addr[0]==host and addr[1]==int(port) and int(ts)>int(timestamp):
            message_h = encrypt_auth(timestamp,session_key)
            sock.sendto(en(message_h),(host,int(port)))
            sock.close()
            return b64decode(en(session_key))
        sock.close()
    return None

# retives the dictionary of all the folders mapped to the allowed ports
def get_folders():
    file = open('ports.txt','r')
    # read file line by line
    line = file.readline()
    line = line.strip()
    # convert string to dictionary
    folders = string_json(line)
    print(folders)
    return folders

# retrives the salts of given id
def get_salt(user_id):
    # as we are inside the server folder we need to move outside
    path = os.path.join('..','service.txt')

    # open file
    file = open(path,'r')
    val = file.readline()
    val = val.strip()
    # convert string to dictionary
    val = string_json(val)
    salt = val[user_id]
    salt = b64decode(en(salt))

    print(salt)
    return salt



def send_SRPC_response(s, data,key):
    send_data = encrypt_rpc(data,key)
    s.send(send_data)
    return

# present working directory
def pwd(*args):
    # if platform is windows
    if 'Windows'==platform.system():
        data = os.getcwd().split("\\")[-1]
    # if platform is Linux or Mac
    else :
        data = os.getcwd().split("/")[-1]
    return data

# list elements
def ls(*args):
    ls_list = sorted(os.listdir())
    data = ""
    for x in ls_list:
        data = data + x + "\t"
    return data

# copy File
def cp(file_names):
    file_name = file_names[0]
    output_file_name = file_names[1]
    try:
        copyfile(file_name, output_file_name)
        data = "Copy success: " + output_file_name + " created."
    except Exception as err:
        data = str(err)
    return data

# display File
def cat(file_name):
    try:
        f = open(file_name[0], 'r')
        data = f.read()
        f.close()
    except Exception as err:
        data = str(err)
    return data


Commands = {"pwd": pwd, "ls": ls, "cp": cp, "cat": cat}

def main():
    global PORT
    PORT = int(sys.argv[1])
    global HOST
    HOST = '127.0.0.1'
    FS_Ports = get_folders()
    if str(PORT) not in FS_Ports:
        print("Wrong Credentials\n")
        return
    # set the current directory
    os.chdir(FS_Ports[str(PORT)])
    # retieve the salt
    salt = get_salt(FS_Ports[str(PORT)])

    PASSWORD = input("Enter Password: ")
    # generate the key using the salt and password
    key = grant_access(PASSWORD,salt)

    # in case we get the wrong password close the program
    if key is None:
        return None

    try:
        # create TCP sockets
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # set reuse option
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print("Socket ok!")
    except socket.error as err:
        print ("socket creation failed -- Exiting")
        s.close()
        exit(0)

    try:
        # bind the socket
        s.bind(('', PORT))
        print("Bind Ok!")
    except socket.error as err:
        print ("%s\nSocket binding failed -- Exiting" %err)
        s.close()
        exit(0)

    request = {"cmd" : None, "data": None}

    # set the socket to listening state
    s.listen(1)
    print("Listening..")

    # accept connection
    c, addr = s.accept()
    print("Connected to", addr)

    while(True):
        try:
            # enter blocking mode
            # block beyond 1 connection

            # receive and decode
            x = c.recv(1024)
            x = decrypt_rpc(dne(x),key)


            # extract data
            message = x.split()

            print("Received RPC: ", message[0])

            request["cmd"] = message[0]
            request["data"] = message[1:]

            if message[0] == "esc" :

                data = 'disconnected'
                print("Sending Response to RPC: ", data)
                send_SRPC_response(c, data,key)

                print("RPC Response Sent")

                # close the connection
                c.close()
                # close the socket
                s.close()
                print("Socket Closed")
                # get the session key again
                key = grant_access(PASSWORD,salt)
                print('Key Found\n')



                try:
                    # create socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    #  set reuse option
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    print("Socket ok!")
                except socket.error as err:
                    print ("socket creation failed -- Exiting")
                    s.close()
                    exit(0)

                try:
                    # bind socket
                    s.bind(('', PORT))
                    print("Bind Ok!")
                except socket.error as err:
                    print ("%s\nSocket binding failed -- Exiting" %err)
                    s.close()
                    exit(0)
                
                # set to listen state
                s.listen(1)
                print("Listening again..")

                # accept connection
                c, addr = s.accept()
                print("Connected to", addr)
                continue

            # execute the RPC
            data = Commands[request["cmd"]](request["data"])

            print("Sending Response to RPC: ", data)

            # send rpc response
            send_SRPC_response(c, data,key)

            # Close the connection with the client
            # c.close()

        except Exception as e:

            print("ERROR: ", sys.exc_info()[0],"\n" ,e)
            c.close()
            s.close()
            exit(0)
    c.close()
    s.close()

if __name__ == "__main__":
    main()

