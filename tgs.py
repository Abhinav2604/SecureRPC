import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import datetime; 
import socket
import os
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

# Decrypting TGT (message B)
def decrypt_tgt(message,key):
    message = dn(message)
    data = string_json(message)
    nonce = en(data['nonce'])
    tag = en(data['tag'])
    ciphertext = en(data['data'])
    key = key
    try:
        cipher = AES.new(key, AES.MODE_EAX, nonce=b64decode(nonce))
        # decrypt and verify message using tgs secret key
        plain = cipher.decrypt_and_verify(
                            b64decode(ciphertext),b64decode(tag))
        plain = dne(plain)
        plain = string_json(plain)
        plain = string_json(plain)
        # retrieveing the data
        session_key = plain['key']
        ts = plain['validity_period']
        client = plain['client_id']
        host = plain['host']
        port = plain['port']
        return b64decode(en(session_key)),client,host,port,ts
    except (ValueError, KeyError) as e:
        pass
    return None,None,None,None,None

# decrypting authenticator
def decrypt_authenticator(message_d,key):
    data = message_d
    nonce = en(data['nonce'])
    tag = en(data['tag'])
    ciphertext = en(data['cipher'])
    key = key
    try:
        cipher = AES.new(key, AES.MODE_EAX, nonce=b64decode(nonce))
         # decrypt and verify message using tgs secret key
        data = cipher.decrypt_and_verify(
                            b64decode(ciphertext),b64decode(tag))
        data = dne(data)
        data = string_json(data)
        return data['client_id'], data['timestamp']
    except (ValueError, KeyError) as e:
        pass
    return None,None

# searching for credentials of the service
def find_credentials(user_id):
    for root, dir, files in os.walk(PATH):
      if user_id in files:
          file = open(user_id, 'r') 
        #   reading file line by line
          line = file.readline()
        # stripping line of any spaces and tabs
          password = line.strip()
          line = file.readline()
          salt = line.strip()
        # converting string to byte and using base 64 encoding
          salt = b64decode(en(salt))
          line = file.readline()
          host = line.strip()
          line = file.readline()
          port = line.strip()
        # genrating the secret key corresponding to password and salt
          key = create_key(password,salt)
          return key,host,port
    return None,None,None

# encrypting authenticator for server using server secret key
def encrypt_service_auth(service_id,message_json):
    # finding the key associated with the service ID
    key,host,port = find_credentials(service_id+'.txt')
    if key is None:
        return
    
    message_d = json_string(message_json)
    message_d = en(message_d)
    cipher = AES.new(en(key), AES.MODE_EAX)
    # encrypting the message using server secret key
    ciphertext, tag = cipher.encrypt_and_digest(message_d)
    nonce = cipher.nonce
    ciphertext = dn(ciphertext)
    tag = dn(tag)
    nonce = dn(nonce)

    data_json = {'cipher':ciphertext,'tag':tag,'nonce':nonce}
    data_string = json_string(data_json)
    data_bytes = en(data_string)
    return data_bytes

# encrypting server session key using TGS session key
def encrypt_key(session_key,key):

    cipher = AES.new(en(key), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(en(session_key))
    nonce = cipher.nonce
    nonce = en(nonce)
    tag = en(tag)
    ciphertext = en(ciphertext)
    data_json = {'key':dn(ciphertext),'tag':dn(tag),'nonce':dn(nonce)}
    data_string = json_string(data_json)
    data_bytes = en(data_string)
    return data_bytes


def authenticate_client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((TGS_HOST, TGS_PORT))
    while 1:
        data, server = sock.recvfrom(4096)
        message_c = dne(data)
        data, server = sock.recvfrom(4096)
        message_d = dne(data)
        # create TGS secret key
        key = create_key("tgs@123")
        if 'message_b' not in string_json(message_c):
            message_c,message_d = message_d, message_c
        message = string_json(message_c)
        service_id = message['service_id']

        # retrieve client id and network info from TGT
        client_tgs_session_key, client_id, host, port,ts = decrypt_tgt(message['message_b'],key)

        if client_tgs_session_key is None:
            continue
        message_d = string_json(message_d)

        # retrieve client Id from message d(authenticator)
        client ,ts_client = decrypt_authenticator(message_d,client_tgs_session_key)

        if client is None:
            continue
        # verify if both IDs are same or not
        if(client==client_id and server[0]==host and server[1]==int(port)):
            # create a server session key
            session_key = dn(get_random_bytes(32))
            message_json = {'key':session_key,'client':client_id,'host':host,'port':port,'validity':ts}
            # encrypt message using server secret key
            message_e = encrypt_service_auth(service_id,message_json)

            message_e = en(message_e)
            sock.sendto(message_e,(host,int(port)))

            # encrypt server session key using client-tgs session key
            message_d = encrypt_key(session_key,client_tgs_session_key)
            message_d = en(message_d)
            sock.sendto(message_d,(host,int(port)))

if __name__ == '__main__':
    authenticate_client()

        