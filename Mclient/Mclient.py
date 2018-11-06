#!/usr/bin/env

#######################  M Network Client  ########################
import sock_serv
import socket
import time
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
import base64

name = "clientA"

def create_address():
    #Uses crypto libraries to generate new address
    secret_code = "SomethingRandom"
    key = RSA.generate(2048)
    #change PEM to DER?? at socketlevel of always?
    encrypted_key = key.export_key(format='PEM',passphrase=secret_code, pkcs=8,protection="scryptAndAES128-CBC")
    file_out = open("rsa_key.bin", "wb")
    file_out.write(encrypted_key)
    print(key.publickey().export_key(format='PEM'))

def get_key(passphrase):
    encoded_key = open("rsa_key.bin", "rb").read()
    key = RSA.import_key(encoded_key, passphrase=passphrase)
    return key

def connect_client(provider, account_address):
    #this method connect the client and checks node account data against local DB
    pass

def sign_t(key, transaction):
    #Method signs a transaction
    h = SHA256.new(transaction.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

def listen():
    data = sock_serv.launch_server("127.0.0.1", 65432)
    return data

def create_message(transaction, signature):
    #wraps up message info
    signature = base64.b64decode(signature, '-_')
    #signature = signature.decode('base64')
    print("--- decoded sig --- \n", signature)
    message = {"transaction":transaction,"signature":signature}
    return json.dumps(message)

def send(message):
    HOST = '127.0.0.1'
    PORT = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        s.sendall(message.encode())

def create_t(amount, to):
    #Method to create a transaction order
    
    #both below should be done on server(node) executing the T, not on client
    #1. Discovery, make sure the TO address axists
    #2. amount, make sure is less than available
    
    t = json.dumps({"pubKey":{"amount": amount, "to": to}})
    return t


if __name__ == "__main__":
    print("---- STARTING CLIENT ----")

    create_address()


    t = create_t(200, "00002")
    print("t: ",t)
    key = get_key("SomethingRandom")
    signature = sign_t(key, t)
    print("signature: ",signature)
    
    send(create_message(t, signature))
    #send(t)
    
    #time.sleep(3)
