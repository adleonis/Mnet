#!/usr/bin/env

############# M Network Client ORM ##############
# This code generates DB entries, keys, peers, ##
# and anything else needed for wallet purposes. #
# ######                     ####################
#################################################

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC

import base64
import json
import time

import sqlite3

DB = "MClientWallet001"

### - Connect to Sqlite - ###
def connect_sql(DB):
    conn = sqlite3.connect(DB)
    #DB used to hold accounts (pub & private keys) for testing
    return conn

def sign_t(key, transaction_object):
    #Method signs a transaction
    h = SHA256.new(str(transaction_object).encode())
    #h = SHA256.new(json.dumps(transaction).encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

def create_key(algo,algotype):
    #algo is type <str> can be "RSA" or "ECC"
    #algotype is type <str> could be "P-256" for ECC algo, or "2048" for RSA algo
    #returns 2 encodings of the same generated keys
    if algo == "RSA":
        key = RSA.generate(int(algotype))
        private_key_der = key.export_key(format='DER')
        private_key_pem = key.export_key(format='PEM')
        public_key_PEM = key.publickey().export_key(format='PEM')
        public_key_DER = key.publickey().export_key(format='DER')
    elif algo == "ECC":
        key = ECC.generate(curve=algotype)
        private_key_der = key.export_key(format='DER')
        private_key_pem = key.export_key(format='PEM')
        public_key = ECC.import_key(private_key_der).public_key()
        public_key_PEM = public_key.export_key(format='PEM')
        public_key_DER = public_key.export_key(format='DER')
    else:
        print("This crypto is not implemented, try 'RSA' or 'ECC' ")
        return False
    return {'pubkDER':public_key_DER,'pkeyDER':private_key_der,
            'pubkPEM':public_key_PEM,'pkeyPEM':private_key_pem, 
            'algo':algo,'algotype':algotype}

def create_local():
    database = DB
 
    sql_create_keys = """ CREATE TABLE IF NOT EXISTS keys (
                                        id integer PRIMARY KEY,
                                        pubkey text NOT NULL,
                                        pkey text NOT NULL,
                                        algo text NOT NULL,
                                        algotype text NOT NULL,
                                        encoding text NOT NULL,
                                        Mdns text
                                    ); """
 
    sql_create_nodes = """CREATE TABLE IF NOT EXISTS nodes (
                                    id integer PRIMARY KEY,
                                    ipv4 text,
                                    ipv6 text,
                                    Mdns text,
                                    port integer,
                                    codename text,
                                    codehash text,
                                    pubKey text
                                );"""
 
    # create a database connection
    conn = connect_sql(database)
    if conn is not None:
        # create tables
        c = conn.cursor()
        c.execute(sql_create_keys)
        c.execute(sql_create_nodes)
        print("Tables Created Successfully!")
    else:
        print("Error! cannot create the database connection.")


def fill_keys_table(howmany):
    #in SQLite DB
    conn = connect_sql("localkeys")
    c = conn.cursor()
    for i in range(howmany):
        key =  create_key("ECC","P-256")
        c.execute(''' INSERT INTO keys(pubkey,pkey,algo,algotype,encoding,Mdns) VALUES(?,?,?,?,?,?) ''',[key["pubkDER"],
                                            key['pkeyDER'],
                                            key['algo'],
                                            key['algotype'],
                                            "DER",
                                            "account "+ str(i)]) 
    conn.commit()    
    print("Added new keys in keys DB")


def local_creds(id):
    #retrieves credentials from local Sqlite3 Keys DB
    conn = connect_sql("localkeys")
    c = conn.cursor()
    creds = c.execute(''' SELECT * FROM keys WHERE (id=?) ''',id).fetchall()
    cred_dict = {"pubkDER":creds[0][1],
                "pkeyDER":creds[0][2],
                "algo":creds[0][3],
                "algotype":creds[0][4]}    
    return cred_dict

if __name__ == "__main__":

    #print(create_key("RSA", "2048"))
    #print(create_key("ECC", "P-256"))
    
    create_local()
    fill_keys_table(10)
    print(local_creds("1"))

