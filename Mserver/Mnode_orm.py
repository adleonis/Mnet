#!/usr/bin/env

################ M Network Maker ################
# This code generates DB entries, keys, peers, 
# and anything else needed for testing purposes.
# ######   NOT FOR RELEASE   ####################
#################################################
import rethinkdb as r

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC

import base64
import json
import time

import sqlite3
import logging

DB = "Mnet002"
DB_local = "localkeys"

### - Connect to Rethink DB - ###
def connect_db():
    conn = r.connect("localhost", 28015)
    return conn

### - Connect to Sqlite - ###
def connect_sql(DB_local):
    conn = sqlite3.connect(DB_local)
    #DB used to hold accounts (pub & private keys) for testing
    return conn

def create_table(name, conn):
    res = r.db(DB).table_create(name).run(conn)

def insert(tablename, thing, conn):
    res = r.db(DB).table(tablename).insert(thing).run(conn)
    return res

def read(DB, tablename, accountaddress, conn):
    cursor = r.db(DB).table(tablename).filter({'address': accountaddress}).pluck('address','balance').run(conn)
    for document in cursor:
        return document


def execute_transaction(AccountUpdate, conn):
    iter = 0
    for account in AccountUpdate.ToState.AccountState:
        #print(address)
        address = account.AccountAddress
        newbalance = AccountUpdate.ToState.AccountState[iter].AccountBalance
        res1 = r.db(DB).table('accounts').filter({'address': address}).update({"balance": newbalance}).run(conn)
        iter +=1
        logging.info("ORM: **DB Update Successful: Local Update of Balance complete**")
    #DEFINITLY IMPLEMENT SOME HARD COMMIT OR ROLLBACK HERE!!!! can't fail one of the other, ever    



#OBSOLETE, USE Create_key BELOW***********************
def create_address():
    #Uses crypto libraries to generate new address
    secret_code = "SomethingRandom"
    key = RSA.generate(2048)
    #change PEM to DER?? at socketlevel of always?
    encrypted_key = key.export_key(format='PEM',passphrase=secret_code, pkcs=8,protection="scryptAndAES128-CBC")
    file_out = open("rsa_key.bin", "wb")
    file_out.write(encrypted_key)

    public_key = key.publickey().export_key(format='PEM')
    file_out2 = open("rsa_pubkey.bin", "wb")
    file_out2.write(public_key)
    return key.publickey().export_key(format='PEM')
#******************************************************

def make_key(localcredsID):
    encoded_key = local_creds(localcredsID)['pkeyDER']
    key = ECC.import_key(encoded_key)
    #print("Key: ",key)
    return key

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
    database = "localkeys"
 
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


def fill_peers_table(howmany):
    #in Rethink DB
    conn = connect_db()
    for i in range(howmany):
        thing = {"Ipv4":"127.0.0.1","Mdns":"localhost","Port":50051,"Address":local_creds(i+1)["pubkDER"]}
        insert("peers",thing, conn)
    print("Added new peers in peers table")
    #ONLY WORKS UP TO 9, 10 fails (see local creds, maybe tuple problem (str(id),) might fix it

def get_peers(howmany):
    conn = connect_db()
    cursor = r.db(DB).table('peers').pluck('Ipv4','Port','Address','Mdns').limit(howmany).run(conn)
    peers=[]
    for document in cursor:
        peers.append(document)
    return peers


def local_creds(id):
    #retrieves credentials from local Sqlite3 Keys DB
    conn = connect_sql("localkeys")
    #print(conn)
    c = conn.cursor()
    creds = c.execute(''' SELECT * FROM keys WHERE (id=?) ''',(str(id))).fetchall()
    #print(creds)
    cred_dict = {"pubkDER":creds[0][1],
                "pkeyDER":creds[0][2],
                "algo":creds[0][3],
                "algotype":creds[0][4]}    
    return cred_dict

def local_creds_by_ID(pubK):
    #retrieves credentials from local Sqlite3 Keys DB
    conn = connect_sql("localkeys")
    #print(conn)
    c = conn.cursor()
    creds = c.execute(''' SELECT id FROM keys WHERE (pubKey=?) ''',(str(pubK),)).fetchall()
    #print(creds)
    #cred_dict = {"pubkDER":creds[0][1],
    #            "pkeyDER":creds[0][2],
    #            "algo":creds[0][3],
    #            "algotype":creds[0][4]}    
    return creds


def fill_accounts_db(howmany):
    conn = connect_db()
    for i in range(howmany):
        print(i)
        creds = local_creds(i+1)
        record = {"address":creds['pubkDER'],"balance":1000}
        insert("accounts", record, conn)
        print("added 1 account in RethinkDB")
    # this function currently only imports 9 records, fails on record 10 
    # (some string issue, try putting id in a tuple(str(id),), in local_creds)

if __name__ == "__main__":
    print("This is the node ORM")
    #print(create_key("RSA", "2048"))
    #print(create_key("ECC", "P-256"))
    

    #PROC 1 -- Create new DB from scratch
    ######################################
    #create_local()
    #fill_keys_table(10)
    #print(local_creds("1"))

    #conn = connect_db()
    #r.db_create(DB).run(conn)
    #out = create_table("accounts",conn)
    #out1 = create_table("peers",conn)
    #out2 = create_table("potentials",conn)
    #out3 = create_table("blacklist", conn)
    #print(out)
    #print(out1)
    #print(out2)
    #print(out3)
    #res = fill_accounts_db(10)
    #print(res)

    # END PROC 1 -- #####################
    fill_peers_table(10)
