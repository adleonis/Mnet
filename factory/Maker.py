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

DB = "Mnet002"
DBlocal = "localkeysPEM"

### - Connect to Rethink DB - ###
def connect_db():
    conn = r.connect("localhost", 28015)
    return conn

### - Connect to Sqlite - ###
def connect_sql(DB):
    conn = sqlite3.connect(DB)
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


#why is this here? should be in Server ORM
def execute_transaction(AccountUpdate, conn):
    res1 = r.db('Mnet001').table('accounts').filter({'address': AccountUpdate.FromAddress}).update({"balance": AccountUpdate.FromBalance}).run(conn)
    res2 = r.db('Mnet001').table('accounts').filter({'address': AccountUpdate.ToAddress}).update({"balance": AccountUpdate.ToBalance}).run(conn)
    #DEFINITLY IMPLEMENT SOME HARD COMMIT OR ROLLBACK HERE!!!! can't fail one of the other, ever    
    print("**DB Update Successful: Local Transfer in mempool complete**")
#*****************************************

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

#Obsolete: Use Local_creds() below ********************
def get_key(passphrase):
    encoded_key = open("rsa_key.bin", "rb").read()
    key = RSA.import_key(encoded_key, passphrase=passphrase)
    return key
#******************************************************

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
    database = DBlocal
 
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
    conn = connect_sql(DBlocal)
    c = conn.cursor()
    for i in range(howmany):
        key =  create_key("ECC","P-256")
        c.execute(''' INSERT INTO keys(pubkey,pkey,algo,algotype,encoding,Mdns) VALUES(?,?,?,?,?,?) ''',[key["pubkPEM"],
                                            key['pkeyPEM'],
                                            key['algo'],
                                            key['algotype'],
                                            "PEM",
                                            "account"+ str(i)]) 
    conn.commit()    
    print("Added new keys in keys DB")


def local_creds(id):
    #retrieves credentials from local Sqlite3 Keys DB
    conn = connect_sql(DBlocal)
    c = conn.cursor()
    creds = c.execute(''' SELECT * FROM keys WHERE (id=?) ''',(str(id),)).fetchall()
    print(creds)
    cred_dict = {"pubkPEM":creds[0][1],
                "pkeyPEM":creds[0][2],
                "algo":creds[0][3],
                "algotype":creds[0][4]}    
    return cred_dict

def fill_accounts_db(howmany,whichfield):
    conn = connect_db()
    for i in range(howmany):
        print(i)
        creds = local_creds(i+1)
        record = {"address":creds[whichfield],"balance":1000}
        insert("accounts", record, conn)
        print("added 1 account in RethinkDB")
    # this function currently only imports 9 records, fails on record 10 
    # (some string issue, try putting id in a tuple(str(id),), in local_creds)

if __name__ == "__main__":

    #print(create_key("RSA", "2048"))
    #print(create_key("ECC", "P-256"))
    

    #PROC 1 -- Create new DB from scratch
    ######################################
    create_local()
    fill_keys_table(10)
    print(local_creds("1"))

    conn = connect_db()
    r.db_create(DB).run(conn)
    out = create_table("accounts",conn)
    out1 = create_table("peers",conn)
    out2 = create_table("potentials",conn)
    out3 = create_table("blacklist", conn)
    #print(out)
    #print(out1)
    #print(out2)
    #print(out3)
    res = fill_accounts_db(10, "pubkPEM")
    print(res)    

    # END PROC 1 -- ######################

