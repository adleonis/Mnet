# Copyright 2018 Pensiv LLC
# gallet.stephane@gmail.com
# All rights reserved

"""The Python implementation of the gRPC Mnet-sync client."""
from __future__ import print_function

import sys
sys.path.append("../")


import grpc

import Mnet_sync_pb2
import Mnet_sync_pb2_grpc

import random  #IS THIS SAFE? don't use for crypto, use pycryptodomex
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import DSS

import base64
import json
import time

import Mnode_orm as orm

###############################################################################
##############                                              ###################
##############                Client Methods                ###################
##############                                              ###################
###############################################################################


def client_get_account_info(AccountAddress):
    AccountDemand = Mnet_sync_pb2.AccountDemand(AccountAddress=AccountAddress)
    #print("\n --- Account Demand ---\n",AccountDemand)
    return AccountDemand


#### REVIEW: need to save address own addresses and account info in rethinkDB ####

######### OBSOLETE< ###################
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
######################################

######## OBSOLETE ####################
def get_key(passphrase):
    encoded_key = open("rsa_key.bin", "rb").read()
    key = RSA.import_key(encoded_key, passphrase=passphrase)
    return key
######################################

def sign_t(key, transaction_object):
    #Method signs a transaction
    h = SHA256.new(str(transaction_object).encode())
    #h = SHA256.new(json.dumps(transaction).encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature


def sign_t_DSA(key, transaction_object):
    #Method signs a transaction
    h = SHA256.new(str(transaction_object).encode())
    #h = SHA256.new(json.dumps(transaction).encode())
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)
    return signature



def create_t(Accounts, Amounts, Messages):
    #Method to create a transaction (AccountUpdate type, see proto)
    #Amounts is a list of amounts to each account on list [-100 50 50]
    #Get latest account balances from server
    #First Account should be the owner account (debited)

    #1. Check math, total amounts = 0
    if sum(Amounts) != 0:
        print("Sorry, your math is wrong, total sum of Amounts must be 0")
        return False        

    with grpc.insecure_channel('localhost:50051') as channel:
        stub = Mnet_sync_pb2_grpc.MnetsyncStub(channel)
        #print("-- GetAccountInfo for: ", FromAddress)

        # Create TransactionRequest object   
        TR = Mnet_sync_pb2.TransactionRequest()

        #Create Instances of LumpStates
        FromState_lump = Mnet_sync_pb2.LumpState()
        ToState_lump = Mnet_sync_pb2.LumpState()

        #1. Build 2 Lumpstates (FromState, ToState) from AccountInfo lists
        
        #1.1 Build Fromstate
        list = []
        iterator = 0
        for account in Accounts:
            #Create instance of AccountInfo
            AccountState = Mnet_sync_pb2.AccountInfo()
            #Get latest info from server (accountbalance) and fill instance of Accountinfo
            response = stub.GetAccountInfo(client_get_account_info(AccountAddress=account))
            AccountState.AccountAddress = response.AccountAddress
            AccountState.AccountBalance = response.AccountBalance
            AccountState.TextMessage = response.TextMessage
            #print(AccountState)
            list.append(AccountState)
            iterator += 1
        #Fill in lump object with accounts
        #FromState_lump.AccountState.extend(list)
        TR.Transaction.FromState.AccountState.extend(list)
       
        #1.1 Build Tostate
        to_list = []
        iterator = 0
        for amount in Amounts:
            #Create instance of AccountInfo
            AccountState = Mnet_sync_pb2.AccountInfo()
            #DO MATH (FromAmount + transfer = ToAmount)
            AccountState.AccountAddress = response.AccountAddress
            AccountState.AccountBalance = TR.Transaction.FromState.AccountState[iterator].AccountBalance + amount
            AccountState.TextMessage = Messages[iterator]
            #print(AccountState)
            to_list.append(AccountState)
            iterator += 1
        #Fill in lump object with accounts
        TR.Transaction.ToState.AccountState.extend(to_list)
        #ToState_lump.AccountState.extend(to_list)

        #Make AccountUpdate Object
        #AccountUpdate_object = Mnet_sync_pb2.AccountUpdate
        TR.Transaction.Owner.CopyFrom(TR.Transaction.FromState.AccountState[0])
        #AccountUpdate_object.FromState = FromState_lump    
        #AccountUpdate_object.ToState = ToState_lump    

        #***************************
        #Sign Transaction object (it's an AccountUpdate type)
        signature = sign_t_DSA(orm.make_key(orm.local_creds_by_ID(Accounts[0])[0][0]), TR.Transaction)   
        # Create TransactionRequest object and fill it    
        #TransactionRequest = Mnet_sync_pb2.TransactionRequest()
        TR.Signature = signature
        TR.Timestamp = int(time.time())
        #print("--------------TransactionRequest---------------")
        #print(TR)
        #print(type(TR))
        #***************************

    #TR is the "Transaction Request"
    return TR

#***********OBSOLETE**************************
def create_transaction_request(transaction,localcredsID):
    #Sign Transaction object (it's an AccountUpdate type)
    signature = sign_t_DSA(orm.make_key(localcredsID), transaction)    
    # Create TransactionRequest object and fill it    
    TransactionRequest = Mnet_sync_pb2.TransactionRequest()
    TransactionRequest.Signature = signature
    TransactionRequest.Timestamp = int(time.time())
    Transaction = Mnet_sync_pb2.AccountUpdate   ##WEIRD PROTOBUF THING, just set child and it automatically gets put into parent
    print(type(Transaction))
    print(type(transaction))

    Transaction.CopyFrom(transaction)
    
    print(TransactionRequest)
    return TransactionRequest
#**********************************************


#originally in server -- try -----------------
def confirm_transaction(TransactionRequest):
    #This is a CLIENT method
    #Once transaction has been made locally by node, tell other nodes about it.
    #Select peer from list
    #Pass along original transaction request (node wants other nodes to agree on transfer, including commission
    #close com once enough nodes have agreed

    #Get peers from Peers DB
    peers = orm.get_peers(5)
    #print(peers)
    #Loop through peers, sending transaction
    for peer in peers:
        Ipv4 = peer['Ipv4']
        Port = peer['Port']
        #Port = 50052

        print(Ipv4+":"+str(Port))
        #Start a communication Channel with new peer (you are the client in this connection)
        with grpc.insecure_channel('localhost:50052') as channel:
        #with grpc.insecure_channel(Ipv4+":"+str(Port)) as channel:

            stub2 = Mnet_sync_pb2_grpc.MnetsyncStub(channel)
            TC = build_TransactionConfirmation(peer, peers, TransactionRequest)
            selfPeer=orm.get_peers(1)  #hardcoded, get actual local server info to put here, since you've already accepted the transaction
            TC = add_peer_toTransactionConfirmation(selfPeer, TC)
            print("got here")
            #response_stream = stub2.ConfirmTransaction(yield_TC(True, TC))
            response_stream = stub2.ConfirmTransaction(TC)
            print(" -- response stream -- \n")
            print(response_stream)
            for response in response_stream:
                print("resp: -- ",response)


#---------------------------------------------

def run_transactions(howmany,stub):
    accounts = [orm.local_creds(1)['pubkDER'],orm.local_creds(2)['pubkDER'],orm.local_creds(3)['pubkDER']]
    amounts = [-21, 20, 1]
    messages = ["Paying rent", "Rent from Stephane", "Transaction Fee"]
    for i in range(howmany):
        t = create_t(accounts, amounts, messages)
        #print("\n -------------- Output -------------- \n", t, "\n" ,req)
        responses = stub.ProcessTransaction(t)
        try:
            for response in responses:
                print("@ ", response.Timestamp, " |  " ,response.Status)
        except grpc.RpcError as e:
            e.details()
            status_code = e.code()
            status_code.name
            status_code.value


def run():
    # NOTE(gRPC Python Team): .close() is possible on a channel and should be
    # used in circumstances in which the with statement does not fit the needs
    # of the code.
    with grpc.insecure_channel('localhost:50051') as channel:
        stub = Mnet_sync_pb2_grpc.MnetsyncStub(channel)
        
        #print("-------------- GetAccountInfo --------------")
        #response = stub.GetAccountInfo(client_get_account_info(AccountAddress="3D2oetdNuZUqQHPJmcMDDHYoqkyNVsFk9r"))
        #print(response)

        #print("\n -------------- Create Transaction Request -------------- \n")
        #t = create_t(100,"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqMTJvoYL+97W8t9/Xo5e5ult9z+5lhep4BEos+yqj+7M+GXUllK+rlT4PQ+4hLY4wVhJY3Bmrxzt9VNPFAZA3FnxVVv2PewDmVoAVak1+Q1XpGKryOJopAfHWzsIRNZ8tT1tqyrYEQujilfuQ8wjiP0aqjl7o0C5+n0u/5YS/mdFDTNTZofu2Yo/mbSC/aQXg8h41D+Y0FcHsfsuMibh94D4mA0kKkxZW1daKQeifnt5SzcfU/zeVKRsn8atAmxgnspzugxjCODgTSj1ZAilMsx8nObNlVlaBUNXL2/Vuvc+/aqsuEWlgKSWZlf69VZ6jGjKsiwnE2fblDiEEIJOsQIDAQAB", "1PnMfRF2enSZnR6JSexxBHuQnxG8Vo5FVK")
        cycles = 1
        start=time.time()
        run_transactions(cycles,stub)
        end = time.time()
        total = end - start
        percycle = total/cycles
        print(cycles, ' executed! -- Code Execution in: ', total)   
        print('Per cycle time: ', percycle)   

if __name__ == '__main__':
    #create_address()
    
    run()

    #with grpc.insecure_channel('localhost:50051') as channel:
    #    stub = Mnet_sync_pb2_grpc.MnetsyncStub(channel)

    #    accounts = [orm.local_creds(1)['pubkDER'],orm.local_creds(2)['pubkDER'],orm.local_creds(3)['pubkDER']]
    #    amounts = [-200, 199, 10]
    #    messages = ["Paying rent", "Rent from Stephane", "Transaction Fee"]
    #    t = create_t(accounts, amounts, messages)
    #    #tr = create_transaction_request(t, 1)
    #    #print(t)
    #    responses = stub.ProcessTransaction(t)
    #    try:
    #        for response in responses:
    #            print("@ ", response.Timestamp, " |  " ,response.Status)
    #    except grpc.RpcError as e:
    #        e.details()
    #        status_code = e.code()
    #        status_code.name
    #        status_code.value
