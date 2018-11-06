# Copyright 2018 Pensiv LLC
# gallet.stephane@gmail.com
# All rights reserved

"""The Python implementation of the gRPC route guide server for Mnet Nodes"""

import sys
sys.path.append('../')
import re
from concurrent import futures
import time
import math
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

import grpc

import Mnet_sync_pb2
import Mnet_sync_pb2_grpc
#import Mnet_sync_resources  #where is this??

import Mnode_orm as orm

import threading

import logging
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)

logging.basicConfig(filename='./Mnet_server.log', level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')

_ONE_DAY_IN_SECONDS = 60 * 60 * 24

DB="Mnet002"

exitFlag = 0  #threading


class MnetsyncServicer(Mnet_sync_pb2_grpc.MnetsyncServicer):
    """Provides methods that implement functionality of Mnet_sync."""

    #def __init__(self):
    # AT SOME POINT INSTANTIATE     
    #    self.db = Mnet_sync_resources.read_Mnet_sync_database()

    def GetAccountInfo(self, request, context):
        #REMEMBER TO START THE RETHINKDB SERVER BEFOREHAND, somwhere
                
        #Get the interesting info from the request
        AccountAddress = request.AccountAddress

        #Lookup in DB
        conn = orm.connect_db()
        AccountInfo = orm.read(DB="Mnet002", tablename="accounts", accountaddress=AccountAddress, conn=conn)
        #Create a response object using predefined PROTO types
        response = Mnet_sync_pb2.AccountInfo()
        if AccountInfo is not None:
            #Save DB values into Response Object
            response.AccountAddress = AccountInfo['address']
            response.AccountBalance = AccountInfo['balance']
        else:
            #No such account on record
            context.set_details("Sorry, we don't have any info on this address")
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
        return response
    
    def sign_t_DSA(key, transaction_object):
        h = SHA256.new(str(transaction_object).encode())
        signer = DSS.new(key, 'fips-186-3')
        signature = signer.sign(h)
        return signature

    def ProcessTransaction(self, request, context):
        
        try:
            #Check that request comes from account owner
            # needed? why? SO OTHERS DON"T TRY TO SUBMIT OLD TRANSACTIONS ALREADY SIGNED BY OWNER (or intercepted), maybe needed
            #Check that request is signed correctly (by owner)
            #print(request, type(request))
            owner = request.Transaction.Owner.AccountAddress
            #print("Owner:", owner)
            signature = request.Signature
            logging.info("Just received a transaction request from: "+str(request.Transaction.Owner.AccountAddress))

            #print("sig: \n", signature)
            #key = RSA.import_key("-----BEGIN PUBLIC KEY-----\n"+ owner + "\n-----END PUBLIC KEY-----")
            key = ECC.import_key(owner)
            #print("\n \n --- \n \n", request.Transaction, "\n", type(request.Transaction))
            h = SHA256.new(str(request.Transaction).encode())
            verifier = DSS.new(key, 'fips-186-3')
            try:
                verifier.verify(h, signature)
                #pkcs1_15.new(key).verify(h, signature) #for RSA instead of ECC
                logging.info("The signature is valid.")
            except (ValueError, TypeError):
                logging.warning("The signature is not valid.")
            #Check that math works out (not creating or stealing money)
                #Get current account, compare From State and To State and build Amounts array, check sum(amounts)=0
                #Also check no account goes negative
            #Lookup in DB

            #Check math
            amounts = [[],[],[],[]] #FromBalance, ToBalance, Amountchange, Textmessage
            it = 0
            for account in request.Transaction.FromState.AccountState:
                amounts[0].append(account.AccountBalance)
            for account in request.Transaction.ToState.AccountState:
                if account.AccountBalance > 0:  #Check no accounts go negative
                    amounts[1].append(account.AccountBalance)
                    amounts[3].append(account.TextMessage)
                    amounts[2].append(amounts[1][it] - amounts[0][it])
                else:
                    Status = "-- Account Balance Insuficient for transaction --"
                    logging.info(Status)
                    TransactionStatus = Mnet_sync_pb2.TransactionStatus(Status=Status,Timestamp=int(time.time()))
                    yield TransactionStatus
                    raise ValueError("Account Balance Insuficient for transaction")
                it+=1

            #Check total transfer math is ok
            if sum(amounts[2]) == 0:
                logging.info("-- MATH IS OK --")
                #print("-- MATH IS OK --")
            else:
                #warn user, transaction refused, math wrong
                return False
            
            # Check that the FromState is the same as node local version (in-sync check)
            conn = orm.connect_db()
            iter = 0
            for amount in amounts[0]:    
                balance = orm.read(DB, "accounts", request.Transaction.FromState.AccountState[iter].AccountAddress, conn)['balance']
                if amount == balance:
                    #print("-- Account in sync --")
                    logging.info("-- Account in sync, checked --")
                else:
                    print("--Need to sync account first--")
                    # TODO: try to connect to peers and sync local account info to try again
                    logging.info("-- NOT ALL ACCOUNTS SYNCED, UNABLE TO SYNC, TRANSACTION ABORTED --")
                    return False
                iter +=1
            logging.info("-- ALL ACCOUNTS SYNCED and TRANSACTION INFO VERIFIED --")
            Status = "Locally Accepted "
            TransactionStatus = Mnet_sync_pb2.TransactionStatus(Status=Status,Timestamp=int(time.time()))
            yield TransactionStatus
            
            #Update DB --> send to Mempool
            AccountUpdate = request.Transaction
            res = orm.execute_transaction(AccountUpdate, conn)
            Status = "**DB Update Successful: Local Transfer to mempool complete**"
            TransactionStatus = Mnet_sync_pb2.TransactionStatus(Status=Status,Timestamp=int(time.time()))
            logging.info("**DB Update Successful: Local Transfer to mempool complete**")
            yield TransactionStatus
            #Communicate to other node?  maybe somewhere else
            confirm_transaction(request)
            return True
        except():
            Status = "**Transaction Failed**"
            TransactionStatus = Mnet_sync_pb2.TransactionStatus(Status=Status,Timestamp=int(time.time()))
            yield TransactionStatus
            logging.warning("**Transaction Failed**")
            return False

def build_TransactionConfirmation(peer, peers, request):
    TC = Mnet_sync_pb2.TransactionConfirmation()
    TC.OriginalTransactionRequest.Transaction.CopyFrom(request.Transaction)
    TC.CurrentStatus = True
    return TC

def add_peer_toTransactionConfirmation(newpeer, TC):
    #TC is current instance of TransactionConfirmation
    TC.PeersConfirmed.add()
    PeersConfirmed = newpeer
    #print(PeersConfirmed)
    yield TC

def yield_TC(flag, TC):
    while flag == True:
        time.sleep(2)
        print(" -- Yielding TC -- ")
        yield TC

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
            return response_stream
            #for response in response_stream:
            #    print("resp: -- ",response)

def ConfirmTransaction(self, request, context):
    #THIS IS THE SERVER METHOD
    
    #Accept TransactionConfirmation, check locally, send response (open stream)
    #When satisfied enough peers also confirmed, close it
    print(" Request for Transaction Confirmation Received from peer -- Evaluating")
    print(response)
    time.sleep(2)
    return request
    #for response in request_iterator:
    #    print(response)
    #    time.sleep(2)
    #    yield response

    #prev_notes = []
    #for new_note in request_iterator:
    #    for prev_note in prev_notes:
    #        if prev_note.location == new_note.location:
    #            yield prev_note
    #    prev_notes.append(new_note)
    #    print("New Note: ",new_note)

def serve():
    logging.info("Server Started")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    Mnet_sync_pb2_grpc.add_MnetsyncServicer_to_server(
        MnetsyncServicer(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    print('Started server. Listening on port 50051.')
        
    try:
        while True:
            time.sleep(_ONE_DAY_IN_SECONDS)
    except KeyboardInterrupt:
        server.stop(0)
        logging.info("Server Stopped")

if __name__ == '__main__':
    serve()
    #confirm_transaction()
