import Mnet_sync_server
import Mnet_sync_client



def go():
    # 1. Start Server (listening on 50051)
    out = Mnet_sync_server.serve()
    print("server STARTED, moving on")

    # catch messages coming from server
    print(out)

    # 2. Start Server_CLIENT (emmitting on 50052)
    #Mnet_sync_client.



if __name__ == "__main__":
    go()

