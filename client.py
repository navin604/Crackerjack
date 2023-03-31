import json
import socket
from threading import Thread, Lock
import random
import sys
import time
""" TODO:   SPECIFY PORT/ADDR via command line 
            

"""
stop_flag = True
lock = Lock()
crack_flag = False
def client_setup() -> socket.socket:
    # Creates socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 2020))
    return sock

def recv_msg(sock: socket.socket):
    global stop_flag
    global crack_flag
    while True:
        data = sock.recv(4096)
        print(data)
        data = json.loads(data.decode())
        if data["TASK"] == "CRACK":
            val = data["VALUE"]
            print(f"received task {val}")
            thread_1 = Thread(target=crack, args=(data["VALUE"], sock))
            thread_1.start()
        if data["TASK"] == "STOP":
            with lock:
                if crack_flag:
                    print("STOPPING FLAG SET")
                    stop_flag = False



def crack(val: int, sock: socket.socket):
    global crack_flag
    global stop_flag
    with lock:
        crack_flag = True
    print("CRACKING")
    time.sleep(3)
    while True:
        with lock:
            if not stop_flag:
                print("STOPPING FLAG REACHED")
                stop_flag = True
                sys.exit()
        num = random.randint(0,1000)
        if num == val:
            print(f"I found password {val}")
            with lock:
                crack_flag = False
            send_msg("SUCCESS", sock)
            sys.exit()


def send_msg(msg: str, sock: socket.socket):
    sock.sendall(msg.encode())
def main():
    sock = client_setup()
    thread_recv = Thread(target=recv_msg, args=(sock,))
    thread_recv.start()



if __name__ == "__main__":
    main()