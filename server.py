import json
import socket
import sys
import getopt
from threading import Thread, Lock
from typing import List, Tuple
import select
from math import ceil
import time

ATTEMPT_TIMER = 0
PORT = 8080
ADDR = "127.0.0.1"
lock = Lock()


clients = []


alphanum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALPHANUM_LIST = list(alphanum)

hashes = {"1":"MD5","2a":"Blowfish - 2a","2y":"Eksblowfish - 2y","5":"SHA-256", "6": "SHA-512","y": "yescrypt","2b":"bcrypt version 2b" }

#Contains cracked passwords
output = {}



def main(file, users):
    tasks = get_hashes(file, users)
    sock = server_setup()
    # connection handler receives new clients
    thread_1 = Thread(target=connection_handler,args=(sock,))
    thread_1.start()
    # task manager splits tasks and sends to each client
    thread_2 = Thread(target=task_assigner, args=(tasks,))
    thread_2.start()




def get_hashes(shadow, users):
    passwords = []
    try:
        shadow_file = open(shadow, 'r')
    except:
        sys.exit("Could not open shadow file")

    lines = shadow_file.readlines()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        user = line.split(":")[0]
        if users and user not in users:
            continue
        if (line.split(":")[1] == "!!" or line.split(":")[1] == "*" or line.split(":")[1] == "" or line.split(":")[
            1] == "!*" or line.split(":")[1] == "!"):
            continue
        passwords.append(line.split(":")[1])
    return passwords


def server_setup():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ADDR, int(PORT)))
    return server_socket


def connection_handler(sock: socket.socket):
    sock.listen()
    while True:
        # Wait for a new client connection
        client_socket, client_address = sock.accept()
        print(f"Accepted new connection from {client_address}")
        with lock:
            clients.append(client_socket)


def task_splitter(chars: List, num_clients: int):
    # Separates workload based on number of clients connected
    result = []
    num_each = ceil(len(chars) / num_clients)
    for i in range(0, len(chars), num_each):
        result.append(chars[i:i + num_each])
    return result


def task_assigner(tasks):
    # Takes each hashed password and splits workload among clients
    # WHen cracked, client sends a msg
    check = False
    i = 0
    time.sleep(5)
    while i < len(tasks):
        with lock:
            # If there are not any clients, reset loop
            if len(clients) < 1:
                continue
            # Split tasks based on num clients
            workspace = task_splitter(ALPHANUM_LIST, len(clients))
            print("Sending tasks to workers.....")
            # There are clients, assign task to each client
            for c in range(len(clients)):
                msg = {"TASK": "CRACK", "VALUE": tasks[i], "RANGE": workspace[c]}
                clients[c].sendall(json.dumps(msg).encode())

        print("Waiting for response.....")
        # Using select, wait for an update from client
        while True:
            with lock:
                readable, _, _ = select.select(clients, [], [])

                # readable is list of clients who sent msg to server
            for sock in readable:
                # Data from existing client socket
                response = sock.recv(4096)
                print(response)
                response = json.loads(response.decode())
                if response["TASK"] == "SUCCESS":
                    cracked_pass = response["VALUE"]
                    print(f"Task completed by {sock.getpeername()}")
                    print(f"{tasks[i]} is ->  {cracked_pass}")
                    # emit stop command
                    check = stop(sock)
                    i += 1
                    break
            if check:
                print("Getting next task")
                break


def stop(sock: socket.socket):
    # Tells all clients to kill stop the cracking process
    print("Emitting STOP event")
    with lock:
        msg = {"TASK": "STOP"}
        for c in clients:
            if c != sock:
                c.sendall(json.dumps(msg).encode())
    return True



def output():
    pass


def usage():
    print("-------------------------------------------")
    print("sample usage: python main.py [options] user1 user2")
    print("-------------------------------------------\n")
    print("-h  --help   show this help")
    print("-f           specify shadow file")
    print("-p           specify server port")
    print("-t           set attempt limit")


def parse_args() -> Tuple[str, List[str]] :
    global ATTEMPT_TIMER
    global PORT
    file = ""

    if len(sys.argv) == 1:
        print("Missing required args, usage below.....")
        usage()
        sys.exit()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hf:t:p:", ["help"])
    except getopt.GetoptError as err:
        # Print error msg and usage guide
        print(err)
        sys.exit(2)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o == "-f":
            print(f"file is {a}")
            file = a
        elif o == "-t":
            print(f"attempt is {a}")
            ATTEMPT_TIMER = a
        elif o == "-p":
            print(f"port is {a}")
            PORT = a
        else:
            print("Unhandled option.... Exiting\n")
            sys.exit()
    print(args)
    print("-------------------------------------------\n")
    return file, args

if __name__ == "__main__":
    file, users = parse_args()
    main(file, users)
