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

exit_flag = False

clients = []


alphanum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALPHANUM_LIST = list(alphanum)

hashes = {"1":"MD5","2a":"Blowfish - 2a","2y":"Eksblowfish - 2y","5":"SHA-256", "6": "SHA-512","y": "yescrypt","2b":"bcrypt version 2b" }

#Contains cracked passwords
output = {}


def main(file, users):
    tasks, names = get_hashes(file, users)
    sock = server_setup()
    # connection handler receives new clients
    thread_1 = Thread(target=connection_handler, args=(sock,))
    thread_1.start()
    # task manager splits tasks and sends to each client
    thread_2 = Thread(target=task_assigner, args=(tasks, names))
    thread_2.start()



def get_hashes(shadow, users):
    passwords = []
    usernames = []
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
        hashed_password = line.split(":")[1]
        passwords.append(hashed_password)
        usernames.append(user)
        initialize_output(user, hashed_password)
    return passwords, usernames


def initialize_output(user: str, hashed_password: str):
    output[user] = {}
    output[user]['hash'] = hashes[hashed_password.split("$")[1]]
    output[user]['password'] = "Not cracked"
    output[user]['tries'] = ""
    output[user]['time'] = ""


def server_setup():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((ADDR, int(PORT)))
    server_socket.setblocking(False)
    return server_socket


def connection_handler(sock: socket.socket):
    # Wait for a new client connection
    sock.listen()
    while True:
        if exit_flag:
            return
        try:
            client_socket, client_address = sock.accept()
            print(f"Accepted new connection from {client_address}\n")
            with lock:
                clients.append(client_socket)
        except BlockingIOError:
            # no connections available at this time
            pass


def task_splitter(chars: List, num_clients: int):
    # Separates workload based on number of clients connected
    result = []
    num_each = ceil(len(chars) / num_clients)
    for i in range(0, len(chars), num_each):
        result.append(chars[i:i + num_each])
    return result


def task_assigner(tasks: List[str], names: List[str]):
    # Takes each hashed password and splits workload among clients
    # WHen cracked, client sends a msg
    global exit_flag
    check = False
    i = 0
    print("Server waiting for 10 seconds to allow clients to connect!\n")
    time.sleep(10)
    while i < len(tasks):
        start = time.time()
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
                readable, _, _ = select.select(clients, [], [], 0)
            # readable is list of clients who sent msg to server
            for sock in readable:
                # Data from existing client socket
                response = sock.recv(4096)
                response = json.loads(response.decode())
                if response["TASK"] == "SUCCESS":
                    cracked_pass = response["VALUE"]
                    attempt_num = response["ATTEMPT"]
                    tracked_time = response["TIME"]
                    print(f"Task completed by {sock.getpeername()}")
                    print(f"{tasks[i]} is ->  {cracked_pass}\n")
                    # emit stop command
                    check = stop(sock, True)
                    break

            end = time.time()
            if check:
                print("Getting next task\n")
                output[names[i]]['password'] = cracked_pass
                output[names[i]]['tries'] = attempt_num
                output[names[i]]['time'] = tracked_time
                i += 1
                check = False
                time.sleep(3)
                break
            elif end - start >= ATTEMPT_TIMER:
                output[names[i]]['tries'] = "Attempts not tracked due to time limit"
                output[names[i]]['time'] = "Limit Exceeded"
                stop(sock, False)
                i += 1
                break
    print("Finished cracking.....")
    print_stats()
    exit_flag = True
    return


def stop(sock: socket.socket, flag: bool):
    # Tells all clients to kill stop the cracking process
    print("Emitting STOP event")
    if flag:
        with lock:
            msg = {"TASK": "STOP"}
            for c in clients:
                if c != sock:
                    c.sendall(json.dumps(msg).encode())
        return True
    else:
        with lock:
            msg = {"TASK": "STOP"}
            for c in clients:
                c.sendall(json.dumps(msg).encode())


def print_stats():
    # Displays program results when done
    print(f"\nResults of the password cracking process!")
    print(f"------------------------------------------\n")
    if len(output) == 0:
        print("No users cracked!\n")
        return
    for i in output:
        print(f"Username: {i}\n")
        print(f"Hash: {output[i]['hash']}\n")
        print(f"Password: {output[i]['password']}\n")
        print(f"Tries: {output[i]['tries']}\n")
        print(f"Time: {output[i]['time']}\n")
        print(f"------------------------------------------\n")


def usage():
    print("-------------------------------------------")
    print("sample usage: python main.py [options] user1 user2")
    print("-------------------------------------------\n")
    print("-h  --help   show this help")
    print("-f           specify shadow file")
    print("-p           specify server port")
    print("-t           set attempt limit in seconds")


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
            print(f"File: {a}\n")
            file = a
        elif o == "-t":
            try:
                if int(a) < 0:
                    print("Must be > 0\n")
                    sys.exit()
            except:
                print("Time must be int\n")
                sys.exit()
            print(f"Attempt limit in seconds: {a}\n")
            ATTEMPT_TIMER = int(a)
        elif o == "-p":
            try:
                if int(a) < 1 or int(a) > 60000:
                    print("Specify a valid port from 1-60000\n")
                    sys.exit()
            except ValueError:
                print("Enter a valid port\n")
                sys.exit()
            print(f"port is {a}")
            PORT = a
        else:
            print("Unhandled option.... Exiting\n")
            sys.exit()
    if args:
        print(f"Users: {args}")
    else:
        print(f"Cracking all passwords")
    print("-------------------------------------------\n")
    return file, args


if __name__ == "__main__":
    file, users = parse_args()
    try:
        main(file, users)
    except KeyboardInterrupt as e:
        sys.exit(e)