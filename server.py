import socket
import sys
import getopt
from threading import Thread, Lock
from typing import List, Tuple
import select


ATTEMPTS = 0
PORT = 8080
ADDR = "127.0.0.1"
lock = Lock()


clients = []

AlphabetLower = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u',
    'v', 'w', 'x', 'y', 'z','A','B','C',
    'D','E','F','G','H','I','J','K','L',
    'M','N','O','P','Q','R','S','T','U',
    'V','W','X','Y','Z','0','1','2','3','4',
    '5','6','7','8','9'
]

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
        print("Waiting for connections")
        client_socket, client_address = sock.accept()
        print(f"Accepted new connection from {client_address}")
        with lock:
            clients.append(client_socket)


def task_assigner(tasks):
    # place holder task list. Clients will just guess random num
    tasks = [12,65,3,86,45,37,69]
    i = 0
    while i < len(tasks):
        print(tasks[i])
        # somehow implement brays trash code to split tasks can call clients
        # in client list. PLaceholder stuff below
        with lock:
            # If there are not any clients, reset loop
            if len(clients) < 1: continue

            # There are clients, split task and then send them
            for c in clients:
                # send num to client
                # in real version, each client will get sent a different range to guess
                c.sendall(str(tasks[i]).encode())


        # Using select, wait for an update from client
        while True:
            with lock:
                readable, _, _ = select.select(clients, [], [])

                # readable is list of clients who sent msg to server
            for sock in readable:
                # Data from existing client socket
                response = sock.recv(1024).decode()
                if response == "completed":
                    # The client has completed the task
                    # Exit program
                    # IN future we send a msg to all clients telling them to stop current task
                    print(f"Client {sock.getpeername()} completed task")
                    # increment task iterator
                    i+=1
                    sys.exit()



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
    global ATTEMPTS
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
            ATTEMPTS = a
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
