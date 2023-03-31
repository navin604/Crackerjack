import crypt
import json
import socket
from threading import Thread, Lock

import sys
from typing import List, Tuple

""" TODO:   SPECIFY PORT/ADDR via command line 
            Reverse stop flag       

"""


# Turns False if STOP emitted from server
stop_flag = True
lock = Lock()
# True if cracker function active
crack_flag = False
alphanum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
ALPHANUM_LIST = list(alphanum)
found = False
cracked_pass = ""

def client_setup() -> socket.socket:
    # Creates socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 2020))
    return sock

def recv_msg(sock: socket.socket):
    # Receives tasks from server
    global stop_flag
    global crack_flag
    while True:
        data = sock.recv(4096)
        print(data)
        data = json.loads(data.decode())
        if data["TASK"] == "CRACK":
            val = data["VALUE"]
            print(f"Received hash: {val}")
            thread_1 = Thread(target=brute_force_setup, args=(data["VALUE"], data["RANGE"], sock))
            thread_1.start()
        if data["TASK"] == "STOP":
            with lock:
                if crack_flag:
                    print("Received stop request")
                    stop_flag = False


def check_status() -> bool:
    # Checks if stop event emitted from server
    global stop_flag
    with lock:
        if not stop_flag:
            return True


def set_flag():
    # Resets flags upon receiving STOP event
    global stop_flag
    global crack_flag
    with lock:
        if not stop_flag:
            print("STOPPING cracking thread")
            stop_flag = True
            crack_flag = False


def brute_force(hashed_pass, char_len, cur_str, chars):
    # Cracks passwords
    global found
    global stop_flag
    global cracked_pass
    try:
        if char_len == 0:
            # Hash cur_str and check if it matches hashed password
            hashed = crypt.crypt(cur_str, hashed_pass)
            if hashed == hashed_pass:
                print("Brute Force Attack Succeeded!")
                print("===================================================")
                print(f"Password is {cur_str}")
                print("===================================================\n")
                found = True
                cracked_pass = cur_str
                return
            # Incorrect guess
            return

        if cur_str == "":
            # assign prefix
            for i in chars:
                if found:
                    return
                elif check_status():
                    return
                attempt = cur_str + i
                brute_force(hashed_pass, char_len - 1, attempt, chars)
        else:
            for i in ALPHANUM_LIST:
                # assign suffix
                if found:
                    return
                elif check_status():
                    return
                attempt = cur_str + i
                brute_force(hashed_pass, char_len - 1, attempt, chars)
        return
    except Exception:
        return


def brute_force_setup(hashed_pass: str, chars: List[str], sock: socket.socket):
    global found
    global crack_flag
    global stop_flag
    # Start with single character passwords
    char_len = 1
    with lock:
        crack_flag = True
    while not found:
        brute_force(hashed_pass, char_len, "", chars)
        if check_status():
            # Stop emitted from server, reset flags and close thread
            set_flag()
            sys.exit()
        char_len += 1
    with lock:
        crack_flag = False
    found = False
    msg = {"TASK": "SUCCESS", "VALUE": cracked_pass}
    send_msg(msg, sock)
    sys.exit()


def send_msg(msg: dict, sock: socket.socket):
    # Send success message
    sock.sendall(json.dumps(msg).encode())


def main():
    sock = client_setup()
    thread_recv = Thread(target=recv_msg, args=(sock,))
    thread_recv.start()


if __name__ == "__main__":
    main()