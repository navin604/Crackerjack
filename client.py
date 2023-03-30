import socket





if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 2020))
    data = sock.recv(1024).decode()  # receive response
    sock.sendall('completed'.encode())

    print('Received from server: ' + data)  # show in terminal

