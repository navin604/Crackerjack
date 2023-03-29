import socket
import sys
import getopt


def usage():
    print("-------------------------------------------")
    print("sample usage: python main.py [options] user1 user2")
    print("-------------------------------------------\n")
    print("-h  --help   show this help")
    print("-f           specify shadow file")
    print("-p           specify server port")
    print("-t           set attempt limit")


ATTEMPTS = 0
PORT = 8080
ADDR = "127.0.0.1"





def parse_args():
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
