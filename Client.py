import socket
import sys
import secrets
from hashlib import pbkdf2_hmac
from cryptography.fernet import Fernet


def end_connection(connection: socket.socket):
    connection.close()
    exit()


def start_connection(public_keys: list, connection: socket.socket) -> int:
    public_keys = public_keys
    client_private = secrets.randbits(8)

    # Calculate & send the calculated client key
    print("Sending client key...")
    client_key = pow(public_keys[1], client_private, mod=public_keys[0])
    connection.send(bytes([client_key]))

    # Receive the server key
    server_key = int.from_bytes(connection.recv(1026), "big")
    shared_key = server_key**client_private % public_keys[0]
    return shared_key


def main(args: list):
    # Main function

    # Get encryption public keys
    public_keys = [int(key) for key in args[1:3]]

    # Get the server port
    port = args[3]

    # Start connection with server to get a shared key
    con = socket.create_connection(("localhost", port))
    print("test")
    shared_key = start_connection(public_keys=public_keys, connection=con)
    print(shared_key)

    end_connection(connection=con)


if __name__ == "__main__":
    # Arguments:
    # 1) The 1st public var used for encryption
    # 2) The 2nd public var used for encryption
    # 3) The port of the server

    # Using gitlab-ci, an example would be:
    # python Client.py ${1ST_PUBLIC_VAR} ${2ND_PUBLIC_VAR}

    main(args=sys.argv)
