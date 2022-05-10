import socket, select, sys
from scapy.all import *
from AES import AESCipher
import binascii


def handle_connection(data: bytes, connection: socket.socket, connections_dict: dict, main_con):

    cipher = connections_dict[connection]

    # First stage: Decrypt Packet & convert to bytes
    decrypted_data = cipher.decrypt(data)
    decrypted_data = binascii.unhexlify(bytes(decrypted_data, encoding='utf-8'))

    # Second stage: Change source IP
    server_ip = socket.gethostbyname(socket.gethostname())

    #server_ip = '172.217.171.238'

    client_pkt = IP(decrypted_data)
    client_pkt[IP].src = server_ip

    client_pkt.show()

    # Third stage: Send packet & receive packet
    server_pkt = sr1(client_pkt)

    # Fourth stage: Encrypt packet & send to client
    server_pkt = raw(server_pkt)

    # convert bytes into string & remove the b and single quotes
    server_pkt_str = str(binascii.hexlify(server_pkt))[2:-1]

    encrypted_packet = cipher.encrypt(server_pkt_str)

    connection.send(encrypted_packet.encode(encoding='utf-8'))


def main(args: list):
    print("Running server...")

    # Get the server port
    port = int(args[1])
    key = args[2]

    # Open Socket
    main_con = socket.socket()
    main_con.bind(("localhost", port))
    main_con.listen(5)
    main_con.setblocking(False)

    # Dictionary containing sockets as keys & shared crypto keys as values
    connections_dict = {main_con: None}

    print("Server has been started!")

    # Start receiving connections & dealing with them
    while True:
        socket_list = connections_dict.keys()
        read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])

        for con in read_sockets:

            # Connection is new and we need to add it to the list
            if con == main_con:
                print("A new connection has been established")
                new_connection, addr = con.accept()
                # Usually the key is generated here, however for testings' sake
                # we will pre define it
                connections_dict[new_connection] = AESCipher(key=key)

            # Connection is not new
            else:
                try:
                    data = con.recv(2048)
                    print("Received new data")
                except ConnectionResetError:
                    con.close()
                    break

                # Connection closed - close the socket
                if not data:
                    con.close()
                    del connections_dict[con]
                    print("A connection has been closed")

                # Connection is still running - handle connection
                else:
                    handle_connection(data=data,
                                      connection=con,
                                      connections_dict=connections_dict, main_con=main_con)


if __name__ == "__main__":
    # Arguments:
    # 1) The port of the server
    # 2) The key

    main(sys.argv)