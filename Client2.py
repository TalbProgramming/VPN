from AES import AESCipher
import socket, sys
import binascii
from scapy.all import *


def main(args: list):
    port = int(args[1])
    key = args[2]

    main_con = socket.socket()  # create tcp socket
    main_con.connect(('localhost', port))  # connect to main server

    dest_ip = '172.217.171.238'

    packet = IP(dst=dest_ip)/ICMP(type='echo-request')/Raw(b'Hello Yehuda!')
    packet = raw(packet)


    # convert bytes into string & remove the b and single quotes
    packet = str(binascii.hexlify(packet))[2:-1]

    # create cipher
    cipher = AESCipher(key=key)

    # encrypt packet
    encrypted_packet = cipher.encrypt(packet)

    # send encrypted packet
    main_con.send(encrypted_packet.encode(encoding='utf-8'))

    data = main_con.recv(2048)  # receive the packet from the server

    decrypted_data = cipher.decrypt(data)
    decrypted_data = binascii.unhexlify(bytes(decrypted_data, encoding='utf-8'))

    pkt = IP(decrypted_data)
    pkt.show()

    main_con.close()


if __name__ == "__main__":
    main(sys.argv)
