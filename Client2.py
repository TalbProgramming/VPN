from AES import AESCipher
import threading
import binascii
from scapy.all import *


def recv_packets():
    while True:
        print("Waiting for packet...")
        data = main_con.recv(1500)  # receive the packet from the server
        """
        if len(data) % 16 != 0:
            continue
        """
        decrypted_data = cipher.decrypt(data)
        decrypted_data = binascii.unhexlify(bytes(decrypted_data, encoding='utf-8'))

        pkt = Ether(decrypted_data)
        pkt.show()

        sendp(pkt, iface="coolVPN")


def on_packet_sniff(pkt):
    packet = bytes(pkt)

    # convert bytes into string & remove the b and single quotes
    packet = str(binascii.hexlify(packet))[2:-1]

    # encrypt packet
    encrypted_packet = cipher.encrypt(packet)

    # send encrypted packet
    main_con.send(encrypted_packet.encode(encoding='utf-8'))


port = 1234
key = "amongus"
cipher = AESCipher(key=key)

main_con = socket.socket()  # create tcp socket
main_con.connect(('localhost', port))  # connect to main server

threading.Thread(target=recv_packets).start()

sniff(prn=on_packet_sniff, iface="coolVPN")
