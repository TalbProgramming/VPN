import threading
from scapy.all import *
import binascii
import json
import rsa
from cryptography.fernet import Fernet
import base64


# Receive from client
def handle_connection():

    try:
        client_pkt = Ether(data)

        if Ether in client_pkt:
            client_pkt[Ether].src = get_if_hwaddr(interface)
            client_pkt[Ether].dst = router_mac
            client_pkt[Ether].chksum = None

        if IP in client_pkt:
            client_pkt[IP].chksum = None
            client_pkt[IP].src = get_if_addr(interface)

        if UDP in client_pkt:
            client_pkt[UDP].chksum = None

        if TCP in client_pkt:
            client_pkt[TCP].chksum = None

        #client_pkt.show()

        # Third stage: Send packet to WWW
        sendp(client_pkt, iface=interface, verbose=False)
    except Exception as e:
        print(f"[Client -> Server]: {e}")


# Function that receives all incoming packets from WWW
def recv_pkts(pkt):

    if IP not in pkt:
        return

    if pkt[IP].src == get_if_addr(interface):
        return

    try:
        encrypted_packet = encrypt_packet(bytes(pkt), dif_hel_key, encryption_type)
        con.send(encrypted_packet)
    except:
        print("[SERVER] Error ENCRYPTING packet headed to Client")
        return


def bytes_xor(b1, b2):
    # a function that Xors two bytes
    # Credit to - https://stackoverflow.com/questions/23312571/fast-xoring-bytes-in-python-3
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)


def encrypt_packet(pkt, diffie_key, enc_type):
    # Encrypting a packet using the cryptography.fernet library or a Xor function
    # Bibliography:
    # Cryptography library information - https://cryptography.io/en/latest/
    # Creating your own fernet key - https://stackoverflow.com/questions/44432945/generating-own-key-with-python-fernet

    if enc_type == "Strong":
        # Fernet encryption

        # Convert diffie-hellman key into a valid fernet key
        conv_dh = str(key).encode()
        conv_dh_padded = conv_dh + bytes(32 - len(conv_dh))
        f_key = base64.urlsafe_b64encode(conv_dh_padded)


        # Converting the key into a cryptography.fernet object
        final_key = Fernet(f_key)

        # Encrypting the packet
        return final_key.encrypt(pkt)

    elif enc_type == "Weak":
        # convert the key from integer to utf-8 bytes
        x_key = bytes(str(diffie_key), "utf-8")

        # xor the bytes(key and packet)
        return bytes_xor(pkt, x_key)

    return pkt


def decrypt_packet(enc_pkt, diffie_key, enc_type):
    # a function for decrypting a packet

    if enc_type == "Strong":
        # fernet encryption
        # Convert diffie-hellman key into a valid fernet key
        conv_dh = str(key).encode()
        conv_dh_padded = conv_dh + bytes(32 - len(conv_dh))
        f_key = base64.urlsafe_b64encode(conv_dh_padded)

        # Converting the key into a cryptography.fernet object
        final_key = Fernet(f_key)

        # Decrypt the packet back to bytes
        return final_key.decrypt(enc_pkt)

    elif enc_type == "Weak":
        # convert the key from integer to utf-8 bytes
        x_key = bytes(str(diffie_key), "utf-8")

        # xor the bytes(key and packet)
        return bytes_xor(enc_pkt, x_key)

    return enc_pkt


print("Running server...")

# Init Parameters
with open('Server/params_server.json') as f:
    params = json.load(f)

port = params["port"]
server_ip = params["server_ip"]
interface = params["main_interface"]
public_key_modulus = params["public_key_modulus"]
public_key_base = params["public_key_base"]

# encryption variables
encryption_type = "Strong"  # strong is default encryption

router_ip = conf.route.route("0.0.0.0")[2]
router_mac = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip))[ARP].hwsrc

# Open Socket
main_con = socket.socket()
main_con.bind((server_ip, port))
main_con.listen(5)

print("Server has been started!")

# Start receiving connection & dealing with them
while True:

    # Wait for a connection
    con, addr = main_con.accept()

    # receive encryption type from client
    encryption_type = con.recv(1500).decode()
    print("Received encryption type.")

    # ----RSA Authentication Start----
    (rsa_public_key, rsa_private_key) = rsa.newkeys(512)
    print(rsa_public_key)


    # Send Public key to client
    con.send(rsa_public_key.save_pkcs1(format='DER'))
    print("RSA: Sent public key to client...")

    # Sign digital signature & send to client
    message = "AMONGUS".encode()
    signature = rsa.sign(message, rsa_private_key, 'SHA-1')

    con.send(signature)
    print("RSA: Sent digital signature to client...")

    # Wait for answer
    success = con.recv(1500).decode()
    print("RSA: Received answer from client...")
    if not success:
        print("RSA: Client closed connection")
        con.close()
        continue

    print("RSA: Client Successfully Connected!")
    # ----RSA Authentication End----

    # ----Diffie-Hellman Key Exchange Start----
    secret_number = random.randint(100, 5000)

    # Receive DH Client Calculation
    client_calc = con.recv(1500)
    try:
        client_calc = rsa.decrypt(client_calc, rsa_private_key)
    except Exception:
        print("Error Decrypting DH Client Calculation using RSA Priv Key. Connection Closed")
        con.close()
        continue

    client_calc = int(client_calc.decode("utf-8"))
    print("DH: Received Calculation from Client")

    con.send(str(pow(public_key_base, secret_number) % public_key_modulus).encode())
    print("DH: Sent Calculation to Client")

    key = pow(client_calc, secret_number) % public_key_modulus
    dif_hel_key = key
    print(key)

    # ---- Diffie-Hellman Key Exchange End----

    # Start thread that will receive incoming packets from WWW
    thread = threading.Thread(target=lambda: sniff(prn=recv_pkts, iface=interface))
    thread.start()

    # When getting packet from client, send it to WWW
    while True:
        data = con.recv(1500)
        try:
            data = decrypt_packet(data, dif_hel_key, encryption_type)
        except Exception:
            print("[SERVER] Error DECRYPTING packet coming from Client")
            continue

        handle_connection()
