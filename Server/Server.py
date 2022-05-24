import threading
from scapy.all import *
import binascii
import json
import rsa


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

    encrypted_packet = bytes(pkt)
    con.send(encrypted_packet)



print("Running server...")

# Init Parameters
with open('Server/params_server.json') as f:
    params = json.load(f)

port = params["port"]
server_ip = params["server_ip"]
interface = params["main_interface"]
public_key_modulus = params["public_key_modulus"]
public_key_base = params["public_key_base"]

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

    # ----RSA Authentication Start----
    (rsa_public_key, rsa_private_key) = rsa.newkeys(512)

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

    client_calc = int(con.recv(1500).decode())
    print("DH: Received Calculation from Client")

    con.send(str(pow(public_key_base, secret_number) % public_key_modulus).encode())
    print("DH: Sent Calculation to Client")

    key = pow(client_calc, secret_number) % public_key_modulus
    print(key)

    # ---- Diffie-Hellman Key Exchange End----

    # Start thread that will receive incoming packets from WWW
    thread = threading.Thread(target=lambda: sniff(prn=recv_pkts, iface=interface))
    thread.start()

    # When getting packet from client, send it to WWW
    while True:
        data = con.recv(1500)
        handle_connection()