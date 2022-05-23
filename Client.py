import threading
import binascii
from scapy.all import *
import GUIObjects
from PyQt5 import QtWidgets
import json
import rsa
import os
from elevate import elevate


def recv_packets():
    while True:
        data = main_con.recv(1500)  # receive the packet from the server
        try:
            pkt = Ether(data)

            if Ether in pkt:
                pkt[Ether].src = vpn_router_mac
                pkt[Ether].dst = vpn_mac
                pkt[Ether].chksum = None

            if IP in pkt:
                pkt[IP].chksum = None
                pkt[IP].dst = "10.0.0.69"

            if UDP in pkt:
                pkt[UDP].chksum = None

            if TCP in pkt:
                pkt[TCP].chksum = None

            sendp(pkt, iface=vpn_interface, verbose=False)
        except Exception as e:
            print(f"[Server -> Client] {e}")
            continue


def on_packet_sniff(pkt):

#    if Ether in pkt:
#        pkt[Ether].dst = router_mac

    packet = bytes(pkt)
    main_con.send(packet)


def on_connect():
    """
        Function that handles what occurs once the user
        presses "Connect" on GUI and until the client closes
    """
    global cipher

    # Connect to server
    main_con.connect((server_ip, port))

    # ----RSA Authentication Start----
    # Receive public key
    rsa_public_key = rsa.key.PublicKey.load_pkcs1(main_con.recv(1500), format='DER')
    print("RSA: Received public key from server...")

    # Receive signature
    signature = main_con.recv(1500)
    print("RSA: Received digital signature from server...")

    # Verify Signature
    try:
        message = "AMONGUS".encode()
        rsa.verify(message, signature, rsa_public_key)
    except:
        print("RSA: Verification Failed. Closing Client")
        main_con.close()
        window.close()
        exit()

    print("RSA: Verification Successful")

    # If success, send to server
    main_con.send("success".encode())
    # ---- RSA Authentication End----

    # ----Diffie-Hellman Key Exchange Start----
    secret_number = random.randint(100, 5000)

    main_con.send(str(pow(public_key_base, secret_number) % public_key_modulus).encode())
    print("DH: Sent Calculation to Server")

    server_calc = int(main_con.recv(1500).decode())
    print("DH: Received Calculation from Server")

    key = pow(server_calc, secret_number) % public_key_modulus
    print(key)

    # ----Diffie-Hellman Key Exchange End----

    # Change default packet routing to the VPN custom interface
    os.system("route delete 0.0.0.0")
    os.system("route add 0.0.0.0 mask 0.0.0.0 10.0.0.1")
    print("VPN Turned on. This only works if ran in administrative mode")

    # Start receiving packets from server
    thread_recv = threading.Thread(target=recv_packets)
    threads["recv"] = thread_recv
    thread_recv.start()

    # Start sniffing packets from custom interface
    thread_sniff = threading.Thread(target=lambda: sniff(prn=on_packet_sniff, iface=vpn_interface))
    threads["sniff"] = thread_sniff
    thread_sniff.start()


def on_exit():
    """
        Function that handles what occurs when the
        client is closed.
        Threads need to be stopped first before connection
        closes so no errors occur
    """

    print("Exiting")

    # Stop both threads
    #threads["recv"].join()
    #threads["sniff"].join()

    # Close the connection to the server
    main_con.close()

    # Return mask to default
    os.system("route delete 0.0.0.0")
    os.system(f"""netsh interface ipv4 set address name="{main_interface}" source=dhcp""")
    os.system("ipconfig /renew")

    exit()


# Ask for Administrative
elevate()

# Init Parameters for client
with open('params.json') as f:
    params = json.load(f)

port = params["port"]
server_ip = params["server_ip"]
vpn_interface = params["vpn_interface"]
main_interface = params["main_interface"]
public_key_modulus = params["public_key_modulus"]
public_key_base = params["public_key_base"]


router_ip = conf.route.route("0.0.0.0")[2]
router_mac = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip))[ARP].hwsrc
vpn_router_mac = "70:32:17:69:69:69"
vpn_mac = get_if_hwaddr(vpn_interface)

main_con = socket.socket()
threads = {"sniff": None, "recv": None}  # respective keyword for each thread
cipher = None

# Start GUI
app = QtWidgets.QApplication(sys.argv)
window = GUIObjects.MainWindow(on_exit=on_exit, on_connect=on_connect)
window.show()

ret = app.exec_()
on_exit()
sys.exit(ret)