import threading
from scapy.all import *
import json
import rsa
import os
from elevate import elevate


from cryptography.fernet import Fernet
import base64
#  encryption research paper - https://arxiv.org/pdf/1704.08688.pdf
#  cryptography library information - https://cryptography.io/en/latest/
#  creating your own fernet key - https://stackoverflow.com/questions/44432945/generating-own-key-with-python-fernet
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
    main_con.send(bytes(pkt))


def encrypt_packet(pkt, key):
    # Encrypting a packet using the cryptography.fernet library
    # Bibliography
    # Cryptography library information - https://cryptography.io/en/latest/
    # Creating your own fernet key - https://stackoverflow.com/questions/44432945/generating-own-key-with-python-fernet
    """
    <<< IF NEEDED FUNCTIONS>>>

    # convert scapy packet to string
    s_pkt = str(pkt)

    # convert string packet bto bytes
    b_pkt = bytes(s_pkt, "utf-8")
    """
    # Convert diffie-hellman key into a valid fernet key
    f_key = base64.urlsafe_b64encode(bytes(str(key)[:32], "utf-8"))

    # Converting the key into a cryptography.fernet object
    final_key = Fernet(f_key)

    # Encrypting the packet
    encrypted_packet = final_key.encrypt(pkt)
    return encrypted_packet


def decrypt_packet(enc_pkt, key):
    # Convert diffie-hellman key into a valid fernet key
    f_key = base64.urlsafe_b64encode(bytes(str(key)[:32], "utf-8"))

    # Converting the key into a cryptography.fernet object
    final_key = Fernet(f_key)

    # Decrypt the packet back to bytes
    decrypted_packet = final_key.decrypt(enc_pkt)
    return decrypted_packet


def on_connect(server_ip, server_port):
    """
        Function that handles what occurs once the user
        presses "Connect" on GUI and until the client closes
    """
    global cipher

    # Connect to server
    try:
        main_con.connect((server_ip, server_port))
    except:
        print("[Client] Failed to connect to the given IP or Port. Restarting Client...\n\n")
        return False

    print("[Client] Connected Successfully to the Server.")

    # ----RSA Authentication Start----
    # Receive public key
    rsa_public_key = rsa.key.PublicKey.load_pkcs1(main_con.recv(1500), format='DER')
    print("[Client] RSA: Received public key from server...")

    # Receive signature
    signature = main_con.recv(1500)
    print("[Client] RSA: Received digital signature from server...")

    # Verify Signature
    try:
        message = "AMONGUS".encode()
        rsa.verify(message, signature, rsa_public_key)
    except:
        print("[Client] RSA: Verification Failed. Restarting Client...")
        return False

    print("[Client] RSA: Verification Successful. Beginning DH Key Exchange")

    # If success, send to server
    main_con.send("success".encode())
    # ---- RSA Authentication End----

    # ----Diffie-Hellman Key Exchange Start----
    secret_number = random.randint(100, 5000)

    main_con.send(str(pow(public_key_base, secret_number) % public_key_modulus).encode())
    print("[Client] DH: Sent Calculation to Server")

    server_calc = int(main_con.recv(1500).decode())
    print("[Client] DH: Received Calculation from Server")

    key = pow(server_calc, secret_number) % public_key_modulus
    print(key)

    # ----Diffie-Hellman Key Exchange End----

    print("[Client] DH Key Exchange Successful. Starting VPN Tunnel...")

    # Change default packet routing to the VPN custom interface
    os.system("route delete 0.0.0.0")
    os.system("route add 0.0.0.0 mask 0.0.0.0 10.0.0.1")
    print("VPN Turned on. This only works if ran in administrative mode")

    # Start receiving packets from server
    thread_recv = threading.Thread(target=recv_packets)
    threads["recv"] = thread_recv
    thread_recv.start()

    thread_sniff = threading.Thread(target=lambda: sniff(prn=on_packet_sniff, iface=vpn_interface))
    threads["sniff"] = thread_sniff
    thread_sniff.start()

    print("[Client] VPN Tunnel Successfully online.")
    return True


def start_cli():
    print("\n\n[CLI] Please enter a command or type 'help' for a list of commands")
    while True:
        command = input(">")
        if command not in commands:
            print("[CLI] Command not found. Listing all commands:")
            commands["help"]()
            continue

        # Run Command
        commands[command]()


def start_client():
    os.system("cls")

    while True:
        print("[CLI] Hello, welcome to Tal & Norel's VPN")
        print("[CLI] Please choose a mode:")
        print("  (1) Public VPN (Connect to Internet)")
        print("  (2) Custom VPN (Connect to Custom Server)")

        while True:
            vpn_type = input(">")
            if vpn_type == "1" or vpn_type == "2":
                break
            else:
                print("[CLI] Please Choose a Displayed Answer:")

        # If Custom, ask for IP & Port
        if vpn_type == "2":
            # IP
            print("\n[CLI] Please enter the IP Address of the server:")
            vpn_ip = input(">")

            # Port
            print("\n[CLI] Please enter the Port of the server:")
            vpn_port = input(">")

        # If Public, use the default
        else:
            vpn_ip = server_ip
            vpn_port = server_port

        success = on_connect(server_ip=vpn_ip, server_port=vpn_port)

        # If failed to connect, retry client
        if not success:
            continue

        # If succeeded, exit loop & start CLI
        break

    start_cli()


# Command Functions

def command_exit(desc=False):
    if desc:
        return """
           Command: Exit Client
           Usage: exit
           Description: Closes connection to the VPN Server & exits the client.
           """

    # ----------------------- Begin Command -----------------------

    print("Exiting Client...")

    # Close the connection to the server
    main_con.close()

    # Return mask to default
    os.system("route delete 0.0.0.0")
    os.system(f"""netsh interface ipv4 set address name="{main_interface}" source=dhcp""")
    os.system("ipconfig /renew")
    exit()


def command_help(desc=False):
    if desc:
        return """
           Command: Help
           Usage: help
           Description: Shows all commands, their usage, and gives a description of what each command does.
           """

    # ----------------------- Begin Command -----------------------
    print("[CLI] Listing all commands:")
    for command,func in commands.items():
        print("\n\n------------------------------")
        print(func(desc=True))
        print("------------------------------\n\n")


# Ask for Administrative
elevate()

# Init Parameters
with open('Client/params_client.json') as f:
    params = json.load(f)

server_port = params["port"]
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
threads = {"recv": None, "sniff": None}  # respective keyword for each thread
commands = {"exit": command_exit, "help": command_help}

# Start client
start_client()
