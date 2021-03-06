# import all the relevant packages
import threading
from scapy.all import *
import json
import rsa
import os
from elevate import elevate
from cryptography.fernet import Fernet
import base64
import GUI


def recv_packets():
    # a function that receives the packets from the server and sends them back to the interface
    while True:
        # receive the packet
        data = main_con.recv(1500)  # receive the packet from the server
        # decrypt the packet
        data = decrypt_packet(data, dif_hel_key, encryption_type)  # decrypt the received packet
        # change packet variables so it sends it to the interface from the computer
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

            # send the packet to the interface
            sendp(pkt, iface=vpn_interface, verbose=False)
        # if there is an error
        except Exception as e:
            # print the exception
            print(f"[Server -> Client] {e}")
            # return to the start of the loop
            continue


def on_packet_sniff(pkt):
    # a function that sends the server the packets that the client sniffs from the interface
    # sent encrypted packet
    main_con.send(encrypt_packet(bytes(pkt), dif_hel_key, encryption_type))


def bytes_xor(b1, b2):
    # Xor bytes function - https://stackoverflow.com/questions/23312571/fast-xoring-bytes-in-python-3
    parts = []
    for b1, b2 in zip(b1, b2):
        parts.append(bytes([b1 ^ b2]))
    return b''.join(parts)


def encrypt_packet(pkt, key, enc_type):
    # Encrypting a packet using the cryptography.fernet library
    # Bibliography:
    # Cryptography library information - https://cryptography.io/en/latest/
    # Creating your own fernet key - https://stackoverflow.com/questions/44432945/generating-own-key-with-python-fernet

    encrypted_packet = b""

    if enc_type == "Strong":
        # Fernet encryption

        # Convert diffie-hellman key into a valid fernet key
        f_key = base64.urlsafe_b64encode(bytes(str(key)[:32], "utf-8"))

        # Converting the key into a cryptography.fernet object
        final_key = Fernet(f_key)

        # Encrypting the packet
        encrypted_packet = final_key.encrypt(pkt)
    elif enc_type == "Weak":
        # convert the key from integer to utf-8 bytes
        x_key = bytes(str(key), "utf-8")

        # xor the bytes(key and packet)
        encrypted_packet = bytes_xor(pkt, x_key)
    else:
        # no encryption if no option has been chosen
        encrypted_packet = pkt

    return encrypted_packet


def decrypt_packet(enc_pkt, key, enc_type):
    # a function for decrypting a packet
    # Cryptography library information - https://cryptography.io/en/latest/
    # Creating your own fernet key - https://stackoverflow.com/questions/44432945/generating-own-key-with-python-fernet

    decrypted_packet = b""

    if enc_type == "Strong":
        # fernet encryption
        # Convert diffie-hellman key into a valid fernet key
        f_key = base64.urlsafe_b64encode(bytes(str(key)[:32], "utf-8"))

        # Converting the key into a cryptography.fernet object
        final_key = Fernet(f_key)

        # Decrypt the packet back to bytes
        decrypted_packet = final_key.decrypt(enc_pkt)
    if enc_type == "Weak":
        # convert the key from integer to utf-8 bytes
        x_key = bytes(str(key), "utf-8")

        # xor the bytes(key and packet)
        decrypted_packet = bytes_xor(enc_pkt, x_key)
    else:
        # just return the packet
        decrypted_packet = enc_pkt

    return decrypted_packet


def on_connect(server_ip, server_port):
    # a function responsible for the connection with the server
    # Connect to server
    try:
        # connect to the vpn server
        main_con.connect((server_ip, server_port))
    # if there is an error
    except:
        print("[Client] Failed to connect to the given IP or Port. Restarting Client...\n\n")
        return False

    print("[Client] Connected Successfully to the Server.")

    # send the server the encryption type
    main_con.send(encryption_type.encode())
    print("Sent Encryption type")

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
    dif_hel_key = key  # assign the Diffie Hellman public key
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
        # ask for input
        command = input(">")
        # if the command is not valid
        if command not in commands:
            print("[CLI] Command not found. Listing all commands:")
            commands["help"]()
            continue

        # Run Command
        commands[command]()


def start_client():
    # start the gui
    GUI.start_gui()
    # after the user closes the gui, start CLI and questions
    # clear screen
    os.system("cls")

    # cli loop
    while True:
        print("[CLI] Hello, welcome to Tal & Norel's VPN")
        print("[CLI] Please choose a mode:")
        print("  (1) Public VPN (Connect to Internet)")
        print("  (2) Custom VPN (Connect to Custom Server)")

        # user has to choose between connecting to a custom vpn or to a public vpn
        while True:
            vpn_type = input(">")
            if vpn_type == "1" or vpn_type == "2":
                break
            # if the user did not choose a valid answer
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

        # Encryption type determination from user
        print("The encryption types are 'Weak' and 'Strong'.")
        print("Strong - high security but worse internet connection.")
        print("Weak - low security but better internet connection.")
        while True:
            enc_t = input("Which one do you prefer? (W/S)")
            # if the user chose the weak encryption
            if enc_t == "W" or enc_t == "w":
                encryption_type = "Weak"
                continue
            # if the user chose the strong encryption
            elif enc_t == "S" or enc_t == "s":
                encryption_type = "Strong"
                continue
            # if the user did not choose a valid answer
            else:
                print("Answer not valid...")

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
    for command, func in commands.items():
        print("\n\n------------------------------")
        print(func(desc=True))
        print("------------------------------\n\n")


# Ask for Administrative
elevate()

# Init Parameters
with open('Client/params_client.json') as f:
    params = json.load(f)

# extract to variables from the params.json
server_port = params["port"]
server_ip = params["server_ip"]
vpn_interface = params["vpn_interface"]
main_interface = params["main_interface"]
public_key_modulus = params["public_key_modulus"]
public_key_base = params["public_key_base"]

# router addresses
router_ip = conf.route.route("0.0.0.0")[2]
router_mac = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=router_ip))[ARP].hwsrc
vpn_router_mac = "70:32:17:69:69:69"
vpn_mac = get_if_hwaddr(vpn_interface)

# encryption variables
encryption_type = "Strong"  # the default is Strong but you can change it
dif_hel_key = 0  # public variable for the diffie hellman key

# the server-client socket
main_con = socket.socket()
# threads dictionary
threads = {"recv": None, "sniff": None}  # respective keyword for each thread
# cli commands dictionary
commands = {"exit": command_exit, "help": command_help}

# Start client
start_client()
