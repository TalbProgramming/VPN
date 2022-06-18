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
import atexit


def recv_packets():
    # a function that receives the packets from the server and sends them back to the interface
    while True:
        # receive the packet
        data = main_con.recv(4092)  # receive the packet from the server
        # decrypt the packet
        try:
            data = decrypt_packet(data, dif_hel_key, encryption_type)  # decrypt the received packet
        except Exception:
            continue

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
#    if IP not in pkt:
#        return

#    if pkt[IP].dst == "10.0.0.69":
#        return

    try:
        main_con.send(encrypt_packet(bytes(pkt), dif_hel_key, encryption_type))
    except Exception:
        print("[CLIENT] Error ENCRYPTING packet headed to Server")


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

    global fernet_obj

    if enc_type == "Strong":
        # Fernet encryption
        return fernet_obj.encrypt(pkt)

    elif enc_type == "Weak":
        # convert the key from integer to utf-8 bytes
        x_key = bytes(str(key), "utf-8")

        # xor the bytes(key and packet)
        return bytes_xor(pkt, x_key)

    return pkt


def decrypt_packet(enc_pkt, key, enc_type):
    # a function for decrypting a packet
    # Cryptography library information - https://cryptography.io/en/latest/
    # Creating your own fernet key - https://stackoverflow.com/questions/44432945/generating-own-key-with-python-fernet

    global fernet_obj

    if enc_type == "Strong":
        # fernet encryption
        return fernet_obj.decrypt(enc_pkt)

    if enc_type == "Weak":
        # convert the key from integer to utf-8 bytes
        x_key = bytes(str(key), "utf-8")

        # xor the bytes(key and packet)
        return bytes_xor(enc_pkt, x_key)

    return enc_pkt


def on_connect(server_ip, server_port):
    global dif_hel_key
    global fernet_obj

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

    # Calculate DH Client Number & encode it using UTF8
    client_calc = str(pow(public_key_base, secret_number) % public_key_modulus)
    client_calc = rsa.encrypt(client_calc.encode("utf-8"), rsa_public_key)
    main_con.send(client_calc)
    print("[Client] DH: Sent Calculation to Server")

    server_calc = int(main_con.recv(1500).decode())
    print("[Client] DH: Received Calculation from Server")

    key = pow(server_calc, secret_number) % public_key_modulus
    dif_hel_key = key  # assign the Diffie Hellman public key
    print(key)

    # ----Diffie-Hellman Key Exchange End----

    print("[Client] DH Key Exchange Successful. Starting VPN Tunnel...")

    # Create fernet object
    if encryption_type == "Strong":
        conv_dh = str(dif_hel_key).encode()
        conv_dh_padded = conv_dh + bytes(32 - len(conv_dh))
        f_key = base64.urlsafe_b64encode(conv_dh_padded)

        # Converting the key into a cryptography.fernet object
        fernet_obj = Fernet(f_key)

    # Change default packet routing to the VPN custom interface
    set_route("10.0.0.1")
    print("VPN Turned on. This only works if ran in administrative mode")

    # Start receiving packets from server
    thread_recv = threading.Thread(target=recv_packets)
    thread_recv.daemon = True
    threads["recv"] = thread_recv
    thread_recv.start()

    thread_sniff = threading.Thread(target=lambda: sniff(prn=on_packet_sniff, iface=vpn_interface))
    thread_sniff.daemon = True
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
    global encryption_type

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

        # Encryption type determination from user
        print("The encryption types are 'Weak' and 'Strong'.")
        print("Strong - high security but worse internet connection.")
        print("Weak - low security but better internet connection.")
        while True:
            enc_t = input("Which one do you prefer? (W/S)")
            # if the user chose the weak encryption
            if enc_t == "W" or enc_t == "w":
                encryption_type = "Weak"
                break
            # if the user chose the strong encryption
            elif enc_t == "S" or enc_t == "s":
                encryption_type = "Strong"
                break
            # if the user did not choose a valid answer
            else:
                print("Answer not valid...")

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
    exit()


def set_route(route):
    # Return route to default
    os.system("route delete 0.0.0.0")
    os.system(f"route add 0.0.0.0 mask 0.0.0.0 {route}")


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
#elevate()


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
fernet_obj = None

# the server-client socket
main_con = socket.socket()
# threads dictionary
threads = {"recv": None, "sniff": None}  # respective keyword for each thread
# cli commands dictionary
commands = {"exit": command_exit, "help": command_help}

# Start client
start_client()

# "public_key_modulus": 29962952566537595616580074691715715004471020966166863905219015471793104056642460920814497981480604316263906184613054344382075683052568773100732190701675817198195462182932917209076240513582481206090136343825410554993583246668890469709338955286428207238023518271992086860960511209511846290487309812676928740833673393588317235478023683621400408451938599052504549316739582087942516841975677097631032320460944929677827207667362551202440116275880718385985824859905900492529122669495490989816062979221701445277197457023765977676834234103232590600247983503938323988194710465088854492546408495981693179127947462979718935701783,
#  "public_key_base": 14981476283268797808290037345857857502235510483083431952609507735896552028321230460407248990740302158131953092306527172191037841526284386550366095350837908599097731091466458604538120256791240603045068171912705277496791623334445234854669477643214103619011759135996043430480255604755923145243654906338464370416836696794158617739011841810700204225969299526252274658369791043971258420987838548815516160230472464838913603833681275601220058137940359192992912429952950246264561334747745494908031489610850722638598728511882988838417117051616295300123991751969161994097355232544427246273204247990846589563973731489859467850891
