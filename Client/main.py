import scapy
from scapy.all import *
import os
import ctypes


def set_route(route):
    # Return route to default
    os.system("route delete 0.0.0.0")
    os.system(f"route add 0.0.0.0 mask 0.0.0.0 {route}")


def main():

    if not ctypes.windll.shell32.IsUserAnAdmin():
        print("Please run the program in Administrator mode.")
        input("Press enter to exit")
        exit()

    router_ip = conf.route.route("0.0.0.0")[2]
    os.system("start /wait cmd /c py Client.py")
    set_route(router_ip)


if __name__ == "__main__":
    main()