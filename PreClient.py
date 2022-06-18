from scapy.all import *
import os
import subprocess
from elevate import elevate


def set_route(route):
    # Return route to default
    os.system("route delete 0.0.0.0")
    os.system(f"route add 0.0.0.0 mask 0.0.0.0 {route}")


elevate(show_console=False)

router_ip = conf.route.route("0.0.0.0")[2]
time.sleep(4)
os.system("start /wait cmd /c py Client.py")
print("BALLS")
set_route(router_ip)