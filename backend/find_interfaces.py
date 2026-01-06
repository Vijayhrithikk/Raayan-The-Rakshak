
from scapy.all import get_if_list, get_if_hwaddr, conf

print("Available Interfaces for Scapy:")
for iface in get_if_list():
    try:
        print(f"Name: '{iface}'")
        # print(f"MAC: {get_if_hwaddr(iface)}")
    except:
        pass
print(f"Scapy Default: {conf.iface}")
