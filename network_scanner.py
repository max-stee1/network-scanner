import argparse
import subprocess
import scapy.all as scapy
# import optparse
import os

def sudo_permission():
    if not 'SUDO_UID' in os.environ.keys():
        print("Try running this program with sudo")
        exit()

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Use this for select target")
    options = parser.parse_args()
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast =  scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    client_list = []



    for element in answered_list:
        try:
            ping = str(subprocess.check_output("ping " + element[1].psrc +" -c 1 | grep ttl", shell=True))
        except:
            ping = " ttl=8575 dsgdg"
        a = ping.split("ttl=")
        b = a[1].split(" ")
        c = int(b[0])

        output = "Unknown"

        if c == 128:
            output = "windows"
        elif c == 64:
            output = "Linux"
        elif c == 255:
            output = "Cisco Router (IOS 12.4)"
        client_dic = {"ip": element[1].psrc, "mac": element[1].hwsrc, "os": output}
        client_list.append(client_dic)
    return client_list

def print_result(result_list):
    print("IP\t\t\tMAC\t\t\t\t\tOS\n..............................................................................")
    for client in result_list:
        print(client['ip'] + '\t\t' + client['mac'] + '\t\t' + client['os'])

sudo_permission()
options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
