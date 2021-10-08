import os
import platform
import time

from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp

from tplinkshutdown.restarter import restart
from tplinkshutdown.return_codes import exit_wrong_arguments

import sys
import getopt
import dns.resolver


def print_usage():
    print('Restarts TL-WPA8630 with <ip> using <password>. It can optionally restart the powerline adapter only if fails 5 ping attempts to <healthip>.')
    print('tplinkshutdown.py -p <password> -i <ip> [-r <ip>]')
    print('tplinkshutdown.py --password=<password> --ip=<ip> [healthip=<ip>]')
    print('tplinkshutdown.py -p <password> -o <hostname> [-r <ip>]')
    print('tplinkshutdown.py --password=<password> --hostname=<hostname> [healthip=<ip>]')
    print('tplinkshutdown.py -p <password> -m <macaddress> [-r <ip>]')
    print('tplinkshutdown.py --password=<password> --mac=<macaddress> [healthip=<ip>]')

def main():  # type: () -> None

    username: str = ''
    password = ''
    base_url: str = ''
    health_check_ip: str = ''
    ntries: int = 5

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hp:i:r:o:m:", ["password=", "ip=", "healthip=", "hostname=", "mac="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(exit_wrong_arguments)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-p", "--password"):
            password = arg
        elif opt in ("-i", "--ip"):
            base_url = 'http://' + arg
        elif opt in ("-o", "--hostname"):
            answers = dns.resolver.resolve(arg, dns.rdatatype.A)
            # TODO first? last? which?
            for rdata in answers:
                base_url = 'http://' + rdata.address
        elif opt in ("-m", "--mac"):
            # TODO user defined network
            answered, unanswered = srp(Ether(dst=arg) / ARP(pdst="192.168.0.0/24"), timeout=2)
            for snd, rcv in answered:
                base_url = 'http://' + rcv.psrc
        elif opt in ("-r", "--healthip"):
            health_check_ip = arg

    if not password or not base_url:
        print_usage()
        sys.exit(exit_wrong_arguments)

    if health_check_ip:
        i: int = 0
        print('Pinging health ip')
        while i < ntries:
            print('Ping '+str(i)+' of '+str(ntries))
            # Send one packet only
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            # Windows this function will still return True if you get a Destination Host Unreachable error!!!
            response = os.system("ping " + param + " 1 " + health_check_ip)
            # and then check the response...
            if response == 0:
                print('Successfully pinged. Exiting...')
                sys.exit(0)
            else:
                time.sleep(5)
            i += 1

    print('Restarting the powerline adapter')
    result: int = restart(username, password, base_url)

    if result != 0:
        # Something went wrong: print error code
        sys.exit(result)


if __name__ == "__main__":
    main()
