#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct # parse binary
import socket 

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # TODO: Load the firewall rules (from rule_filename) here.
        self.rules = []

        lines = [line.strip() for line in open(config['rule'])]
        for l in lines:
            if len(l) > 0 and l[0] != '%':
                self.rules.append(l)

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        self.geoIP = []
        ip_lines = [ip_line.strip() for ip_line in open('geoipdb.txt')]
        for ip_l in ip_lines:
            if len(ip_l) > 0 and ip_l[0] != '%':
                self.geoIP.append(ip_l)
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        
        if self.packet_valid(pkt_dir, pkt):

            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send(pkt)
            else:
                self.iface_ext.send(pkt)

    # TODO: You can add more methods as you want.
    def parse_pkt(self, packet):
        pkt_info = dict()
        # IPv4 
        header_valid = struct.unpack('B', packet[0])[0]
        if (header_valid & 0b11000 == 4) and (header_valid & 0b0111) > 4: # not a valid packet
             return None
        fields = struct.unpack('!BBHHHBBHII', packet[:20])
        pkt_info['v'] = fields[0] & 0b1100
        pkt_info['hl'] = fields[0] & 0b0111
        pkt_info['tos'] = fields[1]
        pkt_info['len'] = fields[2]
        pkt_info['id'] = fields[3]
        pkt_info['flags'] = fields[4] >> 13 # right shift operator
        pkt_info['off'] = fields[4] & 0x1fff
        pkt_info['ttl'] = fields[5]
        pkt_info['p'] = fields[6]
        pkt_info['sum'] = fields[7]
        pkt_info['src'] = socket.inet_ntoa(fields[8])
        pkt_info['dst'] = socket.inet_ntoa(fields[9])

        return pkt_info

    def packet_valid(self, pkt_dir, pkt):
        '''
        for each packet that comes through, checks validity 
        against parsed rules and returns boolean if packet can
        be passed or not
        '''
       pkt_info = self.parse_pkt(pkt)
       
       print pkt_info


    def parse_rules():
        '''
        '''


    def get_cc(self, query_ip):
        '''
        Because the ip addresses are sorted,
        we will perform binary search to retrieve
        the correct 2-byte country code
        '''
        q_ip_num = struct.unpack('!L', socket.inet_aton(query_ip))[0]
        lo, hi = 0, len(self.geoIP)-1
        while lo < hi:
            mid = (hi+lo)//2
            mid_bin_ip = socket.inet_aton(self.geoIP[mid].split()[1])
            mid_ip = struct.unpack('!L', mid_bin_ip)[0]
            if q_ip_num > mid_ip:
                lo = mid+1
            elif q_ip_num < mid_ip:
                hi = mid-1
            else:
                country_code = self.geoIP[mid].split()[2]
                return country_code



