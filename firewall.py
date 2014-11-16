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
        self.rule_fields = ["verdict", "protocol", "extIP", "ext_port"]


        # TODO: Load the firewall rules (from rule_filename) here.
        self.rules = []

        """lines = [line.strip() for line in open(config['rules'])]
        for l in lines:
            if len(l) > 0 and l[0] != '%':
                self.rules.append(l)"""

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
        ip_info, transport_info = self.parse_pkt(pkt)
        if ip_info["protocol"][1] == 17 and transport_info["dst"][1] == 53:
            print transport_info["dst"][1]


    # TODO: You can add more methods as you want.
    def parse_pkt(self, pkt):
        pkt_IP_info = dict()
        pkt_transport_info = dict()
        pkt_IP_info["ihl"] = ( format(int(struct.unpack('!B', pkt[0])[0]) & 0x0F, '02x'), int(struct.unpack('!B', pkt[0])[0]) & 0x0F)
        pkt_IP_info["ID"] = (format(int(struct.unpack('!H', pkt[4:6])[0]), '02x'), int(struct.unpack('!H', pkt[4:6])[0]))
        pkt_IP_info["protocol"] = (format(int(struct.unpack('!B', pkt[9:10])[0]),'02x'),int(struct.unpack('!B',pkt[9:10])[0]))
        pkt_IP_info["sIP"] = (format(int(struct.unpack('!L', pkt[12:16])[0]), '02x'), socket.inet_ntoa(pkt[12:16]))
        pkt_IP_info["dIP"] = (format(int(struct.unpack('!L', pkt[16:20])[0]), '02x'), socket.inet_ntoa(pkt[16:20]))
        #print pkt_IP_info["ihl"], pkt_IP_info["ID"],  pkt_IP_info["sIP"],pkt_IP_info["dIP"], pkt_IP_info["protocol"]
        transport_offset = pkt_IP_info["ihl"][1] * 4
        if pkt_IP_info["protocol"][1] == 6 or pkt_IP_info["protocol"][1] == 17:
            pkt_transport_info["src"] = (format(int(struct.unpack('!H', pkt[transport_offset:transport_offset + 2])[0]), '02x'), int(struct.unpack('!H', pkt[transport_offset:transport_offset + 2])[0]))
            pkt_transport_info["dst"] = (format(int(struct.unpack('!H', pkt[transport_offset+2:transport_offset + 4])[0]), '02x'), int(struct.unpack('!H', pkt[transport_offset+2:transport_offset + 4])[0]))
            if pkt_IP_info["protocol"][1] == 17 and pkt_transport_info["dst"][1] == 53:
                dns_offset = 32 + transport_offset
                pkt_transport_info["qdcount"] = (format(int(struct.unpack('!H', pkt[dns_offset+4:dns_offset+6])[0]), '02x'), int(struct.unpack('!H', pkt[dns_offset+4:dns_offset+6])[0]))
                dns_question_offset = dns_offset + 12 
                pkt_transport_info["qname"] = (format(int(struct.unpack('!H', pkt[dns_question_offset:dns_question_offset+2])[0]), '02x'), int(struct.unpack('!H', pkt[dns_question_offset:dns_question_offset+2])[0]))
                pkt_transport_info["qtype"] = (format(int(struct.unpack('!H', pkt[dns_question_offset+2:dns_question_offset+4])[0]), '02x'), int(struct.unpack('!H', pkt[dns_question_offset+2:dns_question_offset+4])[0]))
                pkt_transport_info["qclass"] = (format(int(struct.unpack('!H', pkt[dns_question_offset+4:dns_question_offset+6])[0]), '02x'), int(struct.unpack('!H', pkt[dns_question_offset+4:dns_question_offset+6])[0]))

        elif pkt_IP_info["protocol"][1] == 1:
            pkt_transport_info["type"] = (format(int(struct.unpack('!B', pkt[transport_offset:transport_offset + 1])[0]), '02x'), int(struct.unpack('!B', pkt[transport_offset:transport_offset + 1])[0]))
            
        return pkt_IP_info, pkt_transport_info

        
    #def packet_valid(self, pkt_dir, pkt):
    # TODO: You may want to add more classes/functions as well.
