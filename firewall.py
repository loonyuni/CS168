#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct # parse binary
import socket 
import fnmatch

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.valid_protocols = {'icmp': 1, 'tcp': 6, 'udp': 17}
        # TODO: Load the firewall rules (from rule_filename) here.
        self.rules = []

        lines = [line.strip() for line in open(config['rule'])]
        for l in lines:
            if len(l) > 0 and l[0] != '%':
                self.rules.append(l)

        # TODO: Load the GeoIP DB ('geoipdb.txt') as well.
        self.geoIP = []
        f = open('geoipdb.txt', 'r')
        for line in f:
            if len(line) > 0 and line[0] != '%':
                self.geoIP.append(line.split(' '))
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        if self.packet_valid(pkt_dir, pkt):
            print "////////////////"
            print "// PASSED!! :)//"
            print "////////////////"
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            else:
                self.iface_ext.send_ip_packet(pkt)
        else:
            print "*****************"
            print "* DID NOT PASS  *"
            print "*****************"
    # TODO: You can add more methods as you want.
    def parse_pkt(self, pkt):
        pkt_IP_info = dict()
        pkt_transport_info = dict()
        pkt_IP_info["ihl"] = ( format(int(struct.unpack('!B', pkt[0])[0]) & 0x0F, '02x'), int(struct.unpack('!B', pkt[0])[0]) & 0x0F)
        pkt_IP_info["ID"] = (format(int(struct.unpack('!H', pkt[4:6])[0]), '02x'), int(struct.unpack('!H', pkt[4:6])[0]))
        pkt_IP_info["protocol"] = (format(int(struct.unpack('!B', pkt[9:10])[0]),'02x'),int(struct.unpack('!B',pkt[9:10])[0]))
        pkt_IP_info["sIP"] = (format(int(struct.unpack('!L', pkt[12:16])[0]), '02x'), socket.inet_ntoa(pkt[12:16])) # source
        pkt_IP_info["dIP"] = (format(int(struct.unpack('!L', pkt[16:20])[0]), '02x'), socket.inet_ntoa(pkt[16:20])) # destination
        transport_offset = pkt_IP_info["ihl"][1] * 4
        if pkt_IP_info["protocol"][1] == 6 or pkt_IP_info["protocol"][1] == 17:
            pkt_transport_info["src"] = (format(int(struct.unpack('!H', pkt[transport_offset:transport_offset + 2])[0]), '02x'), int(struct.unpack('!H', pkt[transport_offset:transport_offset + 2])[0]))
            pkt_transport_info["dst"] = (format(int(struct.unpack('!H', pkt[transport_offset+2:transport_offset + 4])[0]), '02x'), int(struct.unpack('!H', pkt[transport_offset+2:transport_offset + 4])[0]))
            if pkt_IP_info["protocol"][1] == 17 and pkt_transport_info["dst"][1] == 53:
                dns_offset = 8 + transport_offset

                pkt_transport_info["qdcount"] = (format(int(struct.unpack('!H', pkt[dns_offset+4:dns_offset+6])[0]), '02x'), int(struct.unpack('!H', pkt[dns_offset+4:dns_offset+6])[0]))

                dns_question_offset = dns_offset + 12 
                curr_num = dns_question_offset 
                num_questions = 0
                i = dns_question_offset 
                pkt_transport_info["qname"] = ""
                while num_questions < pkt_transport_info["qdcount"][1]:
                    if i == curr_num:
                        curr_num += 1 + int(struct.unpack('!B', pkt[i])[0])
                        if len(pkt_transport_info["qname"]) > 0 and int(struct.unpack('!B', pkt[i])[0]) != 0:
                            pkt_transport_info["qname"] = pkt_transport_info["qname"] + '.'
                    else:
                        pkt_transport_info["qname"] = pkt_transport_info["qname"] + chr(int(struct.unpack('!B', pkt[i])[0]))
                    if int(struct.unpack('!B', pkt[i])[0]) == 0:
                        num_questions += 1
                    i += 1
                dns_qtype_offset = i

                pkt_transport_info["qtype"] = (format(int(struct.unpack('!H', pkt[dns_qtype_offset:dns_qtype_offset+2])[0]), '02x'), int(struct.unpack('!H', pkt[dns_qtype_offset:dns_qtype_offset+2])[0]))

                pkt_transport_info["qclass"] = (format(int(struct.unpack('!H', pkt[dns_qtype_offset+2:dns_qtype_offset+4])[0]),'02x'), int(struct.unpack('!H',pkt[dns_qtype_offset+2:dns_qtype_offset+4])[0]))
        elif pkt_IP_info["protocol"][1] == 1:
            pkt_transport_info["type"] = (format(int(struct.unpack('!B', pkt[transport_offset:transport_offset + 1])[0]), '02x'), int(struct.unpack('!B', pkt[transport_offset:transport_offset + 1])[0]))
        return pkt_IP_info, pkt_transport_info


    def packet_valid(self, pkt_dir, pkt):
        '''
        for each packet that comes through, checks validity 
        against parsed rules and returns boolean if packet can
        be passed or not
        '''
        pkt_IP_info, pkt_transport_info = self.parse_pkt(pkt)
        if pkt_dir == PKT_DIR_INCOMING:
            pkt_ext_ip = pkt_IP_info['sIP'][1]
        else:
            pkt_ext_ip = pkt_IP_info['dIP'][1]

        can_send = True
        if pkt_IP_info['ihl'] < 5:
            return False
        last_fail_rule = []
        last_pass_rule = []
        for rule in self.rules:
            rule = rule.split(' ')
            if len(rule) == 4 and pkt_IP_info['protocol'][1] in self.valid_protocols.values(): # not dns
                verdict, protocol, rules_ext_ip, rules_ext_port = [r.lower() for r in rule]
                if pkt_IP_info['protocol'][1] != self.valid_protocols[protocol]:
                    continue # if it doesnt match - remove
                if protocol == 'icmp':
                    if pkt_IP_info['protocol'][1] == 1: #will be matching types
                        pkt_ext_port = str(pkt_transport_info["type"][1])

                else:
                    if pkt_dir == PKT_DIR_INCOMING:
                        pkt_ext_port = str(pkt_transport_info['src'][1])
                    else:
                        pkt_ext_port = str(pkt_transport_info['dst'][1])

                print "------------------------------------------"
                print ' '.join(rule), (self.is_match_ip(rules_ext_ip, pkt_ext_ip), self.is_match_port(rules_ext_port, pkt_ext_port))
                print "rules_port: " + rules_ext_port + " || pkt_port: " + pkt_ext_port
                print "rules_ip: " + rules_ext_ip + " || pkt_ip" + pkt_ext_port
                if self.is_match_ip(rules_ext_ip, pkt_ext_ip) and self.is_match_port(rules_ext_port, pkt_ext_port):
                    if verdict == 'pass':
                        last_pass_rule.append(' '.join(rule))
                        can_send = True
                    else:
                        last_fail_rule.append(' ' .join(rule))
                        can_send = False

            elif len(rule) == 3: #dns
                verdict, dns, domain_name = [r.lower() for r in rule] 
               #  print pkt_IP_info['protocol'], pkt_transport_info["dst"], pkt_transport_info["qdcount"],pkt_transport_info["qtype"], pkt_transport_info["qtype"], pkt_transport_info["qclass"] #dns

                if pkt_IP_info['protocol'][1] == 17 and pkt_transport_info["dst"][1] == 53  and pkt_transport_info["qdcount"][1] == 1 and (pkt_transport_info["qtype"][1] == 1 or pkt_transport_info["qtype"][1] == 28) and pkt_transport_info["qclass"][1] == 1: #dns
                    
                    if fnmatch.fnmatch(pkt_transport_info["qname"], domain_name):
                        if verdict == "pass":
                            last_pass_rule.append(' '.join(rule))
                            can_send = True

                        elif verdict == "drop":
                            last_fail_rule.append(' ' .join(rule))
                            can_send = False
        
        print 'passed: ', last_pass_rule
        print 'failed: ', last_fail_rule
        return can_send

    def is_match_port(self, rules_port, pkt_port):
        if rules_port == 'any' or rules_port == pkt_port:
            return True
        elif '-' in rules_port:
            min_p, max_p = rules_port.split('-')
            min_p = int(min_p)
            max_p = int(max_p)
            return pkt_port >= min_p and pkt_port <= max_p
        return False

    def is_match_ip(self, rules_ext_ip, pkt_ext_ip):
        if rules_ext_ip == 'any' or rules_ext_ip == pkt_ext_ip:
            return True
        elif len(rules_ext_ip) == 2:
            pkt_cc = self.get_cc(pkt_ext_ip)
            return pkt_cc == rules_ext_ip
        elif '/' in rules_ext_ip:
            ip = struct.unpack('<L', socket.inet_aton(pkt_ext_ip))[0]
            net_add, bits = rules_ext_ip.split('/')
            net_mask = struct.unpack('<L', socket.inet_aton(net_add))[0] & ((2L << int(bits)-1)-1)
            return ip & net_mask == net_mask
                
    def get_cc(self, query_ip):
        '''
        Because the ip addresses are sorted,
        we will perform binary search to retrieve
        the correct 2-byte country code
        '''
        lo, hi = 0, len(self.geoIP)-1
        while lo < hi:
            mid = (hi+lo)/2
            if hi-lo == 1:
                if self.compare_range(query_ip, self.geoIP[hi][0:2]) == 0:
                    return self.geoIP[hi][2]
                elif self.compare_range(query_ip, self.geoIP[lo][0:2]) == 0:
                    return self.geoIP[lo][2]

            if self.compare_range(query_ip, self.geoIP[mid][0:2]) < 0:
                hi = mid-1
            elif self.compare_range(query_ip, self.geoIP[mid][0:2]) > 0:
                lo = mid+1
            else:
                return self.geoIP[mid][2].lower().strip()
        return None

 
    def compare_range(self, ip, rng):

        low = int(struct.unpack('!L', socket.inet_aton(rng[0]))[0])
        high = int(struct.unpack('!L', socket.inet_aton(rng[1]))[0])
        target = int(struct.unpack('!L', socket.inet_aton(ip))[0])
        if target < low:
            return -1
        elif low <= target and target <= high:
            return 0
        elif target > high:
            return 1

