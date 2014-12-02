#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import struct # parse binary
import binascii
import socket 
import fnmatch

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.  

class Firewall:
    def __init__(self, config, iface_int, iface_ext): 
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.valid_protocols = {1:'icmp', 6:'tcp', 17:'udp'}
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
        self.RST_IP = '54.173.224.150'

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        can_send, verdict, protocol = self.packet_valid(pkt_dir, pkt)
        if verdict == 'deny':
            pkt_IP_info, pkt_transport_info = self.parse_pkt(pkt)
            if protocol == 'tcp':
                #send deny tcp (rst)
                rst = self.create_rst_pkt(pkt, pkt_IP_info, pkt_transport_info)  
                if pkt_dir == PKT_DIR_INCOMING:
                    self.iface_ext.send_ip_packet(rst)
                else:
                    self.iface_int.send_ip_packet(rst)
            elif protocol == 'dns':
                dns_pkt = self.create_dns_pkt(pkt, pkt_IP_info)
                print "meow"
                if pkt_dir == PKT_DIR_INCOMING:
                    self.iface_ext.send_ip_packet(dns_pkt)
                else:
                    self.iface_int.send_ip_packet(dns_pkt)
        elif verdict == 'log': 
            if protocol == 'http':
                #log it!
                pass
        if can_send:
            if pkt_dir == PKT_DIR_INCOMING:
                self.iface_int.send_ip_packet(pkt)
            else:
                self.iface_ext.send_ip_packet(pkt)

    # TODO: You can add more methods as you want.
    def parse_pkt(self, pkt):
      try:
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
      except Exception: 
        return None, None
      return pkt_IP_info, pkt_transport_info



    def packet_valid(self, pkt_dir, pkt):
        '''
        for each packet that comes through, checks validity 
        against parsed rules and returns boolean if packet can
        be passed or not
        '''
        pkt_IP_info, pkt_transport_info = self.parse_pkt(pkt)
        if pkt_IP_info == None:
            return False
        if pkt_dir == PKT_DIR_INCOMING:
            pkt_ext_ip = pkt_IP_info['sIP'][1]
        else:
            pkt_ext_ip = pkt_IP_info['dIP'][1]
        last_verdict = ""
        last_protocol = ""
        can_send = True
        if pkt_IP_info['ihl'] < 5:
            return False
        for rule in self.rules:
            rule = rule.split(' ')
            if len(rule) == 4 and pkt_IP_info['protocol'][1] in self.valid_protocols: # not dns
                verdict, protocol, rules_ext_ip, rules_ext_port = [r.lower() for r in rule]
                if self.valid_protocols[pkt_IP_info['protocol'][1]] != protocol:
                    continue 
                if protocol == 'icmp':
                    if pkt_IP_info['protocol'][1] == 1: #TODO: constant to go here
                        pkt_ext_port = str(pkt_transport_info["type"][1])
                else:
                    if pkt_dir == PKT_DIR_INCOMING:
                        pkt_ext_port = str(pkt_transport_info['src'][1])
                    else:
                        pkt_ext_port = str(pkt_transport_info['dst'][1])

                if self.is_match_ip(rules_ext_ip, pkt_ext_ip) and self.is_match_port(rules_ext_port, pkt_ext_port):
                    last_verdict = verdict
                    last_protocol = protocol
                    if verdict == 'pass':
                        can_send = True
                    elif verdict == 'drop' or verdict == 'deny':
                        can_send = False

            elif len(rule) == 3: #dns
                verdict, dns, domain_name = [r.lower() for r in rule] 

                if pkt_IP_info['protocol'][1] == 17 and pkt_transport_info["dst"][1] == 53  and pkt_transport_info["qdcount"][1] == 1 and (pkt_transport_info["qtype"][1] == 1 or pkt_transport_info["qtype"][1] == 28) and pkt_transport_info["qclass"][1] == 1: #dns
                    
                    if fnmatch.fnmatch(pkt_transport_info["qname"], domain_name):
                        last_verdict = verdict
                        last_protocol = dns
                        if verdict == "pass":
                            can_send = True
                        elif verdict == 'drop' or verdict == 'deny':
                            can_send = False

        return can_send, last_verdict, last_protocol

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
                    return self.geoIP[hi][2].lower().strip()
                elif self.compare_range(query_ip, self.geoIP[lo][0:2]) == 0:
                    return self.geoIP[lo][2].lower().strip()

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

    def create_dns_pkt(self, pkt, pkt_IP_info):
        dns_pkt = "" 
        
        ### IP HEADER ###
        version_ihl = struct.pack('!B', (struct.unpack('!B', pkt[0])[0] & 0xf0) | 0x05)
        tos = pkt[1]
        total_length = struct.pack('!H', 0x28)
        ID = struct.pack('!H', 0x0)
        ipflags_fragoff = struct.pack('!H', 0x0)
        ttl = struct.pack('!B', 0x40)
        protocol = pkt[9]
        src_IP = pkt[16:20] 
        dst_IP = pkt[12:16]

        #two_byte_chunks = [version_ihl + tos, total_length, ID, ipflags_fragoff, ttl + protocol, src_IP[0:2], src_IP[2:4], dst_IP[0:2], dst_IP[2:4]]
        #header_checksum = self.compute_checksum(two_byte_chunks)
        filler_checksum = struct.pack('!H', 0x0)
        dns_pkt = version_ihl + tos + total_length + ID + ipflags_fragoff + ttl + protocol + filler_checksum + src_IP + dst_IP 

        ### UDP HEADER ###
        transport_off = pkt_IP_info['ihl'][1] * 4
        src_port =  pkt[transport_off+2:transport_off+4]
        dst_port = pkt[transport_off:transport_off+2]
        header_length = struct.pack('!H', 0x08)
        
        two_byte_chunks = [src_IP[0:2], src_IP[2:4], dst_IP[0:2] ,dst_IP[2:4], struct.pack('!B', 0x0) + protocol, src_port, dst_port, header_length]
        udp_checksum = self.compute_checksum(two_byte_chunks)

        dns_pkt += src_port + dst_port + header_length + udp_checksum

        ### DNS HEADER ###

        dns_off = transport_off + 8

        dns_ID = pkt[dns_off:dns_off + 2]
        dns_left_flags = struct.pack('!B', struct.unpack('!B', pkt[dns_off+2])[0] | 0b10000000)
        dns_right_flags = struct.pack('!B', struct.unpack('!B', pkt[dns_off+3])[0] & 0b10000000)

        dns_qdcount = pkt[dns_off+4:dns_off+6]
        dns_anscount = struct.pack( '!H', 0x1)
        dns_nscount = pkt[dns_off+8:dns_off+10]
        dns_arcount = pkt[dns_off+10:dns_off+12]

        dns_pkt += dns_ID + dns_left_flags + dns_right_flags + dns_qdcount + dns_anscount + dns_nscount + dns_arcount

        dns_question_off = dns_off + 12
        curr_num = dns_question_off 
        num_questions = 0
        i = dns_question_off 
        dns_qname = ""
        while num_questions < struct.unpack('!H', dns_qdcount)[0]:
            dns_qname += pkt[i]
            if int(struct.unpack('!B', pkt[i])[0]) == 0:
                num_questions += 1
            i += 1
        dns_qtype_offset = i

        dns_qtype = pkt[dns_qtype_offset:dns_qtype_offset + 2]
        dns_qclass = pkt[dns_qtype_offset+2:dns_qtype_offset + 4]

        dns_pkt += dns_qname + dns_qtype + dns_qclass

        dns_ans_offset = dns_qtype_offset + 4


        dns_pkt += dns_qname + dns_qtype + dns_qclass

        dns_ans_ttl = struct.pack('!L', 0x1)
        dns_ans_RLENGTH = struct.pack('!H', 0x4)
        dns_ans_RDATA = socket.inet_aton('54.173.224.150')

        dns_pkt += dns_ans_ttl + dns_ans_RLENGTH + dns_ans_RDATA

        # UDP checksum and total length
        udp_length_dec = len(dns_pkt) - transport_off

        #print len(dns_pkt) - dns_off

        udp_length = struct.pack('!H', udp_length_dec)
        dns_pkt = dns_pkt[0:transport_off + 4] +  udp_length + dns_pkt[transport_off+6:]
        two_byte_chunks = [src_IP[0:2], src_IP[2:4], dst_IP[0:2] ,dst_IP[2:4], struct.pack('!B', 0x0) + protocol]
        
        if (len(dns_pkt)-dns_off) % 2 == 1:
            dns_pkt += struct.pack('!B', 0x0)

        for i in range(dns_off, len(dns_pkt), 2):
            two_byte_chunks.append(dns_pkt[i:i+2])

        udp_checksum = self.compute_checksum(two_byte_chunks)

        dns_pkt = dns_pkt[0:transport_off + 6] + udp_checksum + dns_pkt[transport_off + 8:]
        

        #IP checksum and total length
        total_length = struct.pack('!H', len(dns_pkt))
        dns_pkt = dns_pkt[0:2] + total_length + dns_pkt[4:]

        two_byte_chunks = [version_ihl + tos, total_length, ID, ipflags_fragoff, ttl + protocol, src_IP[0:2], src_IP[2:4], dst_IP[0:2], dst_IP[2:4]]
        header_checksum = self.compute_checksum(two_byte_chunks)

        dns_pkt = dns_pkt[0:10] + header_checksum + dns_pkt[12:]

        return dns_pkt

        
    def create_rst_pkt(self, pkt, pkt_IP_info, pkt_transport_info):
        rst_pkt = ""
        ### IP HEADER ###
        version_ihl = struct.pack('!B', (struct.unpack('!B', pkt[0])[0] & 0xf0) | 0x05)
        tos = pkt[1]
        total_length = struct.pack('!H', 0x28)
        ID = struct.pack('!H', 0x0)
        ipflags_fragoff = struct.pack('!H', 0x0)
        ttl = struct.pack('!B', 0x40)
        protocol = pkt[9]
        src_IP = pkt[16:20] 
        dst_IP = pkt[12:16]

        two_byte_chunks = [version_ihl + tos, total_length,ID, ipflags_fragoff, ttl + protocol, src_IP[0:2], src_IP[2:4], dst_IP[0:2], dst_IP[2:4]]
        header_checksum = self.compute_checksum(two_byte_chunks)

        rst_pkt = version_ihl + tos + total_length + ID + ipflags_fragoff + ttl + protocol + header_checksum + src_IP + dst_IP 

        ### TCP HEADER ###
        transport_off = pkt_IP_info['ihl'][1] * 4
        src_port =  pkt[transport_off+2:transport_off+4]
        dst_port = pkt[transport_off:transport_off+2]
        seq_num = pkt[transport_off+8:transport_off+12]
        #ack_num = struct.pack('!L',struct.unpack('!L',pkt[transport_off+4:transport_off+8])[0] + len(pkt) - pkt_IP_info['ihl'][1] -struct.unpack('!B', pkt[12])[0])
        ack_num = struct.pack('!L',struct.unpack('!L',pkt[transport_off+4:transport_off+8])[0] + 1)
        header_length = struct.pack('!B', 0x50)
        tcp_flag = struct.pack('!B', 0x14)
        window = struct.pack('!H', 0)
        urgent_ptr = struct.pack('!H', 0)
        two_byte_chunks = [src_IP[0:2], src_IP[2:4], dst_IP[0:2] ,dst_IP[2:4], struct.pack('!B', 0x0) + protocol, struct.pack('!H', 0x14), src_port, dst_port, seq_num[0:2], seq_num[2:4], ack_num[0:2], ack_num[2:4], header_length + tcp_flag, window, urgent_ptr]
        tcp_checksum = self.compute_checksum(two_byte_chunks)
        rst_pkt += src_port + dst_port + seq_num + ack_num + header_length + tcp_flag + window + tcp_checksum + urgent_ptr

        return rst_pkt
    def compute_checksum(self, two_byte_list):
        checksum = 0
        for two_byte in two_byte_list:
            checksum += struct.unpack('!H', two_byte)[0]
        four_bit_mask = 0xf0000
        carry = (four_bit_mask & checksum) >> 16 
        rest_bits = checksum & 0x0ffff 
        sum_bits = carry + rest_bits
        return struct.pack('!H', ~sum_bits & 0xffff)
