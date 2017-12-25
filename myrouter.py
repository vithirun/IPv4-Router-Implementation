#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net

        # fwding table: net_id  mask  next_hop_ip  out_port 
        self.fwd_table = []

        # arp_mapping ==> ip  mac
        self.arp_mapping = []

        # req_queue ==> pkts to be fwded after arp resolution and ip to be resolved for mac
        self.req_queue = []

        # List of ips waiting for arp resolution: arp_outstanding_req ==> ip  out_port  sent_time  trial  req_pkt
        self.arp_outstanding_req = []

    def icmp_err_msg(self, ip, icmptype, icmpcode): 

        my_interfaces = self.net.interfaces()
        for intf in my_interfaces:
            dummy_ip = intf.ipaddr
            break

        pkt = IPv4() + ICMP()
        pkt[IPv4].src = dummy_ip
        pkt[IPv4].dst = ip
        pkt[IPv4].ttl = 64
        pkt[ICMP].icmptype = icmptype 
        pkt[ICMP].icmpcode = icmpcode 
        self.process_ip_packet(pkt, 1) 
 
    def process_outstanding_arp_requests(self):
        my_interfaces = self.net.interfaces()
        cur = time.time()

        i = -1 
        copy = deepcopy(self.arp_outstanding_req)

        for ent in copy:
            i = i + 1
            diff = int(cur - ent[2])
            if diff % 60 >= 1:
                # resend arp request
                if ent[3] < 5:
                    self.net.send_packet(ent[1], ent[4])
                    ent[3] = ent[3] + 1

                # drop the request with icmp err msg
                else:
                    for e in self.req_queue:
                        if e[1] == ent[0]: 
                            f = e[0]
                            self.icmp_err_msg(f[IPv4].dst, 3, 1)
                    copy.pop(i)

    def is_mac_known(self, ip):
        for ent in self.arp_mapping:
            if ent[0] == ip:
                return ent[1]
        return None

    def send_arp_request(self, my_mac, my_ip, dst_ip, out_port, pkt, is_icmp_resp):
        req_sent = 0
        for requests in self.arp_outstanding_req:
            if requests[0] == dst_ip:
                req_sent = 1
                break

        if is_icmp_resp == 1:
            # prepare the icmp response that is to be sent after mac is resolved
            data = pkt[ICMP].icmpdata.data
            pkt[ICMP].icmptype = 0
            pkt[ICMP].icmpdata.data = data
            tmp = pkt[IPv4].src
            pkt[IPv4].src = pkt[IPv4].dst
            pkt[IPv4].dst = tmp
            tup = [pkt, IPv4Address(dst_ip)]
            self.req_queue.append(tup)
        else:
            tup = [pkt, pkt[IPv4].dst]
            self.req_queue.append(tup)

        if req_sent == 0:
            arp_req = create_ip_arp_request(my_mac, my_ip, dst_ip)
            cur = time.time()
            tup2 = [dst_ip, out_port, cur, 1, arp_req]
            self.arp_outstanding_req.append(tup2)
            self.net.send_packet(out_port, arp_req)

    def process_arp_response(self, pkt):
        arp = pkt.get_header(Arp) 
        # save the arp mapping
        tup = [arp.senderprotoaddr, arp.senderhwaddr]
        self.arp_mapping.append(tup)

        # remove the ip that got its mac from the outstanding req list
        i = -1
        for ent in self.arp_outstanding_req:
            i = i + 1
            if ent[0] == arp.senderprotoaddr:
                out_port = ent[1]
                self.arp_outstanding_req.pop(i)
                break

        # send response for the pkts whose dst mac got resolved
        copy = deepcopy(self.req_queue)
        i = -1
        for ent in copy:
            i = i + 1
            if ent[1] == arp.senderprotoaddr:
                ent0 = ent[0]
                ent0[Ethernet].src = arp.targethwaddr
                ent0[Ethernet].dst = arp.senderhwaddr
                self.net.send_packet(out_port, ent0)
                copy.pop(i)

    def process_arp_request(self, pkt, dev):
        arp = pkt.get_header(Arp) 
        # save the sender ip and mac in ur mapping list
        tup = [arp.senderprotoaddr, arp.senderhwaddr]
        i = -1
        for ent in self.arp_mapping:
            i = i + 1
            if ent[0] == arp.senderprotoaddr:
                arp_mapping.pop(i)
                break
        self.arp_mapping.append(tup)

        # pkt is arp request, send response if it is your ip 
        response_sent = 0
        my_interfaces = self.net.interfaces()
        for intf in my_interfaces:
            if arp.targetprotoaddr == intf.ipaddr:
                arp_resp = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                self.net.send_packet(dev, arp_resp)
                response_sent = 1
                break

        # pkt is arp request, send response if you know the mac from ur table 
        if response_sent == 0:
            for ent in self.arp_mapping:
                if ent[0] == arp.targetprotoaddr:
                    arp_resp = create_ip_arp_reply(ent[1], arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
                    self.net.send_packet(dev, arp_resp)
                    break

    def check_fwding_table(self, check_ip):
        prefixlen = 0
        for ent in self.fwd_table:
            net_id = IPv4Address(ent[0])
            mask = IPv4Address(ent[1])
            check1 = int(check_ip) & int(mask)
            check2 = int(net_id) & int(mask)
            match = check1 == check2
            if match == True:
                temp = (IPv4Network(ent[0] + '/' + ent[1])).prefixlen
                if temp > prefixlen:
                    prefixlen = temp
                    next_hop = ent[2]
                    out_port = ent[3]
        return prefixlen, next_hop, out_port

    def process_ip_packet(self, pkt, flag):
        dst_ip = pkt[IPv4].dst
        check_ip = dst_ip

        my_interfaces = self.net.interfaces()
        for intf in my_interfaces:
            # if the pkt is destined for me
            if intf.ipaddr == dst_ip:
                check_ip = pkt[IPv4].src
                break

        # Check for match in ur fwding table
        prefixlen, next_hop, out_port = self.check_fwding_table(check_ip)

        if prefixlen == 0:
            # icmp destination unreachable
            self.icmp_err_msg(pkt[IPv4].src, 3, 0) 
        else: 
            # match found
            for intf in my_interfaces:
                if intf.name == out_port:
                    my_mac = intf.ethaddr
                    my_ip = intf.ipaddr
                    break

            # icmp echo request
            if check_ip == pkt[IPv4].src:
                # check if it is icmp echo request
                if pkt.has_header(ICMP) == True and pkt[ICMP].icmptype != 8:
                    self.icmp_err_msg(pkt[IPv4].src, 3, 3)
                elif pkt.has_header(ICMP) == True and pkt[ICMP].icmptype == 8:
                    mac = self.is_mac_known(IPv4Address(next_hop))

                    # send arp request if dest mac is not known
                    if mac == None:
                        pkt[IPv4].ttl = pkt[IPv4].ttl - 1
                        if pkt[IPv4].ttl == 0:
                            self.icmp_err_msg(pkt[IPv4].dst, 11, 0)
                        else:
                            self.send_arp_request(my_mac, my_ip, IPv4Address(next_hop), out_port, pkt, 1) 
                    # send icmp response
                    else:
                        data = pkt[ICMP].icmpdata.data
                        pkt[ICMP].icmptype = 0
                        pkt[ICMP].icmpdata.data = data
                        tmp = pkt[IPv4].src
                        pkt[IPv4].src = pkt[IPv4].dst
                        pkt[IPv4].dst = tmp
                        pkt[IPv4].ttl = pkt[IPv4].ttl - 1
                        pkt[Ethernet].dst = mac
                        pkt[Ethernet].src = my_mac
                        self.net.send_packet(out_port, pkt)
            else:
                pkt[IPv4].ttl = pkt[IPv4].ttl - 1

                if pkt[IPv4].ttl == 0:
                    self.icmp_err_msg(pkt[IPv4].dst, 11, 0)
                else:
                    mac = self.is_mac_known(dst_ip)

                    if flag == 1:
                        pkt[IPv4].src = my_ip
                        pkt[Ethernet].src = my_mac

                    # if the mac is not known, send arp request
                    if mac == None:
                        self.send_arp_request(my_mac, my_ip, dst_ip, out_port, pkt, 0)
                    # if the mac is known, fwd the pkt

                    else:
                        pkt[Ethernet].src = my_mac
                        pkt[Ethernet].dst = mac
                        self.net.send_packet(out_port, pkt) 

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''

        # Populate fwding table
        fwd_file = open("forwarding_table.txt", "r")
        for line in fwd_file.readlines():
            words = line.split()
            self.fwd_table.append(words)

        for intf in self.net.interfaces():
            netid = IPv4Address(int(intf.ipaddr) & int(intf.netmask))
            tup = [format(str(netid)), format(str(intf.netmask)), None, intf.name]
            self.fwd_table.append(tup)

        while True:
            my_interfaces = self.net.interfaces()
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                print("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                print("Got shutdown signal")
                break

            self.process_outstanding_arp_requests()
                           
            if gotpkt:
                print("Got a packet: {}".format(str(pkt)))

                if pkt.has_header(Arp):
                    arp = pkt.get_header(Arp) 
                    if arp.targethwaddr != 'ff:ff:ff:ff:ff:ff':
                       self.process_arp_response(pkt) 
                    else:
                       self.process_arp_request(pkt, dev)

                elif pkt.has_header(IPv4):
                    self.process_ip_packet(pkt, 0)

def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
