#!/usr/bin/env python

import time
import threading
from scapy.all import *
import sys
import socket
import json
import Queue
import interfaces
import random

maxhop = 25

# A request that will trigger the great firewall but will NOT cause
# the web server to process the connection.  You probably want it here

triggerfetch = "GET /search?q=falun+gong HTTP/1.1\r\nHost: www.google.com\r\n\r\n"

# A couple useful functions that take scapy packets
def isRST(p):
    return (TCP in p) and (p[IP][TCP].flags & 0x4 != 0)

def isICMP(p):
    return ICMP in p

def isTimeExceeded(p):
    return ICMP in p and p[IP][ICMP].type == 11

# A general python object to handle a lot of this stuff...
#
# Use this to implement the actual functions you need.
class PacketUtils:
    def __init__(self, dst=None):
        # Get one's SRC IP & interface
        i = interfaces.interfaces()
        self.src = i[1][0]
        self.iface = i[0]
        self.netmask = i[1][1]
        self.enet = i[2]
        self.dst = dst
        sys.stderr.write("SIP IP %s, iface %s, netmask %s, enet %s\n" %
                         (self.src, self.iface, self.netmask, self.enet))
        # A queue where received packets go.  If it is full
        # packets are dropped.
        self.packetQueue = Queue.Queue(100000)
        self.dropCount = 0
        self.idcount = 0

        self.ethrdst = ""

        # Get the destination ethernet address with an ARP
        self.arp()
        
        # You can add other stuff in here to, e.g. keep track of
        # outstanding ports, etc.
        
        # Start the packet sniffer
        t = threading.Thread(target=self.run_sniffer)
        t.daemon = True
        t.start()
        time.sleep(.1)

    # generates an ARP request
    def arp(self):
        e = Ether(dst="ff:ff:ff:ff:ff:ff",
                  type=0x0806)
        gateway = ""
        srcs = self.src.split('.')
        netmask = self.netmask.split('.')
        for x in range(4):
            nm = int(netmask[x])
            addr = int(srcs[x])
            if x == 3:
                gateway += "%i" % ((addr & nm) + 1)
            else:
                gateway += ("%i" % (addr & nm)) + "."
        sys.stderr.write("Gateway %s\n" % gateway)
        a = ARP(hwsrc=self.enet,
                pdst=gateway)
        p = srp1([e/a], iface=self.iface, verbose=0)
        self.etherdst = p[Ether].src
        sys.stderr.write("Ethernet destination %s\n" % (self.etherdst))


    # A function to send an individual packet.
    def send_pkt(self, payload=None, ttl=32, flags="",
                 seq=None, ack=None,
                 sport=None, dport=80,ipid=None,
                 dip=None,debug=False):
        if sport == None:
            sport = random.randint(1024, 32000)
        if seq == None:
            seq = random.randint(1, 31313131)
        if ack == None:
            ack = random.randint(1, 31313131)
        if ipid == None:
            ipid = self.idcount
            self.idcount += 1
        t = TCP(sport=sport, dport=dport,
                flags=flags, seq=seq, ack=ack)
        ip = IP(src=self.src,
                dst=self.dst,
                id=ipid,
                ttl=ttl)
        p = ip/t
        if payload:
            p = ip/t/payload
        else:
            pass
        e = Ether(dst=self.etherdst,
                  type=0x0800)
        # Have to send as Ethernet to avoid interface issues
        sendp([e/p], verbose=1, iface=self.iface)
        # Limit to 20 PPS.
        time.sleep(.05)
        # And return the packet for reference
        return p


    # Has an automatic 5 second timeout.
    def get_pkt(self, timeout=5):
        try:
            return self.packetQueue.get(True, timeout)
        except Queue.Empty:
            return None

    # The function that actually does the sniffing
    def sniffer(self, packet):
        try:
            # non-blocking: if it fails, it fails
            self.packetQueue.put(packet, False)
        except Queue.Full:
            if self.dropCount % 1000 == 0:
                sys.stderr.write("*")
                sys.stderr.flush()
            self.dropCount += 1

    def run_sniffer(self):
        sys.stderr.write("Sniffer started\n")
        rule = "src net %s or icmp" % self.dst
        sys.stderr.write("Sniffer rule \"%s\"\n" % rule);
        sniff(prn=self.sniffer,
              filter=rule,
              iface=self.iface,
              store=0)

    # Sends the message to the target in such a way
    # that the target receives the msg without
    # interference by the Great Firewall.
    #
    # ttl is a ttl which triggers the Great Firewall but is before the
    # server itself (from a previous traceroute incantation
    def evade(self, target, msg, ttl):
        src_port = random.randint(2000, 30000)
        self.send_pkt(flags="S", sport=src_port)
        response = self.get_pkt()
        if response == None:
            return "DEAD"
        tcp = response[TCP]
        sequence = tcp.ack
        self.send_pkt(flags="A", seq = sequence, ack= tcp.seq+1, sport = src_port)
        length = len(msg)
        count = 1
        for c in msg:
            if count == length:
                self.send_pkt(payload=c, flags="PA", seq = sequence, ack= tcp.seq+1, sport = src_port)
                self.send_pkt(payload=c, flags="PA", seq = sequence, ack= tcp.seq+1, sport = src_port, ttl = ttl)
            else:
                self.send_pkt(payload=c, flags="A", seq = sequence, ack= tcp.seq+1, sport = src_port)
                self.send_pkt(payload=c, flags="A", seq = sequence, ack= tcp.seq+1, sport = src_port, ttl = ttl)
            sequence +=1
            count +=1
        ret_msg = ""
        result = self.get_pkt()
        ACK = tcp.seq+1
        while result != None:
            if TCP in result and 'Raw' in result:
                if ACK <= result[TCP].seq:
                    ret_msg += result['Raw'].load
                    ACK = result[TCP].seq + 1
            result = self.get_pkt()
        return ret_msg
        
    # Returns "DEAD" if server isn't alive,
    # "LIVE" if teh server is alive,
    # "FIREWALL" if it is behind the Great Firewall
    def ping(self, target):
        # self.send_msg([triggerfetch], dst=target, syn=True)
        src_port = random.randint(2000, 30000)
        self.send_pkt(flags="S", sport=src_port)
        response = self.get_pkt()
        count = 0
        while response == None:
            if count == 10:
                break
            response = self.get_pkt()
            count += 1
        if response == None:
            return "DEAD"
        if isRST(response):
            return "FIREWALL"
        tcp = response[TCP]
        self.send_pkt(payload=triggerfetch, flags="PA",sport = src_port, seq= tcp.ack, ack= tcp.seq+1)
        #self.send_pkt(payload=triggerfetch, flags="P",sport = src_port, seq= tcp.ack, ack= tcp.seq+1)
        result = self.get_pkt()
        if result == None:
            return "DEAD"
        while result != None:
            if isRST(result):
                return "FIREWALL"
            result = self.get_pkt()
        return "LIVE"


    # Format is
    # ([], [])
    # The first list is the list of IPs that have a hop
    # or none if none
    # The second list is T/F 
    # if there is a RST back for that particular request
    def traceroute(self, target, hops):
        ips, Rsts = [], [] 
        for i in range(1, hops + 1):
            response = None
            while not response:
                src_port = random.randint(2000, 30000)
                self.send_pkt(sport = src_port, flags = "S")
                response = self.get_pkt()
            tcp = response[TCP]
            # send 3 copy
            self.send_pkt(payload = triggerfetch, flags = "PA", sport=src_port, seq = tcp.ack, ack= tcp.seq+1, ttl = i)
            self.send_pkt(payload = triggerfetch, flags = "PA", sport=src_port, seq = tcp.ack, ack= tcp.seq+1, ttl = i)
            self.send_pkt(payload = triggerfetch, flags = "PA", sport=src_port, seq = tcp.ack, ack= tcp.seq+1, ttl = i)
            result = self.get_pkt()
            ips.append(None)
            Rsts.append(False)
            while result != None:
                if isTimeExceeded(result):
                    ips[len(ips) - 1] = result[IP].src
                if isRST(result):
                    print ("get a reset")
                    Rsts[len(Rsts) -1] = True
                result = self.get_pkt()
        return ips, Rsts