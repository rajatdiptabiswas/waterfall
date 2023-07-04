__author__ = 'milad'
from netfilterqueue import NetfilterQueue

import sys
from scapy_ssl_tls.ssl_tls import TLS
import scapy_ssl_tls.ssl_tls
from scapy.all import Ether,IP,TCP,send,sendp
import TLSConnection
import traceback
import datetime
import TCPConnection
import struct
import threading
import Queue
import socket
import time

from dpkt import ip, tcp

connections={}
tlsconnections={}
cache = {}


def get_packet(payload):
    '''
    `get_packet` function serves as a cache for IP packets based on specific fields within the payload. It retrieves packets from the cache if they have been previously processed, and if not, it processes and caches the new packet.
    '''

    '''
    Global variable `cache` is expected to be a dictionary used for caching previously processed packets.
    '''
    global cache

    '''
    Extracts specific fields from the `payload` using the `struct.unpack` function. It unpacks the 2-byte field at index 4-5 (`payload[4:6]`) as an unsigned short (`!H`) and the 4-byte field at index 12-15 (`payload[12:16]`) as an unsigned integer (`!I`). It then adds the unpacked values together to create a unique key.
    '''
    key = struct.unpack("!H", payload[4:6])[0] + struct.unpack("!I", payload[12:16])[0] # id + src
    res = cache.get(key, None)

    '''
    It checks if the `key` exists in the `cache` dictionary using the `get` method. If the key is found, the associated value (which should be an IP packet) is retrieved. If the key is not found (`res` is `None`) in the cache, it creates an `IP` object using the `IP` constructor. The `payload` is passed to the `IP` constructor, assuming it is a valid IP packet. The created `IP` object is then assigned to the `res` variable.

    The `res` object (either retrieved from the cache or newly created) is stored in the `cache` dictionary with the `key` as the dictionary key.
    '''
    if res is None:
        res = IP(payload)
        cache[key] = res
    return res



class Phase1Runner(threading.Thread):
    '''
    Defines a class named `Phase1Runner` that inherits from the `threading.Thread` class
    '''

    def __init__(self, *args, **kwargs):
        '''
        Initializes the `Phase1Runner` instance. It invokes the constructor of the `threading.Thread` class to perform the necessary setup. It also initializes a `Queue` object called `self.queue` to store packets, sets the `self.target` attribute to the `run` method, and sets `self.daemon` to `True`.
        '''
        threading.Thread.__init__(self, *args, **kwargs)

        self.queue = Queue.Queue()
        '''`self.run` will be the function executed by each thread'''
        self.target = self.run
        '''Daemon threads are considered "background" threads, and they will not prevent the program from exiting if there are daemon threads running'''
        self.daemon = True 

    def queue_packet(self, pkt):
        '''
        Used to enqueue a packet into the `self.queue` queue. It takes a `pkt` argument and adds it to the queue using the `put` method of the `Queue` object.
        '''
        self.queue.put(pkt)

    def run(self):
        '''
        Runs indefinitely and continuously retrieves packets from the `self.queue` queue using the `get` method. It then calls the `process_pkt` method to handle each packet. If an exception occurs during packet processing, the exception traceback is printed to `sys.stderr`.
        '''
        while True:
            pkt = self.queue.get()
            try:
                self.process_pkt(pkt)
            except:
                traceback.print_exc(file=sys.stderr)


    def process_pkt(self, payload):
        '''
        Responsible for processing individual packets. It takes a `payload` argument, which is the packet payload. The method updates global variables `connections` and `tlsconnections` as it processes the packet.
        '''
        global connections, tlsconnections
        
        # print("Processing Packet")
        '''
        `ckey` variable is assigned a tuple containing source IP address, destination IP address, source port, and destination port extracted from the `payload`.
        '''
        ckey = (socket.inet_ntoa(payload[12:16]), socket.inet_ntoa(payload[16:20]), struct.unpack('!H', payload[20:22])[0], struct.unpack('!H', payload[22:24])[0])

        if ord(payload[9]) == 6:
            '''TCP packet identified by protocol number 6'''
            '''
            Checks if `ckey` is present in the `connections` dictionary. If not, it creates a new TCP connection and adds it to the `connections` dictionary.
            '''
            if not ckey in connections:
                seq = struct.unpack('!I', payload[24:28])[0]
                connections[ckey] = TCPConnection.TCPConnection(seq+1)

            '''
            If the length of the payload is 40 (indicating an empty packet), the method simply returns.
            '''
            if len(payload) == 40:
                '''Probably signifies empty packet when payload length is 40'''
                # pkt.accept()
                return

            '''
            `x` contains the packet from cache
            `x` is added to the connections dictionary
            '''
            x = get_packet(payload)
            connections[ckey].addpacket(x)
            nextpackets = connections[ckey].getpacket()

            '''
            If there are next packets available, it iterates over them and checks if `ckey` is present in the `tlsconnections` dictionary. If present, it adds the packet payload to the existing TLS connection in `tlsconnections`. Otherwise, it creates a new TLS connection and adds the packet payload to it.
            '''
            if nextpackets:
                for p in nextpackets:
                    if ckey in tlsconnections:
                        tlsconnections[ckey].addTLSPacket(p[TCP].payload)
                    else:
                        # print("Creating TLS Connection")
                        tlsconnections[ckey] = TLSConnection.TLSConnection()
                        tlsconnections[ckey].addTLSPacket(p[TCP].payload)

phase1 = Phase1Runner()
'''start() from threading.Thread'''
phase1.start()

# @profile
def print_and_accept(pkt):
    global connections, tlsconnections

    payload = pkt.get_payload()

    ckey = (socket.inet_ntoa(payload[12:16]), socket.inet_ntoa(payload[16:20]), struct.unpack('!H', payload[20:22])[0], struct.unpack('!H', payload[22:24])[0])

    # PHASE 1
    '''
    If the protocol of the packet is TCP (identified by the protocol number 6), it enqueues the `payload` in the `phase1` object's queue using `phase1.queue_packet(payload)`. If the length of the payload is 40 (indicating an empty packet), it immediately accepts the packet and returns.
    '''
    try:
        if ord(payload[9]) == 6:
            '''
            TCP packets because the IP protocol number is 6
            `len(payload) == 40` (probably) means empty packet
            '''
            phase1.queue_packet(payload)
            # phase1.process_pkt(x)
            
            if len(payload) == 40:
                pkt.accept()
                return
    except:
        traceback.print_exc(file=sys.stderr)

    # PHASE 2
    try:
        if ord(payload[9]) == 6:
            if ckey in tlsconnections:
                '''
                if TCP packet and ckey exists in `tlsconnections` dictionary
                '''
                if tlsconnections[ckey].startreplace:
                    # x = get_packet(payload)
                    w = ip.IP(payload)
                    
                    datasize = len(str(w.tcp.data))

                    if datasize>0:
                        #print 'DATA TO REPLACE'

                        newpayload = tlsconnections[ckey].getnewpayload(datasize-7, w.tcp.seq)

                        if len(newpayload)>0:
                            print 'SENDING DATA',datetime.datetime.now()

                        padsize = datasize-7-len(newpayload)

                        newpayload += '0' * padsize
                        payload = newpayload + struct.pack('>H',padsize)

                        # x[TCP].payload = chr(23) + chr(3) + chr(3) + struct.pack('!H',len(payload)) + payload
                        w.tcp.data = chr(23) + chr(3) + chr(3) + struct.pack('!H',len(payload)) + payload
                        w.sum = 0
                        w.tcp.sum = 0

                        '''
                        `struct.pack('>H', 10)` statement will return a binary string representing the value 10 (0x0A) packed as an unsigned short (H) in big-endian byte order (>).

                        `struct.pack('!H', 10)` statement will return a binary string representing the value 10 (0x0A) packed as an unsigned short (H) in network byte order (!).

                        struct.pack('!H', 10) produces the same result as struct.pack('>H', 10) because both use big-endian byte order, but ! is the preferred specifier for network byte order
                        '''

                        changed=True

                        pkt.set_payload(str(w))
    except:
        traceback.print_exc(file=sys.stderr)

    pkt.accept()

'''
Typical usage as per https://pypi.org/project/NetfilterQueue/

NetfilterQueue provides access to packets matched by an iptables rule in Linux. Packets so matched can be accepted, dropped, altered, reordered, or given a mark.

The following script prints a short description of each packet before accepting it.

```
from netfilterqueue import NetfilterQueue

def print_and_accept(pkt):
    print(pkt)
    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()
```
'''

nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)

nfq2 = NetfilterQueue()

try:
    nfqueue.run()
except KeyboardInterrupt:
    print
