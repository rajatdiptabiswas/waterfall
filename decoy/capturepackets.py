__author__ = "milad"
from netfilterqueue import NetfilterQueue

import sys
from scapy_ssl_tls.ssl_tls import TLS
import scapy_ssl_tls.ssl_tls
from scapy.all import Ether, IP, TCP, send, sendp
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

connections = {}
tlsconnections = {}
cache = {}

import logging

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] <%(pathname)s:%(funcName)s> %(message)s",
    level=logging.WARNING,
)
log = logging.getLogger(__name__)

total_replaceable_data = 0
total_replaced_data = 0


def get_packet(payload):
    global cache

    key = (
        struct.unpack("!H", payload[4:6])[0]
        + struct.unpack("!I", payload[12:16])[0]
    )  # id + src

    # log.info("key={}".format(key))

    res = cache.get(key, None)
    if res is None:
        res = IP(payload)
        cache[key] = res
    return res


class Phase1Runner(threading.Thread):
    def __init__(self, *args, **kwargs):
        threading.Thread.__init__(self, *args, **kwargs)

        self.queue = Queue.Queue()
        self.target = self.run
        self.daemon = True

    def queue_packet(self, pkt):
        self.queue.put(pkt)

    def run(self):
        while True:
            pkt = self.queue.get()
            try:
                self.process_pkt(pkt)
            except:
                traceback.print_exc(file=sys.stderr)

    def process_pkt(self, payload):
        global connections, tlsconnections

        # print("Processing Packet")
        log.debug("Processing packet...")

        ckey = (
            socket.inet_ntoa(payload[12:16]),
            socket.inet_ntoa(payload[16:20]),
            struct.unpack("!H", payload[20:22])[0],
            struct.unpack("!H", payload[22:24])[0],
        )

        log.debug("ckey = %s", ckey)

        if ord(payload[9]) == 6:
            if not ckey in connections:
                seq = struct.unpack("!I", payload[24:28])[0]
                connections[ckey] = TCPConnection.TCPConnection(seq + 1)

            if len(payload) == 40:
                # pkt.accept()
                return

            x = get_packet(payload)
            connections[ckey].addpacket(x)
            nextpackets = connections[ckey].getpacket()

            if nextpackets:
                for p in nextpackets:
                    if ckey in tlsconnections:
                        tlsconnections[ckey].addTLSPacket(p[TCP].payload)
                    else:
                        # print("Creating TLS Connection")
                        log.info("Creating TLS connection...")
                        tlsconnections[ckey] = TLSConnection.TLSConnection()
                        tlsconnections[ckey].addTLSPacket(p[TCP].payload)

        log.debug("Processed packet")


phase1 = Phase1Runner()
phase1.start()


# @profile
def print_and_accept(pkt):
    global connections, tlsconnections, total_replaceable_data, total_replaced_data

    payload = pkt.get_payload()

    # log.debug("NetfilterQueue pkt payload=\n{}".format(payload))

    ckey = (
        socket.inet_ntoa(payload[12:16]),
        socket.inet_ntoa(payload[16:20]),
        struct.unpack("!H", payload[20:22])[0],
        struct.unpack("!H", payload[22:24])[0],
    )

    # log.debug("ckey={}".format(ckey))

    # PHASE 1
    try:
        if ord(payload[9]) == 6:
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
                if tlsconnections[ckey].startreplace:
                    # x = get_packet(payload)
                    w = ip.IP(payload)

                    datasize = len(str(w.tcp.data))
                    # log.debug("ip.IP(payload)=\n{}".format(w))
                    log.debug("datasize={}".format(datasize))
                    # log.debug("packet.tcp=\n{}".format(w.tcp))
                    # log.debug(
                    #     "packet.tcp.srcport={} packet.tcp.dstport={}".format(
                    #         w.tcp.sport, w.tcp.dport
                    #     )
                    # )
                    # log.debug("packet.tcp.data=\n{}".format(w.tcp.data))

                    total_replaceable_data += datasize - 7

                    if datasize > 0:
                        # print 'DATA TO REPLACE'
                        log.debug("DATA TO REPLACE")

                        newpayload = tlsconnections[ckey].getnewpayload(
                            datasize - 7, w.tcp.seq
                        )

                        if len(newpayload) > 0:
                            # print 'SENDING DATA',datetime.datetime.now()
                            log.debug(
                                "SENDING DATA {}".format(
                                    datetime.datetime.now()
                                )
                            )

                            total_replaced_data += len(newpayload)

                            log.debug("newpayload=\n{}".format(newpayload))

                            # log.info(
                            #     "\nreplaceable data = {}\ntotal till now = {}".format(
                            #         datasize, total_replaceable_data
                            #     )
                            # )
                            # log.info(
                            #     "\ndata replaced = {}\ntotal till now = {}".format(
                            #         len(newpayload), total_replaced_data
                            #     )
                            # )

                            log.warning(
                                "\nreplaceable = {}\nreplaced    = {}\n--- TOTAL TILL NOW ---\nreplaceable = {}\nreplaced    = {}".format(
                                    datasize - 7,
                                    len(newpayload),
                                    total_replaceable_data,
                                    total_replaced_data,
                                )
                            )

                        padsize = datasize - 7 - len(newpayload)

                        newpayload += "0" * padsize
                        payload = newpayload + struct.pack(">H", padsize)

                        # x[TCP].payload = chr(23) + chr(3) + chr(3) + struct.pack('!H',len(payload)) + payload
                        w.tcp.data = (
                            chr(23)
                            + chr(3)
                            + chr(3)
                            + struct.pack("!H", len(payload))
                            + payload
                        )
                        w.sum = 0
                        w.tcp.sum = 0

                        changed = True

                        pkt.set_payload(str(w))
    except:
        traceback.print_exc(file=sys.stderr)

    pkt.accept()


nfqueue = NetfilterQueue()
nfqueue.bind(1, print_and_accept)
# nfq2 = NetfilterQueue()

try:
    nfqueue.run()

except KeyboardInterrupt:
    print
