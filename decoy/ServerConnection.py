from __future__ import print_function

# print = lambda x: sys.stdout.write("%s\n" % x)
__author__ = "milad"

import select
import socket
import sys
import os
import fcntl
import logging
import traceback
import struct
import uuid
import datetime

log = logging.getLogger("proxy")
hdlr = logging.StreamHandler()
hdlr.setLevel(logging.DEBUG)
hdlr.setFormatter(
    logging.Formatter(
        "%(asctime)s [%(levelname)s] (%(name)s) <%(pathname)s:%(funcName)s> %(message)s"
    )
)
log.addHandler(hdlr)
log.propagate = False


RECEIVE_BYTES = 4096  # rajat - 4096 default


class ProxyConnection(object):
    # enable a buffer on connections with this many bytes
    MAX_BUFFER_SIZE = 1024  # rajat - 1024 default

    # ProxyConnection class forwards data between a client and a destination socket

    def __init__(self, serv_addr, clientid):
        self.conid = uuid.uuid4().bytes
        self.clientid = clientid
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = (
            serv_addr  # rajat - keep track of what was connected to
        )
        self.sock.connect(serv_addr)


class ProxyServer(object):
    def __init__(self, addr):
        self.address = addr
        log.debug(
            "ProxyServer - Listening on address... {}".format(self.address)
        )

        self.listensock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listensock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listensock.bind(self.address)
        self.listensock.listen(5)
        self.connections = {}
        self.revcon = {}  # map from a socket to a ProxyConnection
        self.readsockets = []  # all sockets which can be read
        self.writesockets = []  # all sockets which can be written
        self.allsockets = [self.listensock]  # all opened sockets
        self.connection_count = 0  # count of all active connections
        self.clientsocket = None
        self.datacarry = ""
        self.clientsocks = []

    def run(self):
        loop = 0
        while True:
            # block until there is some activity on one of the sockets, timeout every 60 seconds by default
            r, w, e = select.select(
                [self.listensock] + self.readsockets + self.clientsocks,
                [],
                [self.listensock] + self.readsockets,
            )
            loop += 1
            # handle any reads
            for s in r:
                if s is self.listensock:
                    # open a new connection
                    clientsocket, clientaddr = s.accept()
                    self.clientsocks.append(clientsocket)

                elif s in self.clientsocks:
                    newcon = s.recv(RECEIVE_BYTES)
                    self.addDATA(newcon)

                else:
                    if s in self.connections:
                        try:
                            data = s.recv(RECEIVE_BYTES)
                        except:
                            data = ""

                        pr = self.connections[s]

                        log.warning(
                            "ProxyServer - DATA RECEIVED FROM COVERT {} size={} connection_id={}".format(
                                pr.server_address,
                                len(data),
                                pr.conid,
                            )
                        )

                        if len(data) == 0:
                            self.communicate(pr.clientid, pr.conid, "F", data)
                            self.deactivateRead(self.revcon[pr.conid])
                            del self.revcon[pr.conid]

                            s.close()
                        else:
                            self.communicate(pr.clientid, pr.conid, "D", data)

        self.sock.close()
        self.sock = None

    def addDATA(self, data):
        log.debug("ProxyServer - data={}".format(data))
        self.datacarry += data
        flag = True

        while flag:
            if len(self.datacarry) < 21:
                break
            connid = self.datacarry[:16]
            cmd = struct.unpack(">c", self.datacarry[16:17])[0]
            size = struct.unpack(">I", self.datacarry[17:21])[0]
            if size + 21 <= len(self.datacarry):
                newpkt = self.datacarry[21 : size + 21]
                # print ("DATA ",cmd," size",size)
                log.warning(
                    "ProxyServer - GET COMMAND command={} size={}".format(
                        cmd, size
                    )
                )
                try:
                    if cmd == "O":
                        try:
                            sockid = newpkt[:16]
                            log.warning(
                                "ProxyServer - SEND DATA TO COVERT %s connection_id=`%s`",
                                self.connections[
                                    self.revcon[sockid]
                                ].server_address,
                                sockid,
                            )
                            self.revcon[sockid].sendall(newpkt[16:])
                        except:
                            self.communicate(connid, sockid, "F", "")
                    elif cmd == "N":
                        newcon = newpkt
                        # print (newcon)
                        log.debug("newcon={}".format(newcon))
                        try:
                            clid, ip, port = (
                                newcon[:16],
                                newcon[16:].split(":")[0],
                                int(newcon[16:].split(":")[1]),
                            )
                            self.open((ip, port), connid, clid)

                        except:
                            # print("ERROR", newcon)
                            log.error("ProxyServer - newcon={}".format(newcon))
                            traceback.print_exc(file=sys.stderr)
                    elif cmd == "Q":
                        sockid = newpkt[:16]
                        log.warning(
                            "ProxyServer - CLOSE CONNECTION TO COVERT %s connection_id=`%s`",
                            self.connections[
                                self.revcon[sockid]
                            ].server_address,
                            sockid,
                        )
                        self.deactivateRead(self.revcon[sockid])

                        self.revcon[sockid].close()

                        del self.revcon[sockid]
                except:
                    traceback.print_exc(file=sys.stderr)
                if size + 21 == len(self.datacarry):
                    self.datacarry = ""
                    flag = False
                else:
                    self.datacarry = self.datacarry[size + 21 :]

            else:
                flag = False

    def activateRead(self, sock):
        if not sock in self.readsockets:
            self.readsockets.append(sock)

    def deactivateRead(self, sock):
        if sock in self.readsockets:
            self.readsockets.remove(sock)

    def activateWrite(self, sock):
        if not sock in self.writesockets:
            self.writesockets.append(sock)

    def deactivateWrite(self, sock):
        if sock in self.writesockets:
            self.writesockets.remove(sock)

    def registerSocket(self, sock, conn):
        self.connections[sock] = conn
        self.allsockets.append(sock)

    def unregisterSocket(self, sock, conn):
        del self.connections[sock]
        self.allsockets.remove(sock)

    # open a new proxy connection from the listening socket
    def communicate(self, clientid, conid, CMD, data):
        # print("sending command", CMD, datetime.datetime.now())
        log.warning(
            "ProxyServer - SEND COMMAND %s TO CLIENT connection_id=`%s` client_id=`%s`",
            CMD,
            conid,
            clientid,
        )
        # log.debug("ProxyServer - data=\n{}".format(data))
        for c in self.clientsocks:
            c.sendall(
                "%s%s%s%s%s"
                % (
                    clientid,
                    conid,
                    struct.pack(">c", CMD),
                    struct.pack(">I", len(data)),
                    data,
                )
            )

    def open(self, server, clientid, clid):
        # print("NEW CONNECTION %s" % server[0])
        log.warning(
            "ProxyServer - NEW CONNECTION TO COVERT %s connection_id=`%s` client_id=`%s`",
            server,
            clid,
            clientid,
        )
        conn = ProxyConnection(server, clientid)
        self.connections[conn.sock] = conn
        self.revcon[conn.conid] = conn.sock
        self.activateRead(conn.sock)
        self.communicate(conn.clientid, conn.conid, "C", clid)


if __name__ == "__main__":
    try:
        proxy = sys.argv[1].split(":")
        dest = sys.argv[2].split(":")
        proxyhost = proxy[0]
        proxyport = int(proxy[1])
        serverhost = dest[0]
        serverport = int(dest[1])
    except:
        sys.exit(-1)
