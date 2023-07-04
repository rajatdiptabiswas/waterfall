from __future__ import print_function
#print = lambda x: sys.stdout.write("%s\n" % x)
__author__ = 'milad'

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


class ProxyConnection(object):
    # enable a buffer on connections with this many bytes
    MAX_BUFFER_SIZE = 1024

    # ProxyConnection class forwards data between a client and a destination socket

    def __init__(self,serv_addr,clientid):
        '''uuid.uuid4() generates a random UUID and .bytes gets the raw bytes'''
        self.conid=uuid.uuid4().bytes
        self.clientid=clientid
        '''Creates IPv4 TCP socket'''
        self.sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        '''Acts as a client to connect to the server holding the address `serv_addr`'''
        self.sock.connect(serv_addr)


class ProxyServer(object):
    def __init__(self,addr):
        self.address = addr

        '''Creates IPv4 TCP socket'''
        self.listensock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        '''
        `SO_REUSEADDR` enables a socket to bind to an address even if the address is already in use by another socket. This option is useful when a server needs to restart quickly after a previous execution, as it allows the server to bind to the same address without waiting for the operating system to release the previous socket. Allows multiple sockets to bind to the same address and port combination. This can be helpful in scenarios where you want to run multiple instances of a server on the same machine, each listening on the same port but serving different clients.
        '''
        '''Allows the socket to reuse the address immediately, even if it was recently used by another socket'''
        self.listensock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listensock.bind(self.address)
        '''The argument indicates that the socket can queue up to 5 incoming connections that are waiting to be accepted'''
        self.listensock.listen(5)
        self.connections = {}
        self.revcon = {}                    # map from a socket to a ProxyConnection
        self.readsockets = []               # all sockets which can be read
        self.writesockets = []              # all sockets which can be written
        self.allsockets = [self.listensock] # all opened sockets
        self.connection_count = 0           # count of all active connections
        self.clientsocket = None
        self.datacarry = ''
        self.clientsocks = []

    def run(self):
        '''
        `select()` takes three lists of I/O objects as arguments: the input sources to be monitored for readability, the output sources to be monitored for writability, and the sources to be monitored for exceptional conditions. It blocks until at least one of the specified I/O sources becomes ready or a timeout occurs.

        `select()` function returns three lists of objects: the subsets of the input, output, and exceptional source lists that are ready for reading, writing, or have exceptional conditions, respectively. By checking these lists, you can determine which I/O sources are ready for further operations without blocking and wasting resources.

        Typical select.select() usage:
        ```
        import select
        import socket

        # Create a socket and bind it to an address
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('localhost', 8080)
        server_socket.bind(server_address)
        server_socket.listen(5)

        inputs = [server_socket]  # List of input sources to monitor

        while True:
            # Wait for I/O readiness or a timeout of 1 second
            ready_to_read, ready_to_write, exceptions = select.select(inputs, [], [], 1.0)

            for source in ready_to_read:
                if source is server_socket:
                    # New connection is available
                    client_socket, client_address = server_socket.accept()
                    inputs.append(client_socket)
                    print(f"New client connected: {client_address}")
                else:
                    # Existing connection has data to read
                    data = source.recv(4096)
                    if data:
                        print(f"Received data: {data.decode()}")
                    else:
                        # Connection closed
                        inputs.remove(source)
                        source.close()
        ```

        select.select(inputs, [], [], timeout) is used to wait until there is input ready to be read from the inputs list (in this case, the server_socket for accepting new connections and client sockets for receiving data). It blocks until either one or more sockets become ready or the timeout (1 second) is reached.

        When a socket becomes ready, the corresponding action can be performed. In the example, if the server_socket becomes ready, it means a new client connection is available, so it can be accepted and added to the inputs list. If a client socket becomes ready, it means there is data to be read, so it can be received and processed. If the received data is empty, it indicates that the client has closed the connection, so the socket is removed from the inputs list and closed.

        By using select, you can efficiently handle I/O operations on multiple sources without having to create threads or processes for each source, resulting in more scalable and responsive I/O handling in your applications.
        '''

        loop = 0
        while True:
            # block until there is some activity on one of the sockets, timeout every 60 seconds by default
            r, w, e = select.select(
                            [self.listensock]+self.readsockets+self.clientsocks,
                            [],
                            [self.listensock]+self.readsockets)
            loop += 1
            # handle any reads
            for s in r:
                if s is self.listensock:
                    # open a new connection
                    clientsocket,clientaddr=s.accept()
                    self.clientsocks.append(clientsocket)

                elif s in self.clientsocks:
                    newcon=s.recv(4096)

                    self.addDATA(newcon)

                else:
                    if s in self.connections:

                        try:
                            data=s.recv(4096)

                        except:
                            data=''
                        pr=self.connections[s]
                        if len(data)==0:
                            self.communicate(pr.clientid,pr.conid,'F',data)
                            self.deactivateRead(self.revcon[pr.conid])
                            del self.revcon[pr.conid]

                            s.close()
                        else:
                            self.communicate(pr.clientid,pr.conid,'D',data)

        self.sock.close()
        self.sock = None

    def addDATA(self,data):
        '''
        Handles incoming data packets and processes them based on a specific format. Parses incoming data packets, extracts relevant information from the packet headers, and performs specific actions based on the extracted command.

        1. It appends the received `data` to the `datacarry` attribute of the class.
        2. It enters a loop (`while flag`) to process the data packets in `datacarry`.
        3. If the length of `datacarry` is less than 21 bytes, it breaks out of the loop since it doesn't have enough data to process.
        4. If the length of `datacarry` is 21 bytes or more, it extracts the connection ID, command, and size from the data header:
        - `connid`: First 16 bytes of `datacarry`.
        - `cmd`: The 17th byte of `datacarry` (interpreted as a single character).
        - `size`: An unsigned integer (4 bytes) obtained from bytes 17 to 20 of `datacarry`.
        5. If the combined size of the header and payload (`size + 21`) is less than or equal to the length of `datacarry`, it extracts the new packet (`newpkt`) from `datacarry` using the calculated size.
        6. It processes the packet based on the extracted command (`cmd`):
        - If `cmd` is 'O', it tries to send the payload of the packet to a socket identified by `sockid` within the `revcon` dictionary.
        - If `cmd` is 'N', it extracts the necessary information (client ID, IP, and port) from the payload (`newcon`) and calls the `open` method with the extracted parameters.
        - If `cmd` is 'Q', it retrieves the `sockid` from the payload and performs necessary cleanup operations, such as deactivating read operations, closing the corresponding socket, and removing it from the `revcon` dictionary.
        7. If any exceptions occur during the processing of a packet, it prints the traceback information to `sys.stderr`.
        8. If the combined size of the header and payload matches the length of `datacarry`, it clears the `datacarry` attribute and sets `flag` to False, indicating that all the data has been processed.
        9. If the combined size of the header and payload is larger than the length of `datacarry`, it sets `flag` to False to exit the loop since there is not enough data to process another packet.
        
        `TLSConnection` has a function called `addDATA` as well which only handles the 'S' command.
        '''
        self.datacarry+=data
        flag=True

        while flag:
            if len(self.datacarry)<21:
                break
            connid=self.datacarry[:16]
            cmd= struct.unpack('>c',self.datacarry[16:17])[0]
            size=struct.unpack('>I',self.datacarry[17:21])[0]
            if size+21<=len(self.datacarry):
                newpkt=self.datacarry[21:size+21]
                #print ("DATA ",cmd," size",size)
                try:
                    if cmd=='O':
                        try:
                            sockid=newpkt[:16]
                            self.revcon[sockid].sendall(newpkt[16:])
                        except:
                            self.communicate(connid,sockid,'F','')
                    elif cmd=='N':
                        newcon=newpkt
                        #print (newcon)
                        try:
                            clid,ip,port= newcon[:16],newcon[16:].split(':')[0],int(newcon[16:].split(':')[1])
                            self.open((ip,port),connid,clid)

                        except:
                            print ('ERROR',newcon)
                            traceback.print_exc(file=sys.stderr)
                    elif cmd=='Q':
                        sockid=newpkt[:16]
                        self.deactivateRead(self.revcon[sockid])

                        self.revcon[sockid].close()

                        del self.revcon[sockid]
                except:
                    traceback.print_exc(file=sys.stderr)
                if size+21 == len(self.datacarry):
                    self.datacarry=''
                    flag=False
                else:
                    self.datacarry=self.datacarry[size+21:]

            else:
                flag=False

    def activateRead(self,sock):
        if not sock in self.readsockets:
            self.readsockets.append(sock)

    def deactivateRead(self,sock):
        if sock in self.readsockets:
            self.readsockets.remove(sock)

    def activateWrite(self,sock):
        if not sock in self.writesockets:
            self.writesockets.append(sock)

    def deactivateWrite(self,sock):
        if sock in self.writesockets:
            self.writesockets.remove(sock)

    def registerSocket(self,sock,conn):
        self.connections[sock] = conn
        self.allsockets.append(sock)

    def unregisterSocket(self,sock,conn):
        del self.connections[sock]
        self.allsockets.remove(sock)

    # open a new proxy connection from the listening socket
    def communicate(self,clientid,conid,CMD,data):
        '''
        Responsible for sending a command (`CMD`) and associated data to a set of client sockets. The `communicate` method sends a command and associated data to multiple client sockets by iterating over them and sending the formatted packet.

        1. It takes four parameters: `clientid` (client ID), `conid` (connection ID), `CMD` (command), and `data` (data to be sent).
        2. It prints a log message indicating the command being sent and the current timestamp.
        3. It iterates over a collection of client sockets (`self.clientsocks`).
        4. For each client socket (`c`), it sends a packet composed of the following parts concatenated together:
        - `clientid`: The client ID.
        - `conid`: The connection ID.
        - `struct.pack('>c', CMD)`: The command packed as a single character using big-endian byte order.
        - `struct.pack('>I', len(data))`: The length of the data packed as a 4-byte unsigned integer using big-endian byte order.
        - `data`: The actual data to be sent.
        5. The `sendall` method is used to send the entire packet through the client socket.
        '''
        print ('sendding command',CMD,datetime.datetime.now())
        for c in self.clientsocks:
            c.sendall('%s%s%s%s%s'%(clientid,conid,struct.pack('>c',CMD),struct.pack('>I',len(data)),data))

    def open(self,server,clientid,clid):
        '''
        Responsible for establishing a new connection with a server and performing the necessary setup steps. The `open` method establishes a new connection with a server, adds the connection to relevant dictionaries, activates reading for the socket, and communicates the new connection information to the client.

        1. It takes three parameters: `server` (a tuple containing the server IP address and port), `clientid` (client ID), and `clid` (connection ID).
        2. It prints a log message indicating the IP address of the server.
        3. It creates a new `ProxyConnection` object called `conn` by passing the `server` and `clientid` as arguments.
        4. It adds the `conn.sock` (socket object) to a `connections` dictionary, using the socket as the key and the `conn` object as the value.
        5. It adds the `conn.sock` to a `revcon` dictionary, using the `conn.conid` (connection ID) as the key and the socket as the value.
        6. It activates reading for the socket by calling the `activateRead` method with `conn.sock` as the argument.
        7. It communicates with the client by calling the `communicate` method with the following arguments:
        - `conn.clientid` (client ID)
        - `conn.conid` (connection ID)
        - `'C'` (command indicating a new connection)
        - `clid` (connection ID)
        8. The `communicate` method will handle sending the command and associated data to the appropriate client sockets.
        '''
        print ('NEW CONNECTION %s'%server[0])
        conn = ProxyConnection(server,clientid)
        self.connections[conn.sock]=conn
        self.revcon[conn.conid]=conn.sock
        self.activateRead(conn.sock)
        self.communicate(conn.clientid,conn.conid,'C',clid)


if __name__ == '__main__':
    try:
        proxy = sys.argv[1].split(":")
        dest = sys.argv[2].split(":")
        proxyhost = proxy[0]
        proxyport = int(proxy[1])
        serverhost = dest[0]
        serverport = int(dest[1])
    except:
        sys.exit(-1)

    logger = logging.getLogger('simpleproxy')
    logger.setLevel(logging.INFO)
    hdlr = logging.StreamHandler()
    hdlr.setLevel(logging.INFO)
    hdlr.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(hdlr)
