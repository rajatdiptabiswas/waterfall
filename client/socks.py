import struct

from twisted.internet import protocol

'''
self.state = [
    '',
    'wait_hello',
    'wait_connect',
    'communicate'
]
'''

class Socks5Protocol(protocol.Protocol):
    '''
    SOCKS5 protocol server implemented using Twisted.
    It defines the `Socks5Protocol` class, which is a subclass of `twisted.internet.protocol.Protocol`.
    This class handles the logic of the SOCKS5 protocol, including the negotiation phase, connection establishment, and data communication.
    '''
    def __init__(self):
        self.state = ''
        self.remote = None

    def connectionMade(self):
        '''
        This method is called when a connection is made with the server.
        It sets the initial state to 'wait_hello'.
        '''
        self.state = 'wait_hello'

    def dataReceived(self, data):
        '''
        This method is called when data is received from the client.
        It delegates the processing of the data to the corresponding state method based on the current state of the protocol.

        if self.state == 'wait_hello':
            wait_hello(data)
        '''
        method = getattr(self, self.state)
        method(data)

    def wait_hello(self, data):
        '''
        Processes the initial handshake message received from the client in the SOCKS5 protocol.
        It handles the initial negotiation phase of the SOCKS5 protocol, where the server and client exchange supported authentication methods. It ensures that the protocol version is correct, there is at least one supported authentication method, and the selected method is handled accordingly. Otherwise, it terminates the connection.
        '''
        
        '''
        1. It unpacks the first two bytes of the data parameter using the struct.unpack function. These two bytes represent the SOCKS protocol version (ver) and the number of authentication methods supported (nmethods).

        2. It checks if the ver is equal to 5, which indicates the use of SOCKS5 protocol. If it's not, it closes the connection using self.transport.loseConnection() and returns.

        3. It checks if the nmethods is less than 1, which indicates that there are no supported authentication methods. If it's less than 1, it closes the connection and returns.

        4. It retrieves the authentication methods from the data starting from the third byte (data[2:2 + nmethods]).

        5. It iterates over each method and checks if the method is 0, which represents "no authentication". If it is, it sends a response packet indicating acceptance (resp = struct.pack('!BB', 5, 0)) and transitions the state to 'wait_connect'. It then sends the response packet to the client using self.transport.write(resp).
        If any method is 255, which represents "disconnect", it closes the connection and returns.

        6. If none of the above conditions match, it means the request is not processed correctly according to the SOCKS5 protocol. In this case, it closes the connection.
        '''
        (ver, nmethods) = struct.unpack('!BB', data[:2])
        if ver != 5:
            # we do SOCKS5 only
            self.transport.loseConnection()
            return
        if nmethods < 1:
            # not SOCKS5 protocol?!
            self.transport.loseConnection()
            return
        methods = data[2:2 + nmethods]
        for meth in methods:
            if ord(meth) == 0:
                # no auth, neato, accept
                resp = struct.pack('!BB', 5, 0)
                self.transport.write(resp)
                self.state = 'wait_connect'
                return
            if ord(meth) == 255:
                # disconnect
                self.transport.loseConnection()
                return
        # -- we should have processed the request by now
        self.transport.loseConnection()

    def wait_connect(self, data):
        '''
        Handles the client's connection request after the initial handshake in the SOCKS5 protocol.
        Handles the connection request from the client and performs the necessary checks and processing based on the command and address type. If the request is valid, it calls the `perform_connect` method to initiate the connection. Otherwise, it terminates the connection or raises an exception if the command is not implemented.
        '''

        '''
        1. It unpacks the first four bytes of the `data` parameter using the `struct.unpack` function. These four bytes represent the SOCKS protocol version (`ver`), command (`cmd`), reserved (`rsv`), and address type (`atyp`).

        2. It checks if the `ver` is equal to 5 and the `rsv` is equal to 0. If either of these conditions is not met, it indicates a protocol violation, and the connection is closed using `self.transport.loseConnection()`.

        3. It extracts the remaining data from the `data` parameter by slicing it with `data[4:]`.

        4. If the `cmd` is equal to 1, it means it's a "connect" command. It proceeds to handle the address and port information based on the `atyp`.
        - If `atyp` is 1, it indicates an IPv4 address. It unpacks the four bytes representing the address using `struct.unpack('!BBBB', data[:4])` and formats it as a string.
        - If `atyp` is 3, it indicates a domain name. It unpacks the length of the domain name (`l`) using `struct.unpack('!B', data[:1])` and extracts the domain name from the data.
        - If `atyp` is 4, it indicates an IPv6 address. Since IPv6 is not supported in this example, it raises a `RuntimeError` with a message indicating that IPv6 is not supported.
        - After extracting the address information, it extracts the port using `struct.unpack('!H', data[:2])`.
        - It then calls the `perform_connect` method with the extracted `host` and `port` values.

        5. If the `cmd` is 2, it means it's a "bind" command, which is not implemented. Therefore, it raises a `NotImplementedError` with a message indicating that "SOCKS Bind" is not implemented.

        6. If the `cmd` is 3, it means it's a "UDP associate" command, which is also not implemented. It raises a `NotImplementedError` with a message indicating that "SOCKS UDP" is not implemented.

        7. If none of the above conditions match, it means the request is not processed correctly according to the SOCKS5 protocol. In this case, it closes the connection.
        '''
        (ver, cmd, rsv, atyp) = struct.unpack('!BBBB', data[:4])
        if ver != 5 or rsv != 0:
            # protocol violation
            self.transport.loseConnection()
            return
        data = data[4:]
        if cmd == 1:
            host = None
            if atyp == 1:  # IP V4
                (b1, b2, b3, b4) = struct.unpack('!BBBB', data[:4])
                host = '%i.%i.%i.%i' % (b1, b2, b3, b4)
                data = data[4:]
            elif atyp == 3:  # domainname
                l, = struct.unpack('!B', data[:1])
                host = data[1:1 + l]
                data = data[1 + l:]
            elif atyp == 4:  # IP V6
                raise RuntimeError("IPV6 not supported")
            else:
                # protocol violation
                self.transport.loseConnection()
                return
            (port) = struct.unpack('!H', data[:2])
            port = port[0]
            data = data[2:]
            return self.perform_connect(host, port)
        elif cmd == 2:
            raise NotImplementedError("SOCKS Bind not implemented")
        elif cmd == 3:
            raise NotImplementedError("SOCKS UDP not implemented")

        # -- we should have processed the request by now
        self.transport.loseConnection()

    def send_connect_response(self, code):
        '''
        Responsible for sending a response to the client after the connection request has been processed.
        Constructs a response packet with the appropriate fields according to the SOCKS5 protocol. It includes the response code, the local IP address, and port, and sends it back to the client using the transport's write method.
        '''

        '''
        1. It tries to obtain the local host IP address using `self.transport.getHost().host` and assigns it to the `myname` variable. If an exception occurs during this process, it means that the socket is no longer present, and the connection should be terminated. In such a case, the method calls `self.transport.loseConnection()` to close the connection and then returns.

        2. It splits the `myname` string into four parts representing the IP address components and converts them into integers using a list comprehension. Each part of the IP address is converted to an integer using `int(i)` and stored in the `ip` list.

        3. It creates a response packet (`resp`) using `struct.pack` to pack the following values:
        - The SOCKS protocol version (`5`) and the response code (`code`) provided as arguments to the method.
        - The reserved field (`0`) and the address type (`1`) indicating an IPv4 address.
        - The IP address components (`ip[0]`, `ip[1]`, `ip[2]`, `ip[3]`) packed using `struct.pack('!BBBB', ...)`.
        - The local port obtained from `self.transport.getHost().port` packed using `struct.pack('!H', ...)`.

        4. Finally, it sends the response packet (`resp`) to the client by calling `self.transport.write(resp)`.
        '''
        try:
            myname = self.transport.getHost().host
        except:
            # this might fail as no longer a socket
            # is present
            self.transport.loseConnection()
            return
        ip = [int(i) for i in myname.split('.')]
        resp = struct.pack('!BBBB', 5, code, 0, 1)
        resp += struct.pack('!BBBB', ip[0], ip[1], ip[2], ip[3])
        resp += struct.pack('!H', self.transport.getHost().port)
        self.transport.write(resp)

    def perform_connect(self, host, port):
        if hasattr(self.factory, 'on_socks_connect'):
            self.factory.on_socks_connect(self, host, port)
        # if self.on_connect is not None:
        #     self.on_connect(self, host, port)

    def start_remote_communication(self, remote):
        self.remote = remote
        self.send_connect_response(0)
        self.state = 'communicate'

    def communicate(self, data):
        self.remote.send(data)
