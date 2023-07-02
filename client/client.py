import base64
import logging
import uuid
from Queue import Queue, Empty
from functools import partial
from twisted.internet import reactor, protocol, task
from twisted.internet.defer import Deferred
from twisted.internet.protocol import Protocol, Factory, ClientFactory

from channels import *
from ous import OvertUserSimulator
from socks import Socks5Protocol
from util import Buffer

log = logging.getLogger(__name__)

try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
    from scapy_ssl_tls import ssl_tls_crypto
except ImportError:
    raise
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *

tls_version = TLSVersion.TLS_1_2


"""
OvertGateway(ClientFactory)
    - protocol -> OvertConnection(Protocol)

OvertConnection(Protocol)

CovertConnection

Waterfall(ClientFactory)
    - protocol -> ?
"""


class OvertConnection(Protocol):
    """
    `OvertConnection` is the protocol used in `OvertGateway(ClientFactory)`.

    `self.factory` refers to `OvertGateway`'s methods.
    """

    KEEPALIVE_INTERVAL = 1

    HEADER_SIZE = 21
    COMMANDS = ["C", "R", "D", "F"]

    def __init__(self, *args, **kwargs):
        self.state = None
        self.channel_uuid = str(uuid.uuid4().bytes)
        self.ready = False

        self._buffer = []
        self._tls_recv_buffer = []
        self._tls_recv_deferred = None

        self._keepalive_loop = None

        self._datacarry = ""
        self._tlscarry = ""
        self._havecommand = False

        self.tls_ctx = ssl_tls_crypto.TLSSessionCtx(True)

    def connectionMade(self):
        """
        Twisted function. This method is called when the network connection is successfully established.
        """
        self.factory.channel_connected(self)

    """
    `channel_ready`, `connection_established`, `connection_data_received`, and `connection_closed` methods handle various events related to the connection and notify the corresponding factory `OvertGateway(ClientFactory)`.
    """

    def channel_ready(self, *args):
        self.ready = True
        self.factory.channel_ready()

    def connection_established(self, conn_uuid, conn_id):
        self.factory.connection_established(conn_uuid, conn_id)

    def connection_data_received(self, conn_id, data):
        self.factory.connection_data_received(conn_id, data)

    def connection_closed(self, connid):
        self.factory.connection_closed(connid)

    def establish_tls(self):
        """
        - The `establish_tls` method is responsible for establishing the TLS connection. It calls several methods (`_tls_hello`, `_tls_client_key_exchange`, `_tls_finish_handshake`) in sequence using Twisted's `Deferred` mechanism.
        - Each TLS-related method handles a specific part of the TLS handshake process.
        - Returns a `Deferred()` object
        """
        d = self._tls_hello()
        d.addCallback(self._tls_client_key_exchange)
        d.addCallback(self._tls_finish_handshake)
        d.addCallback(partial(self.do_next, self.add_tls_pkt))
        return d

    def _tls_hello(self):
        log.info("Sending TLS hello...")
        # pec = '006d000b000403000102000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f0010001100230000000d0020001e060106020603050105020503040104020403030103020303020102020203000f000101'
        # ur = b''.join([chr(int(pec[i:i + 2], 16)) for i in range(0, len(pec), 2)])

        extensions = [
            TLSExtension() / TLSExtECPointsFormat(),
            TLSExtension() / TLSExtSupportedGroups(),
        ]

        # cipher_suites = ssl_tls_crypto.TLSSecurityParameters.crypto_params.keys()
        # cipher_suites = [TLSCipherSuite.ECDHE_RSA_WITH_AES_128_CBC_SHA256, ]

        # cipher_suites = [TLSCipherSuite.ECDHE_RSA_WITH_AES_256_CBC_SHA, ]

        ###############
        cipher_suites = [
            TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ]
        # self.tls_ctx.params.negotiated.key_exchange = TLSKexNames.ECDHE
        ###########

        """
        Constructs a TLS ClientHello message using the TLSRecord and TLSHandshakes classes from the `cryptography.hazmat.primitives.ssl` module.

        `/` is a shorthand notation in scapy library for concatenating protocol layers.
        """
        client_hello = TLSRecord(version=tls_version) / TLSHandshakes(
            handshakes=[
                TLSHandshake()
                / TLSClientHello(
                    version=tls_version,
                    compression_methods=[
                        TLSCompressionMethod.NULL,
                    ],
                    cipher_suites=cipher_suites,
                    extensions=extensions,
                )
            ]
        )
        # client_hello = TLSRecord(version=tls_version) / TLSHandshake() / \
        #                TLSClientHello(version=tls_version, compression_methods=[TLSCompressionMethod.NULL, ],
        #                               cipher_suites=cipher_suites) / ur

        self.tls_sendall(client_hello)
        deferred = self.tls_recvall()
        return deferred

    def _tls_client_key_exchange(self, *args):
        log.info("Making TLS key exchange...")

        client_key_exchange = TLSRecord(version=tls_version) / TLSHandshakes(
            handshakes=[
                TLSHandshake() / self.tls_ctx.get_client_kex_data("LOAD")
            ]
        )
        client_ccs = TLSRecord(version=tls_version) / TLSChangeCipherSpec()
        self.tls_sendall(TLS.from_records([client_key_exchange, client_ccs]))

        deferred = self.tls_recvall()
        return deferred

    def _tls_finish_handshake(self, *args):
        self.tls_sendall(
            TLSRecord(version=tls_version)
            / TLSHandshakes(
                handshakes=[
                    TLSHandshake()
                    / TLSFinished(data=self.tls_ctx.get_verify_data())
                ]
            )
        )
        deferred = self.tls_recvall()
        return deferred

    def tls_sendall(self, pkt):
        """
        Sends TLS-encrypted data by converting the TLS packet into a string and writing it to the transport.
        """
        if self.tls_ctx.client_ctx.must_encrypt:
            data = str(tls_to_raw(pkt, self.tls_ctx, True, None, None, None))
        else:
            data = str(pkt)
        self.transport.write(data)
        self.tls_ctx.insert(pkt)

    def tls_recvall(self, timeout=0.7):
        """
        Sets up a deferred object and waits for TLS records to be received. It uses a timeout mechanism to handle cases where data is not received within a certain timeframe.
        """
        self._tls_recv_buffer = []
        self._tls_recv_deferred = Deferred()

        self.do_next(self._tls_recvall_part)

        reactor.callLater(timeout, self._tls_recvall_timeout)

        return self._tls_recv_deferred

    def _tls_recvall_part(self, data):
        self._tls_recv_buffer.append(data)

    def _tls_recvall_timeout(self):
        records = TLS("".join(self._tls_recv_buffer), ctx=self.tls_ctx)
        # records.show()

        # NOTE: It's important to clear this stuff before calling the callback
        # If it's called after the callback it could interfere with things set
        # if the callbacks return deferreds
        d = self._tls_recv_deferred
        self._tls_recv_deferred = None
        self._tls_recv_buffer = []

        self.do_next(None)

        if d is not None:
            d.addErrback(self._deferred_error)
            d.callback(records)

    def _deferred_error(self, err):
        log.error("Error occured in deferred callback")
        log.error(err)

    def do_next(self, method, *args):
        if method is not None and type(method) != str:
            method = method.__name__
        self.state = method

    def dataReceived(self, data):
        """
        - Twisted function. This method is called when data is received over the network connection.
        - It buffers the received data if the connection state is not yet determined or processes the data by invoking the appropriate method based on the current state.
        """
        if self.state is None:
            print("BUFFERING")
            self._buffer.append(data)
            return
        elif len(self._buffer):
            self._buffer.append(data)
            data = "".join(self._buffer)
            self._buffer = []

        if self.state is not None:
            method = getattr(self, self.state)
            method(data)
            return

        assert False

    def add_data(self, data):
        """
        - Processes the received data by extracting the command, connection ID, and payload from the received packet. It then calls the corresponding methods based on the command type.

        - Commands:
            - C = connection_established()
            - R = channel_ready()
            - D = connection_data_received()
            - F = connection_closed()
        """
        # print(data)
        # print ('HH',[ord(i) for i in  data])
        if len(data) == 0:
            return
        if not self._havecommand:
            cmd = struct.unpack(">c", (self._datacarry + data)[16:17])[0]
            if cmd not in self.COMMANDS:
                return
            else:
                self._havecommand = True

        self._datacarry += data

        flag = True
        while flag:
            if len(self._datacarry) < self.HEADER_SIZE:
                break
            connid = self._datacarry[:16]
            cmd = struct.unpack(">c", self._datacarry[16:17])[0]
            size = struct.unpack(">I", self._datacarry[17:21])[0]

            # print('pkt_riecive {} {}'.format(cmd, size))
            if size + self.HEADER_SIZE <= len(self._datacarry):
                newdata = self._datacarry[
                    self.HEADER_SIZE : self.HEADER_SIZE + size
                ]
                try:
                    if cmd == "C":
                        self.connection_established(newdata, connid)
                    if cmd == "R":
                        self.channel_ready()
                    if cmd == "D":
                        self.connection_data_received(connid, newdata)

                    if cmd == "F":
                        self.connection_closed(connid)
                    else:
                        raise ValueError("Unknown command {}".format(cmd))
                except:
                    pass
                # self.havecommand=False

                if size + self.HEADER_SIZE == len(self._datacarry):
                    flag = False
                    self._datacarry = ""
                else:
                    self._datacarry = self._datacarry[self.HEADER_SIZE + size :]

            else:
                flag = False

    def add_tls_pkt(self, pkt):
        """
        Processes received TLS packets, assembling them from fragmented data and calling `add_data` to process the decrypted payload.
        """
        # print("TTTTTTTTTLLLLLLLLLSSSSSSSS ", len(pkt))
        # records = TLS(pkt, ctx=self.tls_ctx)
        # records.show()
        self._tlscarry += pkt
        flag = True
        while flag:
            if len(self._tlscarry) > 5:
                size = struct.unpack("!H", self._tlscarry[3:5])[0]
                # print (size, [ord(i) for i in self.tlscarry[:3]])

                if size + 5 <= len(self._tlscarry):
                    data = self._tlscarry[5 : size + 5]
                    padsize = struct.unpack(">H", data[-2:])[0]

                    self.add_data(data[: len(data) - (2 + padsize)])
                    if size + 5 == len(self._tlscarry):
                        self._tlscarry = ""
                        flag = False
                    else:
                        self._tlscarry = self._tlscarry[size + 5 :]
                else:
                    flag = False
            else:
                flag = False

    def send(self, data, expected_response_size=None):
        self.tls_sendall(TLSPlaintext(data=data))


class CommandFactory:
    """
    The `CommandFactory` class provides static methods to generate different command messages used in the communication protocol.
    These commands are constructed by packing the necessary data into binary strings using `struct.pack()` and concatenating them with the appropriate command type.
    """

    @staticmethod
    def initialize_relay(channel_uuid):
        return "%s%s%s" % (
            struct.pack(">c", "S"),
            struct.pack(">I", len(channel_uuid)),
            channel_uuid,
        )

    @staticmethod
    def new_connection(addr, port, con_uuid):
        data = "%s%s:%s" % (con_uuid, addr, port)
        return "%s%s%s" % (
            struct.pack(">c", "N"),
            struct.pack(">I", len(data)),
            data,
        )

    @staticmethod
    def close_connection(conn_id):
        return "%s%s%s" % (
            struct.pack(">c", "Q"),
            struct.pack(">I", len(conn_id)),
            conn_id,
        )

    @staticmethod
    def data(data, conn_id):
        data = "%s%s" % (conn_id, data)
        return "%s%s%s" % (
            struct.pack(">c", "O"),
            struct.pack(">I", len(data)),
            data,
        )


class ChannelNotReadyError(Exception):
    pass


class OvertGateway(protocol.ClientFactory):
    """
    - `OvertGateway` class inherits from `ClientFactory`, which is a class provided by Twisted for creating client protocols and managing their connections.
    - It uses `OvertConnection` as its protocol.
    - Initializes
        - `self.new_connection`, `self.close_connection`, and `self.register_connection` class attributes to a function that raises `ChannelNotReadyError`.
        - `self.channel` to the passed in `channel` parameter `GoogleChannel()`.
        - `self.overt_connection` to `None`. Later assigned to a `OvertConnection` object named `channel`.
        - `self._covert_buffers`, `self.pending_connections`, and `self.connections` to dictionaries.
        - `self._buffer` to a `Buffer()` object from the `util.py` file. Used to store and manipulate binary data.
        - `self.on_channel_ready` to a Twisted `Deferred()` object.
    """

    protocol = OvertConnection

    def __init__(self, channel):
        self.channel = channel

        self.new_connection = self.raise_channel_not_ready
        self.close_connection = self.raise_channel_not_ready
        self.register_connection = self.raise_channel_not_ready

        self.overt_connection = None

        self._covert_buffers = {}
        self._buffer = Buffer()
        self.pending_connections = {}
        self.connections = {}

        self.on_channel_ready = Deferred()

    def start_channel(self):
        """
        - Create a TCP connection to `self.channel.host` and `self.channel.port`.
        - Connect to Google if `GoogleChannel()` being used
            - channel.host = '172.217.17.32'    // google.com
            - channel.port = 443                // HTTPS
        """
        reactor.connectTCP(self.channel.host, self.channel.port, self)

    def channel_connected(self, channel: OvertConnection):
        """
        - `OvertConnection(Protocol)`'s `connectionMade()` calls `self.factory.channel_connected(self)`.
        - `OvertConnection(Protocol)`'s `self.factory` refers to `OvertGateway(ClientFactory)`.
        - The `channel` parameter `self` passed to `self.factory.channel_connected(self)` is `OvertConnection(Protocol)`.
        - `OvertConnection(Protocol)` has an `establish_tls()` function.
        Could not find references to `channel_connected`, `establish_tls` elsewhere
        """
        self.overt_connection = channel

        log.info("Initializing overt channel...")
        d = self.overt_connection.establish_tls()
        d.addCallback(self.init_relay)

    def channel_ready(self, *args):
        log.info("Channel Ready")
        self.new_connection = self._new_connection
        self.register_connection = self._register_connection
        self.close_connection = self._close_connection

        self.on_channel_ready.callback(None)

    def connection_established(self, conn_uuid, conn_id):
        d = self.pending_connections[conn_uuid]
        d.callback(conn_id)
        del self.pending_connections[conn_uuid]

    def connection_data_received(self, connid, data):
        self.connections[connid].data_received(data)

    def connection_closed(self, connid):
        self.connections[connid].remote_closed()
        # TODO:
        # del self.connections[connid]

    def init_relay(self, *args):
        log.info("Initializing relay...")

        # if not self.channel.support_upstream:
        #     log.info("Non need, channel doesn't support upstream")
        #     self.on_channel_ready.callback(None)
        #     return

        data = self.overt_connection.channel_uuid
        self.send_covert_command(
            CommandFactory.initialize_relay(data), wait_for_overt=False
        )

    def _new_connection(self, addr, port, conn_uuid):
        command = CommandFactory.new_connection(addr, port, conn_uuid)
        self.send_covert_command(command)
        d = Deferred()
        self.pending_connections[conn_uuid] = d
        return d

    def _close_connection(self, conn_id):
        command = CommandFactory.close_connection(conn_id)
        self.send_covert_command(command)

    def _register_connection(self, connid, connection):
        self.connections[connid] = connection

    def send_overt_request(
        self, request, use_as_covert=False, expected_response_size=None
    ):
        use_as_covert = use_as_covert and self.channel.support_upstream

        covert_size = (
            self.channel.calculate_sendable_covert_data(len(request))
            if use_as_covert
            else 0
        )

        if use_as_covert and covert_size and self._buffer.has_data():
            covert_data = self._buffer.read(covert_size)
            wrapped_data = self.channel.wrap_message(covert_data)
            log.debug(
                "Sending {} Covert data on {}, total size: {}".format(
                    len(covert_data), self.channel.host, len(wrapped_data)
                )
            )
            self.overt_connection.send(
                wrapped_data, expected_response_size=expected_response_size
            )
        else:
            log.debug(
                "Sending {} Overt data on {}".format(
                    len(request), self.channel.host
                )
            )
            self.overt_connection.send(request)

    def send_covert_data(self, data, connid, wait_for_overt=True):
        # log.debug('Sending covert data for connection: {}'.format(connid))
        message = CommandFactory.data(data, connid)
        self.send_covert_command(message, wait_for_overt=wait_for_overt)

    def send_covert_command(self, command, wait_for_overt=True):
        if wait_for_overt:
            self._buffer.write(command)
        else:
            self.overt_connection.send(self.channel.wrap_message(command))

    def raise_channel_not_ready(self, *args, **kwargs):
        raise ChannelNotReadyError("Channel has not been initialized yet")


class CovertConnection:
    """
    `CovertConnection` class acts as an intermediary between a local connection (represented by `socks_conn`) and an overt protocol (`overt`) by managing the establishment, data transfer, and closure of the connections.
    """

    def __init__(self, overt, addr, port, local_con):
        self.overt = overt
        self.addr = addr
        self.port = port

        self.socks_conn = local_con

        self.uuid = str(uuid.uuid4().bytes)
        self.connid = None

    def make_connection(self):
        """
        - `make_connection` method is called to initiate the connection to the remote address and port using the `overt` protocol.
        - If the connection is successful it executes the callback `connection_made`. Otherwise if an error is encountered it executes `connection_failed`.
        - It returns a `Deferred` object representing the asynchronous result of the connection attempt.
        """
        log.info("Connecting {}:{}...".format(self.addr, self.port))
        d = self.overt.new_connection(self.addr, self.port, self.uuid)
        d.addCallback(self.connection_made)
        d.addErrback(self.connection_failed)
        return d

    def connection_made(self, connid):
        """
        - `connection_made` method is called when the connection to the remote address and port is successfully established.
        - It assigns the `connid` (connection identifier) received from the `overt` protocol, registers the `CovertConnection` instance with the `overt` protocol, and starts remote communication through the `socks_conn` object.
        """

        log.debug("Connection established...")

        self.connid = connid
        self.overt.register_connection(self.connid, self)

        self.socks_conn.start_remote_communication(self)

    def connection_failed(self, err):
        raise err

    def data_received(self, data):
        self.socks_conn.transport.write(data)

    def remote_closed(self):
        self.socks_conn.loseConnection()

    def local_closed(self):
        self.overt.close_connection(self.connid)

    def send(self, data):
        self.overt.send_covert_data(data, self.connid)


class Waterfall(ClientFactory):
    """
    - `Waterfall(ClientFactory)`. The `Waterfall` class inherits from `ClientFactory`. `ClientFactory` is a class provided by Twisted and is used to create client protocols and manage their connections.
    - Initializes an empty array `self.overts`
    - `self.overts` stores `OvertGateway(ClientFactory)` instances initialized with `channel`s like `GoogleChannel()`.
    """

    def __init__(self):
        self.overts = []

    def new_overt_connection(self, channel):
        """
        - `channel_gateway` is a `OvertGateway(ClientFactory)` instance initialized with `channel=GoogleChannel()`
        - `channel_gateway.start_channel()` starts TCP connection to 172.217.17.32:443 (Google:HTTPS)
        - Adds the `channel_gateway` instace to the `Waterfall` instance's `self.overts` list
        - Returns the `channel_gateway` instance
        """
        channel_gateway = OvertGateway(channel)
        channel_gateway.start_channel()
        self.overts.append(channel_gateway)
        return channel_gateway

    def new_covert_connection(self, socks_conn, addr, port):
        """
        - Takes the first `OvertGateway(ClientFactory)` instance initialiazed with a channel from the `overts` array and stores it in `overt`
        - Creates a `CovertConnection` instance `connection` using the parameters --- `OvertGateway` instance `overt`, address, port, SOCKS connection instance
        - Performs `connection.make_connection()` on the created `CovertConnection` instance `connection` which initiates a connection to the specified address and port, and returns a `Deferred` object that represents the asynchronous result of the connection attempt
        - Returns the created `CovertConnection` instance `connection`
        """
        overt = self.overts[0]

        connection = CovertConnection(overt, addr, port, socks_conn)
        connection.make_connection()
        return connection


def main():
    logging.root.setLevel(logging.DEBUG)
    logging.root.addHandler(logging.StreamHandler())

    waterfall = Waterfall()

    """
    `reactor` will use the `socks_factory = ServerFactory()` to create instances of `Socks5Protocol(Protocol)` to handle incoming SOCKS connections.
    """

    """
    This code sets up a SOCKS5 server that listens on port 2020 using Twisted's reactor. When a new SOCKS connection is established, the `new_covert_connection` method of the `waterfall` object is called to handle the connection. The `Socks5Protocol` class is used to process and handle the SOCKS protocol for each connection.
    """
    socks_factory = protocol.ServerFactory()
    socks_factory.on_socks_connect = waterfall.new_covert_connection
    socks_factory.protocol = Socks5Protocol
    reactor.listenTCP(2020, socks_factory)

    # channels = [AmazonChannel()]
    channels = [GoogleChannel()]
    # channels = [BingChannel()]
    # channels = [YahooChannel()]
    # channels = [WikipediaChannel()]
    overts = []

    def connect_overt(*args):
        if not channels:
            return
        channel = channels.pop()
        overt = waterfall.new_overt_connection(channel)
        overts.append(overt)

        """
        overt: OvertGateway(ClientFactory)
        overt.on_channel_ready: Deferred()
        """
        overt.on_channel_ready.addCallback(connect_overt)

    connect_overt()

    # queries = ['black', 'blue', 'red', 'random', 'nature', 'sky', 'building', 'wallpaper', 'town',
    #            'space', 'people', 'house', 'bear', 'water', 'atom', 'cow', 'icecream']
    queries = ["nature"]
    overt_urls = [
        "https://www.google.com/search?site=&tbm=isch&q={}".format(x)
        for x in queries
    ]
    """
    `overt_urls` has link to Google Image search for nature
    """
    # overt_urls = ['https://www.amazon.com']
    ous = OvertUserSimulator(overt_urls, overts)
    ous.start()

    reactor.run()


if __name__ == "__main__":
    main()
