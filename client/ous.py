import re
import logging
import urllib
from datetime import datetime

from urlparse import urlparse

import uuid
from twisted.internet import protocol, defer
from twisted.internet import reactor, ssl, task
from twisted.protocols import basic
from twisted.web import http, proxy

from browser import FirefoxDriver, PhantomDriver
from util import HttpResponse

log = logging.getLogger(__name__)

SMALL_RESPONSE_LIMIT = 1024

class ProxyUpstreamProtocol(protocol.Protocol):
    '''
    `ProxyUpstreamProtocol` is a subclass of `twisted.internet.protocol.Protocol`. This class represents the protocol that is responsible for handling the communication with the upstream proxy server.
    It provides methods for sending data upstream and downstream, handles connection events, and terminates the connection when necessary.
    '''
    def __init__(self):
        '''
        Initializes the protocol object.
        It sets the `dataReceived` attribute to the `send_downstream()` method, indicating that incoming data should be sent downstream to the proxy.
        '''
        self.dataReceived = self.send_downstream
        self.proxy = None
        self.connected = False

    def connectionMade(self):
        '''
        Twisted function. `connectionMade()` method is called when a connection is established with the upstream proxy server.
        It sets the `connected` flag to `True` and assigns the proxy object from the factory to the `proxy` attribute. If the proxy is already connected to a remote server, it calls `remote_connected()` on the proxy object passing itself as an argument. Otherwise, it calls `lose_connection()` to terminate the connection.
        '''
        self.connected = True
        self.proxy = self.factory.proxy
        if self.proxy.connected:
            self.proxy.remote_connected(self)
        else:
            self.lose_connection()

    def send_upstream(self, data):
        '''
        `send_upstream()` method is used to send data upstream to the proxy server.
        It uses the `transport.write()` method to send the provided `data`.
        '''
        self.transport.write(data)

    def send_downstream(self, data):
        '''
        `send_downstream()` method is used to send data downstream to the proxy.
        It simply calls `transport.write()` on the proxy's transport object to send the data.
        '''
        self.proxy.transport.write(data)

    def connectionLost(self, *args):
        '''
        Twisted function. `connectionLost()` method is called when the connection is lost or closed.
        It updates the `connected` flag to `False` and calls `lose_connection()` on the proxy to terminate the connection.
        '''
        # log.debug("Proxy remote connection closed")
        self.connected = False
        self.proxy.lose_connection()

    def lose_connection(self):
        '''
        `lose_connection()` method is used to terminate the connection by calling `transport.loseConnection()` if the protocol is currently connected.
        '''
        if self.connected:
            self.transport.loseConnection()


class ProxyServerProtocol(basic.LineReceiver):
    '''
    `ProxyServerProtocol` class handles incoming connections, parses the CONNECT request, initiates connections to remote servers, and facilitates communication between the client and the remote server through instances of `ProxyUpstreamProtocol`.
    '''
    
    '''
    `LineReceiver` is a protocol class provided by the Twisted framework in the `twisted.protocols.basic` module. `LineReceiver` is designed to handle protocols where data is received and processed line by line.
    It provides methods and callbacks to handle the incoming data, split it into lines, and perform actions based on the received lines.
    '''
    
    def __init__(self):
        self.address = None
        self.remote = None
        self.connected = True
        self.ous = None

    def connectionMade(self):
        '''
        Twisted function `connectionMade()` method is called when a connection is established. 
        It sets the `ous` attribute to the factory's `ous` attribute.
        '''
        self.ous = self.factory.ous

    def lineReceived(self, line):
        '''
        Twisted function `lineReceived()` method is called when a line of data is received. 
        It checks if the received line matches a CONNECT request pattern (using regular expressions) and extracts the host and port information from it. If no match is found, the method returns.
        '''
        if not len(line.strip()):
            self.end_of_headers()

        match = re.match('CONNECT (.+)[:](\d+) HTTP/1[.]\d', line)

        if match is None:
            return

        host, port = match.groups()
        self.address = (host, int(port))

    def rawDataReceived(self, data):
        '''
        Twisted function `rawDataReceived()` method is called when raw data is received.
        If the `remote` attribute is not yet set (indicating that the remote connection has not been established), it logs an error and terminates the connection. Otherwise, it forwards the data to the `remote` protocol's `send_upstream()` method.
        '''
        if self.remote is None:
            log.error("Data received before remote was connected, aborting")
            self.transport.loseConnection()
            return

        self.remote.send_upstream(data)

    def end_of_headers(self):
        '''
        `end_of_headers()` method is called when the end of the headers section is reached.
        If no address has been extracted from a CONNECT request, it logs an error and terminates the connection. Otherwise, it determines whether to start a covert proxy session or a vanilla proxy session based on the address. It calls the `start_proxy()` method accordingly.
        '''
        if self.address is None:
            log.error("No CONNECT received, aborting")
            self.transport.loseConnection()
            return

        self.line_mode = 0

        if self.ous.is_overt_address(self.address[0]):
            # print("YES {}".format(self.address[0]))
            # log.debug("Starting covert proxy session")
            self.start_proxy('127.0.0.1', self.ous.proxy_handler_port)
        else:
            # log.debug("Starting vanilla proxy session")
            # print("NO  {}".format(self.address[0]))
            self.start_proxy(*self.address)

    def start_proxy(self, host, port):
        '''
        `start_proxy()` method creates a `ClientFactory` and assigns it the `ProxyUpstreamProtocol` as the protocol class, indicating that instances of `ProxyUpstreamProtocol` will be created for each outgoing connection.
        It sets the `proxy` attribute of the factory to `self` and initiates a TCP connection to the specified `host` and `port` using the factory to create the protocol instances. This initiates the outgoing connection and starts communication with the remote server.
        '''
        factory = protocol.ClientFactory()
        factory.protocol = ProxyUpstreamProtocol
        factory.proxy = self
        reactor.connectTCP(host, port, factory)

    def remote_connected(self, remote):
        '''
        `remote_connected()` method is called when the remote connection is established.
        It assigns the `remote` protocol instance to the `remote` attribute and sends an HTTP response indicating a successful connection to the client.
        '''
        self.remote = remote
        self.transport.write('HTTP/1.1 200 OK\r\n\r\n')

    def connectionLost(self, *args):
        '''
        Twisted function `connectionLost()` method is called when the connection is lost.
        It sets the `connected` attribute to `False` and, if the `remote` attribute is not `None`, calls the `lose_connection()` method of the `remote` protocol.
        '''
        # log.debug("Proxy connection closed")
        self.connected = False
        if self.remote is not None:
            self.remote.lose_connection()

    def lose_connection(self):
        '''
        `lose_connection()` method is used to terminate the connection if it is still open.
        '''
        if self.connected:
            self.transport.loseConnection()


class OvertRequest(http.Request):
    '''
    `OvertRequest` is a subclass of the `twisted.web.http.Request` class. This subclass extends the functionality of handling HTTP requests.
    '''
    def process(self):
        '''
        `process` method in the `twisted.web.http.Request` class is responsible for processing an incoming HTTP request.
        It is a core method in the Twisted framework's `http` module. The `process` method is typically called by the HTTP server when a new request is received.
        '''
        ous = self.channel.ous
        request_cache = ous.request_cache

        # print(self.uri)
        self.content_data = self.content.read()
        use_as_covert = True  # self.method == 'GET'
        overt = ous.get_overt_connection(self.getRequestHostname())
        assert overt is not None

        cache_params = getattr(overt.channel, 'cache_parameters', [])
        cache_key = self.getRequestHostname() + self.path + '?' + urllib.urlencode({k: self.args.get(k, '') for k in cache_params})
        self.cache_key = cache_key

        # Ideally only get requested be cached, but then I have to be able to get the response back from
        # the channel to have something to send back in response
        if use_as_covert and cache_key not in request_cache:
            print("Populating Cache", cache_key)
            return request_cache.populate_cache(self).addCallback(self.cache_response_received)

        response_size = len(request_cache[cache_key])
        use_as_covert = use_as_covert and response_size <= SMALL_RESPONSE_LIMIT

        # TODO: MAJOR, send POST requests in vanilla mode
        if self.method == "GET":
            if overt:
                overt.send_overt_request(
                        self.build_http_request({'connection': 'keep-alive'}),
                        use_as_covert=use_as_covert,
                        expected_response_size=len(request_cache[cache_key])
                )
            else:
                log.error("Overt connection not found for host {}".format(self.getRequestHostname()))


        # Respond the request from cache
        # log.debug("Responding from cache for {}".format(self.uri))
        self.transport.write(request_cache[cache_key])

    def build_http_request(self, headers=None):
        '''
        Used to construct the HTTP request string based on the request method, URI, headers, and content data.
        '''
        request_lines = ['{} {} {}'.format(self.method, self.uri, self.clientproto)]

        _headers = self.getAllHeaders()
        if headers is not None:
            _headers.update(headers)


        for header in _headers:
            request_lines.append('{}: {}'.format(header.title(), _headers[header]))

        request_lines.append('\r\n')
        request_lines.append(self.content_data)
        return '\r\n'.join(request_lines)

    def cache_response_received(self, response):
        '''
        Writes the response to the transport.
        '''
        self.transport.write(response)


class RequestCache:
    '''
    `RequestCache` class manages caching of HTTP requests and responses.
    '''

    class CacheRequestProtocol(protocol.Protocol):
        '''
        `CacheRequestProtocol` class is a protocol implementation that handles cache requests and manages the response data.
        '''

        def __init__(self):
            '''
            Initializes the `CacheRequestProtocol` instance. It creates an empty buffer `_buffer` and an `HttpResponse` object to store the response.
            '''
            self._buffer = []
            self.response = HttpResponse()

        def connectionMade(self):
            '''
            Called when the connection is made. It triggers the `send_request()` method to send the cache request.
            '''
            self.send_request()

        def connectionLost(self, reason=None):
            '''
            Called when the connection is lost.
            '''
            # print("Connection Lost", reason)
            pass
            
        def send_request(self):
            '''
            Sends the cache request by writing it to the transport. It uses the `build_http_request()` method of the associated `Request` object to construct the request and writes it to the transport. The request is followed by two newlines (`\r\n\r\n`) to indicate the end of the request.
            '''
            # log.debug("Sending cache request for {}".format(self.factory.request.uri))
            # request = self.factory.request.build_http_request({'connection': 'close'})
            request = self.factory.request.build_http_request()
            self.transport.write(request)
            self.transport.write('\r\n\r\n')

        def dataReceived(self, data):
            '''
            Called when data is received from the cache server. It appends the received data to the response object by calling `self.response.write(data)`. Then, it checks if the response is finished by checking `self.response.finished`. If the response is finished, it calls the `done()` method.
            '''
            self.response.write(data)

            if self.response.finished:
                self.done()
            # self._buffer.append(data)

        # def connectionLost(self, *args):
        #     response = ''.join(self._buffer)
        #     self._buffer = []
        #     self.factory.response_received(self.factory.request_id, self.factory.request.cache_key, response)

        def done(self):
            '''
            Called when the response is complete. It sets various headers for the response --- 'Expires', 'Last-Modified', 'Cache-Control', and 'Pragma'. Then, it converts the response object to raw data using the `to_raw()` method and notifies the associated `RequestCache` object about the response by calling `self.factory.response_received()`. Finally, it closes the connection by calling `self.transport.loseConnection()`.
            '''
            self.response.set_header('Expires', 'Tue, 03 Jul 2001 06:00:00 GMT')
            self.response.set_header('Last-Modified', datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT'))
            self.response.set_header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
            self.response.set_header('Cache-Control', 'post-check=0, pre-check=0')
            self.response.set_header('Pragma', 'no-cache')

            response = self.response.to_raw()
            # print(response)
            self.factory.response_received(self.factory.request_id, self.factory.request.cache_key, response)
            self.transport.loseConnection()

    def __init__(self):
        self._cache = {}
        self.__contains__ = self._cache.__contains__
        self.__getitem__ = self._cache.__getitem__
        self._pending_requests = {}

    def populate_cache(self, request):
        request_id = str(uuid.uuid4())[:8]
        d = defer.Deferred()
        self._pending_requests[request_id] = d

        factory = protocol.ClientFactory()
        factory.protocol = self.CacheRequestProtocol
        factory.request = request
        factory.response_received = self.response_received
        factory.request_id = request_id
        reactor.connectSSL(request.getRequestHostname(), 443, factory, ssl.ClientContextFactory())

        return d

    def response_received(self, request_id, path, response):
        self._cache[path] = response
        # print('CACHE', path, len(response))
        d = self._pending_requests.pop(request_id)
        d.callback(response)


class OvertUserSimulator(object):
    '''
    The `OvertUserSimulator` class represents a user simulator that interacts with multiple overt servers. It acts as a proxy and browser to simulate user behavior and perform requests through the overt servers.
    '''
    proxy_port = 7070
    proxy_handler_port = 6060

    def __init__(self, overt_urls, overts):
        '''
        Initializes the `OvertUserSimulator` object. It takes a list of Overt server URLs (`overt_urls`) and the Overt server instances (`overts`) as parameters.
        '''
        if type(overts) is not list and type(overts) is not tuple:
            overts = [overts]
        self.overts = overts

        if type(overt_urls) is str:
            overt_urls = [overt_urls]

        if not len(overt_urls):
            raise ValueError('Must specify at least one overt url')

        self.overt_urls = overt_urls
        self.overt_url_iterator = 0

        self.browser = None
        self.request_cache = RequestCache()

    def start(self):
        '''
        Starts the user simulator by initiating the proxy, proxy handler, and browser components.
        '''
        self.start_proxy()
        self.start_proxy_handler()
        self.start_browser()

    '''
    The proxy server captures incoming requests and passes them to the proxy handler server, which processes the requests, communicates with the overt servers, and generates appropriate responses. The proxy server then forwards these responses back to the client.
    '''

    def start_proxy(self):
        '''
        Starts the proxy server by creating a `ProxyServerProtocol` instance and listening on the `proxy_port`.
        '''
        proxy_factory = protocol.ServerFactory()
        proxy_factory.protocol = ProxyServerProtocol
        proxy_factory.ous = self
        reactor.listenTCP(self.proxy_port, proxy_factory)

    def start_proxy_handler(self):
        '''
        Starts the proxy handler server by creating an `OvertHTTPChannel` instance and listening on the `proxy_handler_port`. It uses an SSL context to enable secure communication.
        '''
        httpchannel = type('OvertHTTPChannel', (http.HTTPChannel, object), {'requestFactory': OvertRequest})
        httpchannel.ous = self
        webserver = protocol.ServerFactory()
        webserver.protocol = httpchannel
        reactor.listenSSL(self.proxy_handler_port, webserver, ssl.DefaultOpenSSLContextFactory('cert/key.pem', 'cert/cert.pem'))

    def start_browser(self):
        '''
        Starts the browser component of the user simulator using `PhantomDriver`. It configures the browser to use the proxy server and disables caching and certificate verification. It also queues the URLs from `overt_urls` in a loop to simulate browsing behavior.
        '''
        self.browser = PhantomDriver({
            'cache': False,
            'proxy': {
                'ssl': {'host': '127.0.0.1', 'port': self.proxy_port}
            },
            'verify_certs': False
        })
        self.browser.start()

        def _load_overt():
            self.browser.queue_url(self.overt_urls[self.overt_url_iterator])
            self.overt_url_iterator = (self.overt_url_iterator + 1) % len(self.overt_urls)

        browser_loop = task.LoopingCall(_load_overt)
        browser_loop.start(1)

    def add_overt(self, overt):
        '''
        Adds an additional overt server instance to the simulator.
        '''
        self.overts.append(overt)

    def is_overt_address(self, host):
        '''
        Checks if the given host is associated with any of the overt server instances in the simulator.
        '''
        for overt in self.overts:
            if host in overt.channel.overt_hosts:
                return True
        return False

    def get_overt_connection(self, host):
        '''
        Retrieves the overt server instance associated with the given host.
        '''
        for overt in self.overts:
            if host in overt.channel.overt_hosts:
                return overt
        return None

if __name__ == '__main__':
    from client import OvertGateway

    '''
    Sets up an instance of `OvertUserSimulator` and starts the proxy and proxy handler. It then starts the reactor to run the event loop.
    '''

    overt = OvertUserSimulator(OvertGateway(None), 'https://www.bing.com')
    overt.start_proxy()
    overt.start_proxy_handler()

    reactor.run()
