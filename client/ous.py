import re
import logging
import urllib
from datetime import datetime, timedelta

from urlparse import urlparse

import uuid
from twisted.internet import protocol, defer
from twisted.internet import reactor, ssl, task
from twisted.protocols import basic
from twisted.web import http, proxy

from browser import FirefoxDriver, PhantomDriver
from util import HttpResponse

# log = logging.getLogger(__name__)
log = logging.getLogger("ous")
log.setLevel(logging.CRITICAL)

SMALL_RESPONSE_LIMIT = 1024
OUS_RATE = 3 # OUS sends a request every `OUS_RATE` seconds


class ProxyUpstreamProtocol(protocol.Protocol):
    def __init__(self):
        self.dataReceived = self.send_downstream
        self.proxy = None
        self.connected = False

    def connectionMade(self):
        self.connected = True
        self.proxy = self.factory.proxy # ProxyServerProtocol
        if self.proxy.connected:
            self.proxy.remote_connected(self)
        else:
            self.lose_connection()

    def send_upstream(self, data):
        log.info(
            "ProxyUpstreamProtocol - Sending upstream data... ProxyUpstreamProtocol.transport.write(data) len(data)={}".format(len(data))
        )
        self.transport.write(data)

    def send_downstream(self, data):
        log.info(
            "ProxyUpstreamProtocol - Sending downstream data... ProxyServerProtocol.transport.write(data) len(data)={}".format(
                len(data)
            )
        )
        self.proxy.transport.write(data)

    def connectionLost(self, *args):
        log.debug("ProxyUpstreamProtocol - Proxy remote connection closed")
        self.connected = False
        self.proxy.lose_connection()

    def lose_connection(self):
        log.info("ProxyUpstreamProtocol.transport.loseConnection() {}".format(self.transport.getPeer()))
        if self.connected:
            self.transport.loseConnection()


class ProxyServerProtocol(basic.LineReceiver):
    def __init__(self):
        self.address = None
        self.remote = None
        self.connected = True
        self.ous = None

    def connectionMade(self):
        self.ous = self.factory.ous

    def lineReceived(self, line):
        if not len(line.strip()):
            self.end_of_headers()

        log.debug("ProxyServerProtocol - Line received - {}".format(line))

        match = re.match("CONNECT (.+)[:](\d+) HTTP/1[.]\d", line)

        if match is None:
            log.debug("ProxyServerProtocol - No CONNECT line received")
            return

        host, port = match.groups()
        log.info("ProxyServerProtocol - {}:{} found".format(host, port))
        self.address = (host, int(port))

    def rawDataReceived(self, data):
        if self.remote is None:
            log.error(
                "ProxyServerProtocol - Data received before remote was connected, aborting"
            )
            self.transport.loseConnection()
            return

        self.remote.send_upstream(data)

    def end_of_headers(self):
        if self.address is None:
            log.error("ProxyServerProtocol - No CONNECT received, aborting")
            self.transport.loseConnection()
            return

        self.line_mode = 0

        if self.ous.is_overt_address(self.address[0]):
            # print("YES {}".format(self.address[0]))
            log.info(
                "Overt address {}? TRUE - Starting covert proxy session localhost:{}".format(
                    self.address[0], self.ous.proxy_handler_port
                )
            )
            # log.debug("Starting covert proxy session")
            self.start_proxy("127.0.0.1", self.ous.proxy_handler_port)
        else:
            # print("NO {}".format(self.address[0]))
            log.info(
                "Overt address {}? FALSE - Starting vanilla proxy session {}:{}".format(
                    self.address[0], self.address[0], self.address[1]
                )
            )
            # log.debug("Starting vanilla proxy session")
            self.start_proxy(*self.address)

    def start_proxy(self, host, port):
        factory = protocol.ClientFactory()
        factory.protocol = ProxyUpstreamProtocol
        factory.proxy = self
        log.info(
            "Connect TCP {}:{} ClientFactory:ProxyUpstreamProtocol".format(host, port)
        )
        reactor.connectTCP(host, port, factory)

    def remote_connected(self, remote):
        self.remote = remote # ProxyUpstreamProtocol
        self.transport.write("HTTP/1.1 200 OK\r\n\r\n")

    def connectionLost(self, *args):
        log.info(
            "ProxyServerProtocol - Proxy connection closed {}:{}".format(
                self.address[0], self.address[1]
            )
        )
        self.connected = False
        if self.remote is not None:
            self.remote.lose_connection()

    def lose_connection(self):
        log.info(
            "ProxyServerProtocol.transport.loseConnection() {} {}:{}".format(
                self.transport.getPeer(), self.address[0], self.address[1]
            )
        )
        if self.connected:
            self.transport.loseConnection()


class OvertRequest(http.Request):
    def process(self):
        ous = self.channel.ous
        request_cache = ous.request_cache

        # print(self.uri)
        self.content_data = self.content.read()
        # log.info("OvertRequest - content_data=\n{}".format(self.content_data))
        log.info("OvertRequest - len(content_data)={}".format(len(self.content_data)))
        use_as_covert = True  # self.method == 'GET'
        log.info("OvertRequest - getRequestHostname()={}".format(self.getRequestHostname()))
        overt = ous.get_overt_connection(self.getRequestHostname())
        assert overt is not None

        cache_params = getattr(overt.channel, "cache_parameters", [])
        cache_key = (
            self.getRequestHostname()
            + self.path
            + "?"
            + urllib.urlencode({k: self.args.get(k, "") for k in cache_params})
        )
        self.cache_key = cache_key

        log.info(
            "OvertRequest - cache_key={} in request_cache? {}".format(
                cache_key, cache_key in request_cache
            )
        )

        # Ideally only get requested be cached, but then I have to be able to get the response back from
        # the channel to have something to send back in response
        if use_as_covert and cache_key not in request_cache:
            # print("Populating Cache", cache_key)
            log.info("OvertRequest - Populating cache {}".format(cache_key))
            return request_cache.populate_cache(self).addCallback(
                self.cache_response_received
            )

        log.debug("OvertRequest - response=\n{}".format(request_cache[cache_key]))

        response_size = len(request_cache[cache_key])
        use_as_covert = use_as_covert and response_size <= SMALL_RESPONSE_LIMIT

        def additive_decrease_multiplicative_increase(covert_data_available):
            global SMALL_RESPONSE_LIMIT
            response_sizes = request_cache.get_response_sizes()

            threshold = SMALL_RESPONSE_LIMIT
            min_threshold = response_sizes[0]
            max_threshold = response_sizes[-1]
            step_size = 1024
            increase_factor = 2

            if covert_data_available and not use_as_covert:
                # Perform multiplicative increase
                threshold = min(int(threshold * increase_factor), max_threshold)
                log.critical("Multiplicative increase: New threshold = {}".format(threshold))
            elif not covert_data_available and use_as_covert:
                # Perform additive decrease
                threshold = max(threshold - step_size, min_threshold)
                log.critical("Additive decrease: New threshold = {}".format(threshold))
            
            SMALL_RESPONSE_LIMIT = threshold

        def max_threshold():
            global SMALL_RESPONSE_LIMIT
            response_sizes = request_cache.get_response_sizes()

            threshold = SMALL_RESPONSE_LIMIT
            min_threshold = response_sizes[0]
            max_threshold = response_sizes[-1]

            log.critical("Max threshold: New threshold = {}".format(max_threshold))
            
            SMALL_RESPONSE_LIMIT = max_threshold

        def percentile_threshold(percentile):
            global SMALL_RESPONSE_LIMIT
            response_sizes = request_cache.get_response_sizes()

            threshold = response_sizes[int((percentile / 100) * (len(response_sizes) - 1))]
            
            log.critical("Percentile threshold ({}%): New threshold = {}".format(percentile, threshold))

            SMALL_RESPONSE_LIMIT = threshold

        # additive_decrease_multiplicative_increase()
        # max_threshold()
        # percentile(25)

        log.info("OvertRequest - MIN MAX RESPONSE SIZE = {} {}".format(request_cache._min_response_size, request_cache._max_response_size))
        log.info("OvertRequest - RESPONSE SIZES = {}".format(request_cache.get_response_sizes()))

        # if response_size <= SMALL_RESPONSE_LIMIT:
        log.debug(
            "OvertRequest - response_size={} <= SMALL_RESPONSE_LIMIT={}? {}\nrequest={}".format(
                response_size,
                SMALL_RESPONSE_LIMIT,
                response_size <= SMALL_RESPONSE_LIMIT,
                cache_key
            )
        )

        # TODO: MAJOR, send POST requests in vanilla mode
        if self.method == "GET":
            if overt:
                additive_decrease_multiplicative_increase(overt._buffer.has_data())

                overt.send_overt_request(
                    self.build_http_request({"connection": "keep-alive"}),
                    use_as_covert=use_as_covert,
                    expected_response_size=len(request_cache[cache_key]),
                )
            else:
                log.error(
                    "Overt connection not found for host {}".format(
                        self.getRequestHostname()
                    )
                )

        # Respond the request from cache
        log.info("OvertRequest - Responding from cache for {}".format(self.uri))
        self.transport.write(request_cache[cache_key])

    def build_http_request(self, headers=None):
        request_lines = ["{} {} {}".format(self.method, self.uri, self.clientproto)]

        _headers = self.getAllHeaders()

        log.info("OvertRequest - _headers={}".format(_headers))

        if headers is not None:
            _headers.update(headers)

        for header in _headers:
            request_lines.append("{}: {}".format(header.title(), _headers[header]))

        request_lines.append("\r\n")
        request_lines.append(self.content_data)

        log.info("OvertRequest - Built HTTP request - request_lines=\n{}".format(request_lines))

        return "\r\n".join(request_lines)

    def cache_response_received(self, response):
        self.transport.write(response)


class RequestCache:
    class CacheRequestProtocol(protocol.Protocol):
        def __init__(self):
            self._buffer = []
            self.response = HttpResponse()

        def connectionMade(self):
            self.send_request()

        def connectionLost(self, reason=None):
            # print("Connection Lost", reason)
            log.info("Connection lost {}".format(reason))
            pass

        def send_request(self):
            log.info(
                "CacheRequestProtocol - Sending request {}".format(
                    self.factory.request.uri
                )
            )
            # request = self.factory.request.build_http_request({'connection': 'close'})
            request = self.factory.request.build_http_request()
            self.transport.write(request)
            self.transport.write("\r\n\r\n")

        def dataReceived(self, data):
            self.response.write(data)

            if self.response.finished:
                self.done()
            # self._buffer.append(data)

        # def connectionLost(self, *args):
        #     response = ''.join(self._buffer)
        #     self._buffer = []
        #     self.factory.response_received(self.factory.request_id, self.factory.request.cache_key, response)

        def done(self):
            # log.critical("CacheRequestProtocol - response=\n{}".format(self.response.to_raw()))

            # self.response.print_headers()

            # self.response.set_header("Expires", "Tue, 03 Jul 2001 06:00:00 GMT")
            self.response.set_header("Expires", (datetime.now() - timedelta(days=365)).strftime("%a, %d %b %Y %H:%M:%S GMT"))
            self.response.set_header(
                "Last-Modified", (datetime.now() + timedelta(days=365)).strftime("%a, %d %b %Y %H:%M:%S GMT")
            )
            self.response.set_header(
                "Cache-Control", "no-store, no-cache, must-revalidate, max-age=0"
            )
            # self.response.set_header("Cache-Control", "post-check=0, pre-check=0")
            self.response.set_header("Pragma", "no-cache")

            # self.response.print_headers()

            response = self.response.to_raw()
            log.debug("CacheRequestProtocol - response=\n{}".format(response))
            # print(response)
            self.factory.response_received(
                self.factory.request_id, self.factory.request.cache_key, response
            )
            self.transport.loseConnection()

    def __init__(self):
        self._cache = {}
        self._min_response_size = float('inf')
        self._max_response_size = 0
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
        log.info(
            "Connect SSL {}:{} ClientFactory:CacheRequestProtocol".format(request.getRequestHostname(), 443)
        )
        reactor.connectSSL(
            request.getRequestHostname(), 443, factory, ssl.ClientContextFactory()
        )

        return d
    
    def get_response_sizes(self):
        return sorted([len(x) for x in self._cache.values()])

    def response_received(self, request_id, path, response):
        self._cache[path] = response
        # print('CACHE', path, len(response))
        self._min_response_size = min(self._min_response_size, len(response))
        self._max_response_size = max(self._max_response_size, len(response))
        log.debug(
            "RequestCache - cache[{}]=response len(response)={} response=\n{}".format(
                path, len(response), response
            )
        )
        d = self._pending_requests.pop(request_id)
        d.callback(response)


class OvertUserSimulator(object):
    proxy_port = 7070
    proxy_handler_port = 6060

    def __init__(self, overt_urls, overts):
        if type(overts) is not list and type(overts) is not tuple:
            overts = [overts]
        self.overts = overts

        if type(overt_urls) is str:
            overt_urls = [overt_urls]

        if not len(overt_urls):
            raise ValueError("Must specify at least one overt url")

        self.overt_urls = overt_urls
        self.overt_url_iterator = 0

        log.debug("OvertUserSimulator - overts - {}".format(self.overts))
        log.info("OvertUserSimulator - overt_urls - {}".format(self.overt_urls))

        self.browser = None
        self.request_cache = RequestCache()

    def start(self):
        self.start_proxy()
        self.start_proxy_handler()
        self.start_browser()

    def start_proxy(self):
        proxy_factory = protocol.ServerFactory()
        proxy_factory.protocol = ProxyServerProtocol
        proxy_factory.ous = self
        log.info("Starting proxy... Listening TCP on port {}... ServerFactory:ProxyServerProtocol".format(self.proxy_port))
        reactor.listenTCP(self.proxy_port, proxy_factory)

    def start_proxy_handler(self):
        httpchannel = type(
            "OvertHTTPChannel",
            (http.HTTPChannel, object),
            {"requestFactory": OvertRequest},
        )
        httpchannel.ous = self
        webserver = protocol.ServerFactory()
        webserver.protocol = httpchannel
        log.info(
            "Starting proxy handler... Listening SSL on port {}... ServerFactory:OvertHTTPChannel:OvertRequest".format(
                self.proxy_handler_port
            )
        )
        reactor.listenSSL(
            self.proxy_handler_port,
            webserver,
            ssl.DefaultOpenSSLContextFactory("cert/key.pem", "cert/cert.pem"),
        )

    def start_browser(self):
        self.browser = PhantomDriver(
            {
                "cache": False,
                "proxy": {"ssl": {"host": "127.0.0.1", "port": self.proxy_port}},
                "verify_certs": False,
            }
        )
        log.info(
            "Starting PhantomJS browser using SSL proxy 127.0.0.1:{}".format(
                self.proxy_port
            )
        )
        self.browser.start()

        def _load_overt():
            log.info(
                "OvertUserSimulator - Queueing overt URL to OUS browser {}".format(
                    self.overt_urls[self.overt_url_iterator]
                )
            )

            log.info("OvertUserSimulator - overt_urls={}".format(self.overt_urls))

            self.browser.queue_url(self.overt_urls[self.overt_url_iterator])
            self.overt_url_iterator = (self.overt_url_iterator + 1) % len(
                self.overt_urls
            )

        browser_loop = task.LoopingCall(_load_overt)
        browser_loop.start(OUS_RATE)
        # reactor.callLater(10, _load_overt)

    def add_overt(self, overt):
        log.info(
            "OvertUserSimulator - Adding new overt {} to overts list".format(overt)
        )
        self.overts.append(overt)

    def is_overt_address(self, host):
        for overt in self.overts:
            if host in overt.channel.overt_hosts:
                return True
        return False

    def get_overt_connection(self, host):
        for overt in self.overts:
            if host in overt.channel.overt_hosts:
                return overt
        return None


if __name__ == "__main__":
    from client import OvertGateway

    overt = OvertUserSimulator(OvertGateway(None), "https://www.bing.com")
    overt.start_proxy()
    overt.start_proxy_handler()

    reactor.run()
