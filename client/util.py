from io import BytesIO

import re


class Buffer:
    '''
    Buffer class represents a simple buffer for storing and manipulating binary data
    '''
    def __init__(self):
        '''
        creates a BytesIO object to store the data and sets the read and write positions to 0
        '''
        self._buffer = BytesIO()
        self._read_pos = 0
        self._write_pos = 0

    def read(self, amnt=None):
        '''
        This method reads a specified amount of data from the buffer.
        If no amount is specified (amnt=None), it reads all available data.
        It first checks if there is data available in the buffer. If there is no available data, an empty string is returned. Otherwise, it seeks to the current read position, reads the specified amount of data, updates the read position, and returns the read data.
        '''
        available = self.available()
        if not available:
            return ''

        if amnt is None or available < amnt:
            amnt = available

        self._buffer.seek(self._read_pos)
        result = self._buffer.read(amnt)
        self._read_pos += len(result)

        return result

    def write(self, data):
        '''
        This method writes the given data to the buffer. It seeks to the current write position, writes the data, and updates the write position accordingly.
        '''
        self._buffer.seek(self._write_pos)
        self._buffer.write(data)
        self._write_pos += len(data)

    def available(self):
        '''
        This method returns the number of bytes available in the buffer for reading.
        It calculates the difference between the write position and the read position.
        '''
        return self._write_pos - self._read_pos

    def has_data(self, amnt=0):
        '''
        This method checks if the buffer has data available for reading.
        If an amount is specified (amnt), it checks if the available data is greater than the specified amount. If no amount is specified (amnt=0), it simply checks if there is any available data in the buffer.
        '''
        return self.available() > amnt


class HttpResponse:
    '''
    The `HttpResponse` class provides methods for parsing and manipulating HTTP response data.
    '''
    def __init__(self):
        self.status_code = None
        self.reason = None
        self.version = None
        self.headers = {}
        self.finished = False

        self._is_chunked = False
        self._chunk_size = None
        self._chunk_buff = []

        self._buffer = []
        self._mode = 'status'
        self._body_buffer = BytesIO()

    def write(self, data):
        '''
        This method is used to write data to the response object.
        It handles the parsing of the response data by checking the mode and parsing lines or body data accordingly.
        '''
        if self._mode == 'body':
            if len(self._buffer):
                self._buffer.append(data)
                data = ''.join(self._buffer)
                self._buffer = []

            self.parse_body(data)
            return

        if '\r\n' in data:
            if len(self._buffer):
                self._buffer.append(data)
                data = ''.join(self._buffer)
                self._buffer = []
            index = data.index('\r\n')
            line = data[:index]
            self.parse_line(line)
            self.write(data[index+2:])
        else:
            self._buffer.append(data)

    def parse_body(self, data):
        '''
        This method parses the response body data.
        It handles both chunked and non-chunked data by checking the value of _is_chunked.
        If the data is chunked, it reads and parses each chunk, updating the _body_buffer accordingly. If the data is not chunked, it writes the data to the _body_buffer until it reaches the expected content length.
        '''
        if not data:
            return

        if not self._is_chunked:
            self._body_buffer.write(data)
            self.finished = self._body_buffer.tell() == int(self.headers['content-length'])
            return

        if self._chunk_size:
            read = data[:self._chunk_size]
            rest = data[self._chunk_size+2:]

            self._body_buffer.write(read)

            if len(read) < self._chunk_size:
                self._chunk_size -= len(read)
            else:
                self._chunk_size = None

            self.parse_body(rest)
        else:
            if '\r\n' not in data:
                self._chunk_buff.append(data)
                return

            index = data.index('\r\n')
            buff, rest = data[:index], data[index+2:]

            if len(self._chunk_buff):
                self._chunk_buff.append(buff)
                buff = ''.join(self._chunk_buff)
                self._chunk_buff = []

            self._chunk_size = int(buff, 16)
            if not self._chunk_size:
                self.finished = True
            else:
                self.parse_body(rest)

    def parse_line(self, line):
        '''
        This method parses a single line of the response.
        It determines the mode (either 'status' or 'headers') and extracts the relevant information from the line.
        If the line is empty, it checks for transfer encoding or content length headers to determine if the response body is chunked or if the response is finished.
        '''
        if self._mode == 'status':
            match = re.match("(.+) (\d+) (.+)", line)
            self.version, self.status_code, self.reason = match.groups()
            self._mode = 'headers'
        elif self._mode == 'headers':
            if not line:
                if self.headers.get('transfer-encoding', None) == 'chunked':
                    self._is_chunked = True
                elif self.headers.get('content-length', '0') == '0':
                    self.finished = True
                self._mode = 'body'
            else:
                key, val = re.match('(.+)\s*[:]\s*(.+)', line).groups()
                self.headers[key.lower()] = val

    def set_header(self, header, value):
        '''
        This method sets a header value in the headers dictionary attribute.
        '''
        self.headers[header.lower()] = value

    def get_header(self, header):
        '''
        This method retrieves the value of a header from the headers dictionary attribute.
        '''
        return self.headers.get(header.title(), None)

    def has_header(self, header):
        '''
        This method checks if a header exists in the headers dictionary attribute.
        '''
        return header.lower() in self.headers

    def to_raw(self):
        '''
        This method converts the response object to its raw string representation.
        It constructs the HTTP response string by combining the version, status code, reason, headers, and body data.
        '''
        headers = self.headers
        if 'transfer-encoding' in headers:
            del headers['transfer-encoding']
            headers['content-length'] = self._body_buffer.tell()
        header_str = '\r\n'.join(['{}: {}'.format(h.title(), headers[h]) for h in headers.keys()])

        self._body_buffer.seek(0)
        return '{} {} {}\r\n{}\r\n\r\n{}\r\n'.format(
            self.version,
            self.status_code,
            self.reason,
            header_str,
            self._body_buffer.read()
        )

#
# a = HttpResponse()
#
# a.write('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\n1234567890\r\n05\r\n12345\r\n0\r\n')
#
# print(a.to_raw())