__author__ = 'milad'

from scapy_ssl_tls.ssl_tls import TLS
import scapy_ssl_tls.ssl_tls
from scapy.all import Ether,IP,TCP
import datetime
import re
from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends.openssl import backend
import pickle
import base64
from cryptography.hazmat.primitives import serialization
from scapy.all import rdpcap
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pyasn1.type import univ
import struct
from pyasn1.codec.ber import encoder, decoder
from cryptography.hazmat.primitives.ciphers import AEADCipherContext, Cipher, algorithms, modes
from Crypto.Cipher import AES
import threading
import XRelay
import tinyec.ec as ec
import tinyec.registry as ec_reg
import binascii
from scapy_ssl_tls.ssl_tls_crypto import TLSPRF
import uuid


def int_to_str(int_):
    hex_ = "%x" % int_
    return binascii.unhexlify("%s%s" % ("" if len(hex_) % 2 == 0 else "0", hex_))

def str_to_ec_point(ansi_str, ec_curve):
    if not ansi_str.startswith("\x04"):
        raise ValueError("ANSI octet string missing point prefix (0x04)")
    ansi_str = ansi_str[1:]
    if len(ansi_str) % 2 != 0:
        raise ValueError("Can't parse curve point. Odd ANSI string length")
    str_to_int = lambda x: int(binascii.hexlify(x), 16)
    x, y = str_to_int(ansi_str[:len(ansi_str) // 2]), str_to_int(ansi_str[len(ansi_str) // 2:])
    return ec.Point(ec_curve, x, y)


class TLSConnection:
    '''
    Implemenets a TLS (Transport Layer Security) connection. It includes various attributes and methods related to TLS encryption and decryption.

    Attributes:
    - `carry`: A string used to store the received data.
    - `serverrandom`, `clientrandom`: Strings representing the server and client random values.
    - `serverpub`: String representing the server's public key.
    - `replacepayloads`: A list to store replacement payloads.
    - `masterkey`: A string representing the master secret key.
    - `serverpubkey`: String representing the server's public key.
    - `candecrypt`: A boolean indicating whether decryption is possible.
    - `replacedpackets`: A dictionary to store replaced packets.
    - `testlock`: A `threading.Lock` object used for thread synchronization.
    - `mac_key_length`, `cipher_key_length`, `iv_length`: Integer values representing the lengths of different keys and initialization vectors.
    - `encryptor`: Currently set to `None`. ?
    - `datacarry`: A string used to store data that needs to be processed.
    - `writemode`: Currently set to `None`. ?
    - `writesecret`, `writekey`: Strings related to writing operations.
    - `prf`: An instance of the `TLSPRF` class.
    - `manager`: An instance of the `XRelay.Relay` class.
    - `headersize`: An integer representing the size of headers.
    - `connid`: A UUID representing the connection ID.
    - `startreplace`: A boolean indicating whether the replacement process has started.
    - Other various attributes related to TLS encryption and decryption.
    '''
    def __init__(self):
        self.carry = ''
        self.serverrandom = ''
        self.clientrandom = ''

        for i in range(32):
            if i< 4:
                self.clientrandom+=chr(0)
            else:
                self.clientrandom+=chr(i)

        self.serverpub = ''
        self.replacepayloads = []
        self.masterkey = ''
        self.serverpubkey = ''
        self.candecrypt = False
        self.replacedpackets = {}
        self.testlock = threading.Lock()
        self.mac_key_length = 32
        self.cipher_key_length = 16
        self.iv_length = 16
        self.encryptor = None
        self.datacarry = ''
        self.writemode = None
        self.writesecret = 'MILAD SECRET'
        self.writekey = ''

        self.prf = TLSPRF(0x0303)
        self.manager = XRelay.Relay()
        self.headersize = 5
        self.connid = uuid.uuid4().bytes
        self.startreplace = False

    def driveKeys(self):
        '''
        Responsible for generating and deriving encryption keys for the TLS connection. This method performs the necessary steps to establish encryption keys for the TLS connection based on the provided server public key, client private key, and random values.

        1. It retrieves the elliptic curve (`secp256r1`) from the `ec_reg` registry.
        2. It creates an elliptic curve key pair for the server using the `serverpub` value and the `str_to_ec_point` function.
        3. It loads the client's private key pair from a file (`clientpriv`) using the `pickle` module.
        4. It performs an elliptic curve Diffie-Hellman key exchange to derive the shared secret point.
        5. It converts the shared secret point (`mk`) to a string representation using the `int_to_str` function.
        6. It generates the pre-master secret (`pshare`) by applying the TLS Pseudorandom Function (PRF) to the shared secret, along with the labels 'master secret' and the concatenation of `clientrandom` and `serverrandom`.
        7. It generates a block of key material (`blockkey`) by applying the TLS PRF to the pre-master secret, along with the labels 'key expansion' and the concatenation of `serverrandom` and `clientrandom`.
        8. The key material is then split into different keys and IVs for the client and server, which are stored in various instance variables such as `client_write_MAC_key`, `server_write_MAC_key`, `client_write_key`, `server_write_key`, `client_write_IV`, and `server_write_IV`.
        9. It initializes the decryptor by calling the `initDecryptor` method.
        10. It prints a message indicating that the keys are in place.
        '''

        #pk= ec.generate_private_key(ec.SECP256R1, backend)

        ec_curve = ec_reg.get_curve('secp256r1')
        server_keypair = ec.Keypair(ec_curve, pub= str_to_ec_point(self.serverpub,ec_curve))

        client_keypair=pickle.load(open('clientpriv'))
        secret_point = ec.ECDH(client_keypair).get_secret(server_keypair)
        mk = int_to_str(secret_point.x)

        pshare=self.prf.get_bytes(mk,'master secret',self.clientrandom+self.serverrandom,num_bytes=48)

        target_len=128
        blockkey=self.prf.get_bytes(pshare,'key expansion',self.serverrandom+self.clientrandom,num_bytes=target_len)
        print [ord(i) for i in blockkey]
        i = 0
        self.client_write_MAC_key = blockkey[i:i+self.mac_key_length]
        i += self.mac_key_length
        self.server_write_MAC_key = blockkey[i:i+self.mac_key_length]
        i += self.mac_key_length
        self.client_write_key = blockkey[i:i+self.cipher_key_length]
        i += self.cipher_key_length
        self.server_write_key = blockkey[i:i+self.cipher_key_length]
        i += self.cipher_key_length

        self.client_write_IV = blockkey[i:i+self.iv_length]
        i += self.iv_length
        self.server_write_IV = blockkey[i:i+self.iv_length]
        i += self.iv_length

        self.httpcarry=''

        self.initDecryptor()
        #print [ord(i) for i in self.clientrandom]
        #print [ord(i) for i in self.serverrandom]
        #print [ord(i) for i in self.ivkey]

        print 'Keys are in place'


    def initDecryptor(self):
        # self.mode= modes.CBC(self.server_write_IV)
        # self.mode= modes.GCM(self.server_write_IV)
        # self.cipher = Cipher(algorithms.AES(self.server_write_key) ,self.mode , backend=backend)   #AES.new(self.server_write_key,AES.MODE_CBC,self.server_write_IV) #
        # self.decryptor= self.cipher.decryptor()
        self.candecrypt=True
        pass


    def get_nonce(self, nonce=None):
        import struct
        nonce = nonce or struct.pack("!Q", self.ctx.nonce)
        return b"%s%s" % (self.server_write_iv, nonce)


    def decrypt(self,cipherdata):
        '''
        Used for decrypting cipher data in the TLS connection.

        1. It takes the cipher data as input, which consists of the nonce, encrypted data, and the authentication tag.
        2. It separates the nonce, encrypted data (`cdata`), and authentication tag (`tag`) from the cipher data.
        3. It performs some assertions to validate the lengths of the tag and the encrypted data.
        4. It retrieves the nonce value using the `get_nonce` method.
        5. It initializes the AES-GCM mode of operation using the server's write key and the retrieved nonce and authentication tag.
        6. It creates a cipher object using the AES-GCM algorithm and the initialized mode, using the `Cipher` class from the `cryptography` library.
        7. It sets up a decryptor object using the created cipher.
        8. It sets the `candecrypt` flag to `True` to indicate that decryption can be performed.
        9. It asserts that `candecrypt` is `True`.
        10. It decrypts the encrypted data using the decryptor's `update` method, and stores the result in `plaindata`.
        11. It determines the padding length by extracting the last byte of `plaindata` as an ordinal value.
        12. It removes the padding and the authentication tag from `plaindata` to obtain the decrypted data (`d`).
        13. It returns the decrypted data.

        In case an exception occurs during the decryption process, the method re-raises the exception.
        '''
        ####
        nonce, cdata, tag = cipherdata[:8], cipherdata[8:-16], cipherdata[-16:]
        assert len(tag) == 16
        assert len(cdata) == len(cipherdata) - 16 -8
        # self.mode = modes.GCM(self.server_write_IV, tag=tag)
        # print("DECRYPTING")
        # print("NONCE", nonce)
        # print("DATA", cdata)
        # print("TAG", tag)
        # # print("WRITE_IV", self.server_write_IV)
        # print("WRITE KEY", self.server_write_key)
        nonce = self.get_nonce(nonce)
        try:
            self.mode = modes.GCM(nonce, tag=tag)
            self.cipher = Cipher(algorithms.AES(self.server_write_key) ,self.mode , backend=backend)   #AES.new(self.server_write_key,AES.MODE_CBC,self.server_write_IV) #
            
            self.decryptor= self.cipher.decryptor()
            self.candecrypt=True
            ###
            assert self.candecrypt
            plaindata=self.decryptor.update(cdata)# + self.decryptor.finalize()
            padding= ord(plaindata[-1])
            d = plaindata[16:-(1+padding+self.mac_key_length)]
            return d
        except:
            raise

        # ATTEMP 2

        # crypto_data = CryptoData.from_context(self.tls_ctx, self.ctx, "\x00" * len(ciphertext))
        # crypto_data.content_type = content_type
        # crypto_container = EAEADCryptoContainer.from_context(self.tls_ctx, self.ctx, crypto_data)
        # self.__init_ciphers(self.get_nonce(explicit_nonce))
        # self.dec_cipher.update(crypto_container.aead)
        # cleartext = self.dec_cipher.decrypt(ciphertext)
        # try:
        #     self.dec_cipher.verify(tag)
        # except ValueError as why:
        #     warnings.warn("Verification of GCM tag failed: %s" % why)
        # self.ctx.nonce = struct.unpack("!Q", explicit_nonce)[0]
        # self.ctx.sequence += 1
        # return "%s%s%s" % (explicit_nonce, cleartext, tag)
            # return ''


    def addDATA(self,data):
        '''
        Responsible for processing incoming data in the TLS connection. The method processes incoming data by extracting command and size information from `datacarry` and either handling the command immediately or storing the payload for further processing. If there is more data remaining in `datacarry`, the loop continues to process subsequent messages.

        1. It takes the incoming data as input and appends it to the `datacarry` attribute.
        2. It sets the `flag` variable to `True` to enter a loop.
        3. Within the loop, it extracts the command and size information from the beginning of the `datacarry`.
        4. It checks if there is enough data in `datacarry` to process a complete message based on the extracted size and the headersize.
        5. If there is enough data, it performs the following steps:
        - If the command is `'S'`, it extracts the payload from `datacarry` based on the size and headersize. It sets the `startreplace` flag to `True` and constructs a response message (`resp`) containing the payload.
        - Otherwise, it calls the `processCMD` method of the `manager` object, passing the command and associated data to handle the command.
        - If the size plus 5 (command + size bytes) equals the length of `datacarry`, it means that all the data has been processed, so it clears `datacarry` and sets `flag` to `False` to exit the loop.
        - Otherwise, it updates `datacarry` by removing the processed data.
        6. If there is not enough data to process a complete message, it sets `flag` to `False` to exit the loop.

        `ServerConnection` has a function called `addDATA` as well which handles 'O', 'N', and 'Q' commands.
        '''

        self.datacarry+=data
        flag=True

        while flag:
            cmd= struct.unpack('>c',self.datacarry[:1])[0]
            print 'GET COMMAND',cmd
            size=struct.unpack('>I',self.datacarry[1:5])[0]
            if size+self.headersize<=len(self.datacarry):

                if cmd=='S':
                    newdata= self.datacarry[:size+self.headersize]
                    self.startreplace=True
                    #print newdata[5:],size,cmd
                    assert 16==size
                    pl=newdata[self.headersize:self.headersize+size]
                    resp='%s%s%s%s'%('0'*16,struct.pack('>c','R'),struct.pack('>I',len(pl)),pl)
                    self.replacepayloads.append(resp)

                else:
                    self.manager.processCMD(self.datacarry[:size+5],self.connid)
                if size+5 == len(self.datacarry):
                    self.datacarry=''
                    flag=False
                else:
                    self.datacarry=self.datacarry[size+5:]
            else:
                flag=False


    def addHTTPpacket(self,pkt):
        '''
        The `addHTTPpacket` method is responsible for processing an HTTP packet. The method filters packets that contain `'/~milad'` and extracts the base64-encoded payload from them. It then passes the decoded payload to the `addDATA` method for further processing.

        1. It checks if the provided `pkt` contains the substring `'/~milad'`. If not, it returns immediately without further processing.
        2. It uses a regular expression to search for a pattern `/~milad/(\S+)` within the `pkt`. This pattern is expected to match a base64-encoded string after `/~milad/`.
        3. If a match is found, the method decodes the matched string using base64 decoding.
        4. It calls the `addDATA` method and passes the decoded string as input to further process the data.
        '''
        if  not '/~milad' in pkt:
            return
        reg=re.search(r'/~milad/(\S+)',pkt)
        #print 'raw', pkt
        if reg:

            dec=base64.b64decode( reg.group(1))
            self.addDATA(dec)


    def retrivepackets(self):
        '''
        The `retrievepackets` method retrieves new packets from the packet manager and adds them to the list of replace payloads. The method retrieves new packets from the packet manager and adds them to the list of replace payloads. These payloads will be used later during the processing of packets.

        1. It calls the `getnewpackets` method of the packet manager and passes `self.connid` as an argument. This method retrieves new packets associated with the given connection ID.
        2. The retrieved packets are then added to the `replacepayloads` list using the `extend` method. This list contains the payloads that will replace specific packets during processing.
        '''
        self.replacepayloads.extend( self.manager.getnewpackets(self.connid))


    def getnewpayload(self,size,seq):
        '''
        The `getnewpayload` method retrieves a new payload of a specified size and sequence number. 

        1. The method first calls the `retrivepackets` method, which retrieves new packets from the packet manager and adds them to the list of replace payloads.
        2. If the specified sequence number (`seq`) is found in the `replacedpackets` dictionary, it means that the payload has already been replaced and stored. In this case, the method simply returns the stored payload.
        3. If there are no replace payloads available in the `replacepayloads` list, an empty string is returned.
        4. Otherwise, the method iterates through the replace payloads and appends them to the `ret` variable until either the desired size is reached or there are no more replace payloads left.
        5. If a replace payload is larger than the remaining size needed (`size`), the method splits the payload, adds the appropriate portion to `ret`, and inserts the remaining portion back into the `replacepayloads` list.
        6. Once the new payload is constructed, it is stored in the `replacedpackets` dictionary with the corresponding sequence number as the key.
        7. Finally, the method returns the new payload.
        '''

        self.retrivepackets()
        if seq in self.replacedpackets:
            return self.replacedpackets[seq]

        if len(self.replacepayloads)==0:
            return ''

        ret=''

        while size>0 and len(self.replacepayloads)>0:
            data=self.replacepayloads.pop(0)
            if len(data)> size:
                ret+=data[:size]

                #print 'DATA LARGER'
                self.replacepayloads.insert(0,data[size:])
                size=0

            else:
                ret+=data
                size-=len(data)
        print 'getting new packet',datetime.datetime.now()

        self.replacedpackets[seq]=ret
        return ret


    def processTLSpacket(self,pkt):
        '''
        The `processTLSpacket` method processes a TLS packet by extracting relevant information and performing decryption if applicable.

        1. The method takes a packet (`pkt`) as input and creates a `TLS` object from it.
        2. If a `TLSServerHello` object is present in the `TLS` object, the server random value is extracted and stored in `self.serverrandom`.
        3. If a `TLSClientHello` object is present in the `TLS` object, the client random value is extracted and stored in `self.clientrandom`.
        4. If a `TLSServerKeyExchange` object is present in the `TLS` object, the server key exchange parameters are extracted. The server's public key is obtained from the parameters and stored in `self.serverpub`. The secret point (premaster key) is computed using the client's private key and the server's public key.
        5. The TLS security parameters are generated using the premaster key, client random, and server random. The server write key and IV are extracted from the security parameters and stored in `self.server_write_key` and `self.server_write_iv`, respectively. The `candecrypt` flag is set to `True` to indicate that decryption can be performed.
        6. If the `candecrypt` flag is `True`, the method checks if a `TLSCiphertext` object is present in the `TLS` object. If it is, the ciphertext data is decrypted using the `decrypt` method.
        7. If the decrypted plaintext corresponds to an HTTP packet (indicated by the content type), the `startreplace` flag is set to `True`, and the plaintext is processed as an HTTP packet by calling the `addHTTPpacket` method.
        '''
        mtls=TLS(pkt)

        if scapy_ssl_tls.ssl_tls.TLSServerHello in mtls:
            self.serverrandom= str(mtls[scapy_ssl_tls.ssl_tls.TLSServerHello])[2:34]
            print 'Server Random Found'
        if scapy_ssl_tls.ssl_tls.TLSClientHello in mtls:
            self.clientrandom= str(mtls[scapy_ssl_tls.ssl_tls.TLSClientHello])[2:34]
            #mtls[scapy_ssl_tls.ssl_tls.TLSClientHello].show2()
            #print [ord(i) for i in str(mtls[scapy_ssl_tls.ssl_tls.TLSClientHello])[:40]]
            print [ord(i) for i in self.clientrandom]
            print 'Client Random Found'
        if scapy_ssl_tls.ssl_tls.TLSServerKeyExchange in mtls:
            server_kex = mtls[scapy_ssl_tls.ssl_tls.TLSServerKeyExchange]
            a = server_kex[scapy_ssl_tls.ssl_tls.TLSServerECDHParams]
            point = scapy_ssl_tls.ssl_tls_keystore.ansi_str_to_point(a.p)
            self.serverpub=a.p
            curve = ec_reg.get_curve('secp256r1')
            scapy_ssl_tls.ssl_tls_keystore.ECDHKeyStore(curve, ec.Point(curve, *point))

            # PREMASTER KEY
            ec_curve = ec_reg.get_curve('secp256r1')
            server_keypair = ec.Keypair(ec_curve, pub= str_to_ec_point(self.serverpub,ec_curve))
            client_keypair=pickle.load(open('clientpriv'))
            secret_point = ec.ECDH(client_keypair).get_secret(server_keypair)
            mk = int_to_str(secret_point.x) # masalan premaster key

            sec_params = scapy_ssl_tls.ssl_tls_crypto.TLSSecurityParameters.from_pre_master_secret(self.prf, scapy_ssl_tls.ssl_tls.TLSCipherSuite.ECDHE_RSA_WITH_AES_128_GCM_SHA256, mk, self.clientrandom, self.serverrandom)
            sym_keystore = sec_params.server_keystore        
            # print("SYYYYYN JEEEEEET", sym_keystore.key)                                                               
            self.server_write_key = sym_keystore.key
            self.server_write_iv = sym_keystore.iv
            self.candecrypt = True
            # ecdh=scapy_ssl_tls.ssl_tls.TLSServerECDHParams(str(mtls[scapy_ssl_tls.ssl_tls.TLSServerKeyExchange]))
            # self.serverpub=ecdh.p
            # print 'server public Found'
            # self.driveKeys()

        if self.candecrypt:
            # print 'decrypting '
            # mtls.show2()
            if scapy_ssl_tls.ssl_tls.TLSCiphertext in mtls:
                # print 'decryptable'
                plain=self.decrypt(mtls[scapy_ssl_tls.ssl_tls.TLSCiphertext].data)

                if mtls.records[0].content_type==23:
                    self.startreplace=True
                    #print plain[:60]
                    self.addHTTPpacket(plain)


    def addTLSPacket(self,pkt):
        '''
        The `addTLSPacket` method is responsible for adding a TLS packet (`pkt`) to the existing payload and processing the complete TLS records. Here's how the method works:

        1. The method initializes a flag variable to `True` to indicate that there are more packets to process.
        2. The TLS packet (`pkt`) is appended to the existing payload (`self.carry`).
        3. Inside a loop, the method attempts to extract the length of the first TLS record from the current payload using the `TLS` class. If an exception occurs during this process, the loop is exited.
        4. If the length of the TLS record plus the TLS record header size (5 bytes) is less than or equal to the length of the current payload (`self.carry`), the method extracts the first TLS record by passing the corresponding portion of the payload to the `processTLSpacket` method.
        5. After processing the TLS record, the method checks if the length of the current payload equals the length of the processed TLS record. If it does, the payload is cleared, and the loop is exited.
        6. If the length of the current payload is greater than the length of the processed TLS record, the method updates the current payload by removing the processed TLS record and its header from the payload.
        7. If the length of the current payload is not sufficient to contain a complete TLS record, the flag is set to `False`, indicating that there are no more complete TLS records to process.
        '''

        flag=True

        self.carry+=str(pkt)

        #TLS(carry).show2()

        while flag:
            try:
                plen= TLS(self.carry).records[0].length#[scapy_ssl_tls.ssl_tls.TLSRecord].length
                #TLS(self.carry).show2()
            except:
                #TLS(self.carry).show2()
                #print len(self.carry),len(pkt)
                break

            #print plen
            if plen+5<= len(self.carry):
                self.processTLSpacket(self.carry[:plen+5])
                try:
                    if plen+5 ==len(self.carry):
                        self.carry=''
                        flag=False
                    else:
                        self.carry=self.carry[plen+5:]
                except:
                    print 'error' , len (self.carry), plen+5
            else:
                flag=False
