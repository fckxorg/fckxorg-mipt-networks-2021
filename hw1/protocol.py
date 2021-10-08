import random
import socket
import struct
import math
from time import sleep
import multiprocessing

class Logger:
    log_file = 'log.txt'
    @classmethod
    def log(cls, msg):
        with open(cls.log_file, 'a') as f:
            f.write(msg + '\n')

class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr, send_loss=0.0):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.udp_socket.settimeout(0.001)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)
        self.send_loss = send_loss

    def sendto(self, data):
        if random.random() < self.send_loss:
            # simulate that packet was lost
            return len(data)

        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg = None
        try:
            msg, _ = self.udp_socket.recvfrom(n)
        except:
            pass
        return msg

MYTCP_DEF = 0
MYTCP_ACK = 1
MYTCP_MSG = 2
MYTCP_FIN = 4

MYTCP_HEADER_LEN = len(struct.pack("BQ", 0, 0))
UDP_PACKAGE_MAX_SIZE = MYTCP_HEADER_LEN + 512
ASSURANCE_LIMIT = 3

"""
MyTCP package structure:
package     := header msg?
header      := type ack seq 
type        := <BYTE>
ack         := <ULEB128>
seq         := <ULEB128>
msg         := <STRING>
"""

class Package:
    def __init__(self, type: int, uid: int, data: bytes = None):
        self.__validate_header(type, uid)

        self.type = type
        self.data = data
        self.uid = uid

    def __bytes__(self):
        header = struct.pack("BQ", self.type, self.uid)
        return header + self.data if self.data else header

    def __str__(self):
        types = {MYTCP_ACK : "ACK", MYTCP_FIN : "FIN", MYTCP_MSG : "MSG"}
        return "package {} uid: {} data: {} size: {}".format(types[self.type], str(self.uid), str(self.data) if self.data is not None else "None", len(self))

    def __len__(self):
        return len(bytes(self))

    @classmethod
    def __validate_header(cls, type, uid):
        if type != MYTCP_ACK and type != MYTCP_MSG and type != MYTCP_FIN and type != MYTCP_DEF:
            raise ValueError
        if uid < 0 :
            raise ValueError

    @classmethod
    def from_bytes(cls, data):
        type, uid = struct.unpack("BQ", data[:MYTCP_HEADER_LEN])
        cls.__validate_header(type, uid)
        
        body = None
        if len(data) > MYTCP_HEADER_LEN:
            body = data[MYTCP_HEADER_LEN:]
        return cls(type, uid, body)


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.sack = set()
        self.sseq = set()
        self.rack = set()
        self.uid = 0

    def __data_to_packages(self, data: bytes) -> list[Package]:
        packages = []
        while len(data) + MYTCP_HEADER_LEN > UDP_PACKAGE_MAX_SIZE:
            self.uid += 1
            body = data[:UDP_PACKAGE_MAX_SIZE - MYTCP_HEADER_LEN]
            package = Package(MYTCP_MSG, self.uid, body)
            packages.append(package)
            data = data[UDP_PACKAGE_MAX_SIZE - MYTCP_HEADER_LEN:]

        self.uid += 1 
        package = Package(MYTCP_MSG, self.uid, data)
        packages.append(package)

        return packages

    def __get_ack_package(self, package: Package) -> bool:
        raw_response = self.recvfrom(MYTCP_HEADER_LEN)
        if raw_response is None:
            return False
        response = Package.from_bytes(raw_response)
        if response.type != MYTCP_ACK:
            return False
        
        if response.uid not in self.sseq:
            return None

        self.sack.add(response.uid)
        return True

    
    def __send_ack_package(self, package: Package):
        ack_package = Package(MYTCP_ACK, package.uid, 0)
        self.sendto(bytes(ack_package))
        Logger.log("Sent ack " + str(ack_package) + " for " + str(package))

          
    def __recv_package(self, n: int) -> tuple[bytes, Package]:
        response = self.recvfrom(UDP_PACKAGE_MAX_SIZE)
        while response is None:
            response = self.recvfrom(UDP_PACKAGE_MAX_SIZE)
        package = Package.from_bytes(response)

        if package.uid not in self.rack:
            self.rack.add(package.uid)  
            return package.data if package.data is not None else b'', package
        
        return b'', package
    
    def __send_package(self, package: Package):
        self.sseq.add(package.uid)
        self.sendto(bytes(package))

    def __resend_package(self, package: Package):
        self.sendto(bytes(package))
        
    def send(self, data: bytes):
        packages = self.__data_to_packages(data) 
        
        for package in packages:
            self.__send_package(package)
            Logger.log('Sent ' + str(package))
            while not self.__get_ack_package(package):
                Logger.log('No ack for ' + str(package))
                self.__resend_package(package)
                Logger.log('Resent ' + str(package))
            Logger.log('Ack ' + str(package))

        return len(data)

    def recv(self, n: int):
        data = b''
        package = Package(MYTCP_DEF, 0)
        
        recieved = 0

        while recieved != n:
            result, package = self.__recv_package(n)
            recieved += len(result)
            data += result
            self.__send_ack_package(package)

        return data

