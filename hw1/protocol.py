import random
import socket
import struct
import math
from time import sleep
import multiprocessing

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

MYTCP_HEADER_LEN = len(struct.pack("BQQ", 0, 0, 0))
UDP_PACKAGE_MAX_SIZE = MYTCP_HEADER_LEN + 10_000_000
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
    def __init__(self, type: int, ack: int, seq: int, data: bytes = None):
        self.__validate_header(type, ack, seq)

        self.type = type
        self.ack = ack
        self.seq = seq
        self.data = data

    def __bytes__(self):
        header = struct.pack("BQQ", self.type, self.ack, self.seq)
        return header + self.data if self.data else header

    def __str__(self):
        types = {MYTCP_ACK : "ACK", MYTCP_FIN : "FIN", MYTCP_MSG : "MSG"}
        return "package {} ack: {} seq: {} data: {} size: {}".format(types[self.type], str(self.ack), str(self.seq), str(self.data) if self.data is not None else "None", len(self))

    def __len__(self):
        return len(bytes(self))

    @classmethod
    def __validate_header(cls, type, ack, seq):
        if type != MYTCP_ACK and type != MYTCP_MSG and type != MYTCP_FIN and type != MYTCP_DEF:
            raise ValueError
        if seq < 0 or ack < 0:
            raise ValueError

    @classmethod
    def from_bytes(cls, data):
        type, ack, seq = struct.unpack("BQQ", data[:MYTCP_HEADER_LEN])
        cls.__validate_header(type, ack, seq)
        
        body = None
        if len(data) > MYTCP_HEADER_LEN:
            body = data[MYTCP_HEADER_LEN:]
        return cls(type, ack, seq, body)


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ack = 0
        self.seq = 0
    
    def __data_to_packages(self, data: bytes) -> list[Package]:
        packages = []
        while len(data) + MYTCP_HEADER_LEN > UDP_PACKAGE_MAX_SIZE:
            body = data[:UDP_PACKAGE_MAX_SIZE - MYTCP_HEADER_LEN]
            package = Package(MYTCP_MSG, 0, 0, body)
            packages.append(package)
            data = data[UDP_PACKAGE_MAX_SIZE - MYTCP_HEADER_LEN:]
        
        package = Package(MYTCP_MSG, 0, 0, data)
        packages.append(package)

        return packages

    def __get_ack_package(self, package: Package) -> bool:
        raw_response = self.recvfrom(MYTCP_HEADER_LEN)
        if raw_response is None:
            return False
        response = Package.from_bytes(raw_response)
        if response.type != MYTCP_ACK:
            return False
        
        if response.ack != self.seq:
            return None

        self.ack += len(raw_response)
        return True

    
    def __send_ack_package(self, package: Package):
        ack_package = Package(MYTCP_ACK, self.ack, 0)
        self.seq += len(ack_package)
        ack_package.seq = self.seq
        self.sendto(bytes(ack_package))

    def __parse_response(self, response: bytes) -> tuple[bytes, Package]:
        package = Package.from_bytes(response)
       
        if self.ack < package.seq:
            self.ack += len(response)  
            return package.data if package.data is not None else b'', package
          
        return b'', package
    
    def __recv_package(self, n: int) -> tuple[bytes, Package]:
        response = self.recvfrom(MYTCP_HEADER_LEN + n)
        while response is None:
            response = self.recvfrom(MYTCP_HEADER_LEN + n)

        result, package = self.__parse_response(response)
        return result, package
        
    
    def __finalize(self) -> Package:
        fin = Package(MYTCP_FIN, self.ack, 0)
        self.seq += len(fin)
        fin.seq = self.seq
        self.sendto(bytes(fin))
        return fin


    def send(self, data: bytes):
        packages = self.__data_to_packages(data) 
        
        for package in packages:
            package.ack = self.ack
            self.seq += len(package)
            package.seq = self.seq
            self.sendto(bytes(package))
            while not self.__get_ack_package(package):
                self.sendto(bytes(package))

        return len(data)

    def recv(self, n: int):
        data = b''
        package = Package(MYTCP_DEF, 0, 0)
        
        recieved = 0

        while recieved != n:
            result, package = self.__recv_package(n)
            recieved += len(result)
            data += result
            self.__send_ack_package(package)

        return data

