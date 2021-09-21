import random
import socket
import struct
import math
from time import sleep

class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr, send_loss=0.0):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.udp_socket.settimeout(0.01)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)
        self.send_loss = send_loss

    def sendto(self, data):
        if random.random() < self.send_loss:
            # simulate that packet was lost
            return len(data)

        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

MYTCP_ACK = 1
MYTCP_MSG = 2
MYTCP_FIN = 4

MYTCP_HEADER_LEN = len(struct.pack("BQQ", 0, 0, 0))
UDP_PACKAGE_MAX_SIZE = 2 ** 10 - 1
BATCH_SIZE = 10

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
        return header + self.data

    @classmethod
    def __validate_header(cls, type, ack, seq):
        if type != MYTCP_ACK and type != MYTCP_MSG and type != MYTCP_FIN:
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
            self.seq += UDP_PACKAGE_MAX_SIZE
            body = data[:UDP_PACKAGE_MAX_SIZE - MYTCP_HEADER_LEN]
            package = Package(MYTCP_MSG, self.ack, self.seq, body)
            packages.append(package)
            data = data[UDP_PACKAGE_MAX_SIZE - MYTCP_HEADER_LEN:]

        package = Package(MYTCP_FIN, self.ack, self.seq, data)
        packages.append(package)

        return packages

    def __get_ack_package(self, package: Package) -> bool:
        response = Package.from_bytes(self.recvfrom(MYTCP_HEADER_LEN))
        return response.type == MYTCP_ACK and response.ack == package.seq
    
    def __send_ack_package(self, package: Package):
        if self.ack < package.seq:
            self.ack += len(bytes(package))
            self.seq += MYTCP_HEADER_LEN

        ack_package = Package(MYTCP_ACK, self.ack, self.seq)
        self.sendto(ack_package)
         

    def __handle_response_package(self, response: bytes) -> dict:
        package = Package.from_bytes(response)

        if package.type != MYTCP_FIN and package.type != MYTCP_MSG:
            return {'data' : None, 'final' : True}
        
        self.__send_ack_package(package)
          
        status = {'data' : package.data, 'final' : False}
        if package.type == MYTCP_FIN:
            status['final'] = True
        return status
    
    def send(self, data: bytes):
        packages = self.__data_to_packages(data) 
        
        for package in packages:
            self.sendto(bytes(package))
            while not self.__get_ack_package(package):
                self.sendto(bytes(package))


    def recv(self, n: int):
        response = self.recvfrom(MYTCP_HEADER_LEN + n)
        result = self.__handle_response_package(response)
        
        data = ''
        data += str(result['data'])

        while not result['final']:
            response = self.recvfrom(MYTCP_HEADER_LEN + n)
            result = self.__handle_response_package(response)
            data += str(result['data'])

        return data

