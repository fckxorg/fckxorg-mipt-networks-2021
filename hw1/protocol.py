import random
import socket
import struct
import math

class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr, send_loss=0.0):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
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
UDP_PACKAGE_MAX_SIZE = 2 ** 16
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

class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.ack = 0
        self.seq = 0

    def __get_header(self, type: int, ack: int, seq: int) -> bytes:
        return struct.pack("BQQ", type, ack, seq)
    
    def __data_to_packages(self, data: bytes) -> list[bytes]:
        packages = []
        while len(data) + MYTCP_HEADER_LEN > UDP_PACKAGE_MAX_SIZE:
            self.seq += UDP_PACKAGE_MAX_SIZE
            header = self.__get_header(MYTCP_MSG, self.ack, self.seq)
            packages.append(header + data[:UDP_PACKAGE_MAX_SIZE - len(header)])
            data = data[:UDP_PACKAGE_MAX_SIZE - len(header)]

        header = self.__get_header(MYTCP_FIN, self.ack, self.seq)
        packages.append(header + data)

        return packages
    
    def __send_batch(self, batch: list[bytes]):
        for package in batch:
            self.sendto(package)

    def __get_ack_batch(self, batch: list[bytes]) -> bool:
        for package in batch:
            seq = struct.unpack("BQQ", package)[2]
            response = self.recvfrom(MYTCP_HEADER_LEN)
            header = struct.unpack("BQQ", response_raw)
            
            if header[0] != MYTCP_ACK:
                return False
            if header[1] != seq:
                return False
        return True

    def __handle_package(self, response: bytes) -> dict:
        header = struct.unpack("BQQ", response[:MYTCP_HEADER_LEN])

        if header[0] != MYTCP_FIN and header[0] != MYTCP_MSG:
            return {'data' : None, 'final' : True}

        self.ack += len(response)
        self.seq += MYTCP_HEADER_LEN
        ack_package = self.__get_header(MYTCP_ACK, self.ack, self.seq)
        self.sendto(ack_package)
           
        status = {'data' : response[MYTCP_HEADER_LEN:], 'final' : False}
        if header[0] == MYTCP_FIN:
            status['final'] = True
        return status
            
    def __split_to_batches(self, packages, n):
        return [packages[i:i + n] for i in range(0, len(packages), n)]
    
    def send(self, data: bytes):
        packages = self.__data_to_packages(data) 
        batches = self.__split_to_batches(packages, math.ceil(len(packages) / BATCH_SIZE))
            
        for batch in batches:
            self.__send_batch(batch)

            while not self.__get_ack_batch(batch):
                self.__send_batch(batch)

        return len(data)

    def recv(self, n: int):
        response = self.recvfrom(MYTCP_HEADER_LEN + n)
        result = self.__handle_package(response)
        
        data = ''
        data += result['data']

        while not result['final']:
            response = self.recvfrom(MYTCP_HEADER_LEN + n)
            result = self.__handle_package(response)
            data += result['data']

        return data

