import binascii
import sys
from dataclasses import dataclass
import socket
import os
import threading
import time
import math
import struct
from typing import ClassVar
import hashlib

@dataclass
class Packet:
    header: ClassVar[struct.Struct] = struct.Struct('iii??q')
    sequence_num: int
    length: int
    checksum: int
    SYN: bool
    ACK: bool
    exp_recv_time: int
    payload: bytes

    def packing(self):
        return self.header.pack(self.sequence_num, self.length,self.checksum,
                                self.SYN, self.ACK, self.exp_recv_time) + self.payload

    def calculate_checksum(cls):
        return binascii.crc32()


file_packets = []
sendfail = False

packet_header_size=24
BUFFERLEN = 4096
TOTALTHREADS = 4
TIMEOUT = 500000
MAXRETRANS = 200
WINDOWSIZE = 10


def send_data_worker(threadIdx, sndSock, addr_port_tuple):
    # Get index range of packets this thread will send 
    firstidx = threadIdx * math.ceil(len(file_packets) / TOTALTHREADS)
    lastidx = min(  (threadIdx + 1)*int(math.ceil(len(file_packets) / TOTALTHREADS)),
                    len(file_packets) )  

    # Initialising Window
    window = []
    for i in range(0, WINDOWSIZE):
        window.append(firstidx + i)

    window_end = firstidx + WINDOWSIZE - 1

    i = 0
    while (len(window) != 0):
        if (i >= len(window)):
            i = 0
        if (file_packets[window[i]].ACK):
            window.remove(window[i])
            i = i + 1
            if (window_end + 1 < lastidx):
                window_end = window_end + 1
                window.append(window_end)
        else:
            if ((not file_packets[window[i]].SYN) or (
                    (time.time_ns() // 1000) > file_packets[window[i]].exp_recv_time)):
                sndSock.sendto(file_packets[window[i]].packing(), addr_port_tuple)
                file_packets[window[i]].exp_recv_time = (time.time_ns() // 1000) + TIMEOUT
                file_packets[window[i]].SYN = True
            i = i + 1
        if (sendfail):
            return

def main():
    n = len(sys.argv)

    if n != 4:
        print("Usage for sender (client side) :  python3 " + str(sys.argv[0]) + 
              " [Port Number of sender] [IP Address of receiver] [Port Number of reciever] \n")
        sys.exit(1)

    # Creating send and receive sockets
    sndSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    if sndSock == 0:
        print("Error: Failed to create send socket")
        sys.exit(1)

    rcvSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)
    if rcvSock == 0:
        print("Error: Failed to create recieve socket")
        sys.exit(1)

    # Binding recieve socket
    try:
        rcvSock.bind((str(socket.INADDR_ANY), int(sys.argv[1])))
    except:
        print("Error: Failed to bind recieve socket")
        rcvSock.close()
        sys.exit(1)

    # Form (HOST, PORT) tuple for sndSock
    sndAddrPort = (str(sys.argv[2]), int(sys.argv[3]))    

    rcvSock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, bytes(TIMEOUT))
    sendfail = False

    # Take filename from user
    filename = input("Enter filename of file to send (type \"exit\" to quit): ")
    #filename = "CS3543_100MB"
    if filename == "exit":
        return 0

    # Record file transmission starting time
    startTime = time.time_ns()

    # Make sure file given by user exists
    if (not os.path.exists(filename)):
        print("Error: Given file does not exist")
    else:
        try:
            # Send name of file to receiver
            sndSock.sendto(bytes(str(filename), encoding='utf-8'), sndAddrPort)
        except:
            print("Error: Failed to send filename to receiver")
            sndSock.close()
            sys.exit(1)
        
        # Get size of given file in bytes
        filesize = os.path.getsize(str(filename))  
        totalPackets = 0
        if filesize % BUFFERLEN == 0:
            totalPackets = filesize // BUFFERLEN
        else:
            totalPackets = filesize // BUFFERLEN + 1
        print("Size of file = " + str(filesize) + " bytes")
        print("Total packets to send = " + str(totalPackets)) ##

        rcvData = 0        
        # Transmit totalPackets till ack is sent back
        for i in range(0, MAXRETRANS):
            if (rcvData == totalPackets):  # Check that value sent back is same
                break
            # Send totalPackets
            sndSock.sendto(totalPackets.to_bytes(8, 'little'), sndAddrPort)
            rcvData, _ = rcvSock.recvfrom(BUFFERLEN)
            rcvData = int.from_bytes(rcvData, 'little')

        if rcvData != totalPackets:
            print("MAXRETRANS exceeeded -- Error: Failed to transmit total frame number to receiver")
            sendfail = True
            return 0

        # Divide data in given file into packets
        fptr = open(filename, 'rb')
        for i in range(0, totalPackets):
            # Read BUFFERLEN number of bytes, 1 byte at a time
            data = b''
            for j in range(0, BUFFERLEN-packet_header_size):
                x = fptr.read(1)
                data = data + x
            datalength = len(data) + packet_header_size
            chk = hashlib.md5(data).hexdigest()
            pack_temp = Packet((i + 1), datalength,(int(chk,16)%1000), False, False, 0, data)
            file_packets.append(pack_temp)
        fptr.close()

        # Create and start worker threads to send file data
        worker = []
        threadIdx = []
        for i in range(0, TOTALTHREADS):
            threadIdx.append(i)
            worker.append(
                threading.Thread(target=send_data_worker, args=(i, sndSock, sndAddrPort)))
            worker[i].start()

        # Collect ACKs from worker threads
        recvACK = 0
        while ((not sendfail) and (recvACK != totalPackets) and (rcvData != totalPackets + 1)):
            rcvData, fromAddress = rcvSock.recvfrom(BUFFERLEN)
            rcvData = int.from_bytes(rcvData, 'little')
            if (not file_packets[rcvData - 1].ACK):
                file_packets[rcvData - 1].ACK = True
                recvACK += 1
        sendfail = True

        # All worker threads should exit and join back
        for i in range(0, TOTALTHREADS):
            worker[i].join()

        # Last packet
        lastPacket = Packet(0, 0, 0, False, False, 0, b'')  
        while (rcvData != totalPackets + 1):
            lastPacket.sequence_num = totalPackets + 1
            lastPacket_pack = lastPacket.packing()
            sndSock.sendto(lastPacket_pack, sndAddrPort)  
            rcvData, _ = rcvSock.recvfrom(BUFFERLEN)
            rcvData = int.from_bytes(rcvData, 'little')

        endTime = time.time_ns()
        transmissionTime = endTime - startTime
        print("File transmission time = " + str(transmissionTime / 1000000000) + " secs")
        print("Throughput = " + str((filesize / (1024 * 1024))/(transmissionTime/1000000000)) + " MB/s")

    sndSock.close()
    rcvSock.close()
    sys.exit(0)


if __name__ == "__main__":
    main()

