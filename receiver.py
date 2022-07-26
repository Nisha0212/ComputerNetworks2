import sys
from dataclasses import dataclass
import socket
import struct
from typing import ClassVar
import hashlib

@dataclass
class Packet:
    header: ClassVar[struct.Struct]=struct.Struct('iii??q')
    sequence_num: int
    length: int
    checksum: int
    SYN: bool
    ACK: bool
    exp_recv_time: int
    payload : bytes

    def packing(self):
        return self.header.pack(self.sequence_num, self.length, self.checksum,
                                self.SYN,self.ACK, self.exp_recv_time) + self.payload

    @classmethod
    def unpacking(cls,data:bytes):
        payload = data[cls.header.size:]
        sequence_num,length,checksum,SYN,ACK,exp_recv_time = cls.header.unpack_from(data)
        return Packet(sequence_num,length,checksum,SYN,ACK,exp_recv_time,payload)

BUFFERLEN = 4096

def main():
    n = len(sys.argv)
    if n != 4:
        print("Usage for reciever (server side): python3 " + str(sys.argv[0]) + 
              " [Port Number of receiver] [IP Address of sender] [Port Number of sender]")
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

    print("Server side (reciever) running; waiting for the client (sender) to connect to receiver")
    
    # Form (HOST, PORT) tuple for sndSock
    sndAddrPort = (str(sys.argv[2]), int(sys.argv[3]))
    
    # Getting name of file from sender
    try:
        data, addr = rcvSock.recvfrom(BUFFERLEN)
        filename = data.strip().decode('utf8')
        print(f"Being sent a file with name   \"{filename}\"")
    except:
        print("Error: Failed to receive filename from sender.py")
        rcvSock.close()
        sys.exit(1)

    totalPackets = 0
    # Getting total number of packets from sender
    while (totalPackets <= 0):
        totalPackets, fromAddress = rcvSock.recvfrom(BUFFERLEN)
        sndSock.sendto(totalPackets, sndAddrPort)
        totalPackets=int.from_bytes(totalPackets,'little')
    print(f"Expecting to receive {totalPackets} packets from sender")

    ##pack = Packet(0, 0, 0, False, False, 0, b'')
    rcvBytes = 0
    rcvPackets = 0
    file_packets = []
    pack = Packet(0, 0, 0, False, False, 0, b'') 
    for i in range(0,totalPackets):
        file_packets.append(pack)

    while (rcvPackets != totalPackets):
        # Getting file data packet
        pack, fromAddress = rcvSock.recvfrom(BUFFERLEN)
        pack = Packet.unpacking(pack)
        chk = pack.checksum
        chk2 = int(hashlib.md5(pack.payload).hexdigest(), 16) % 1000
        if (chk != chk2):
            print("Checksum doesn't match!!! Data might be faulty")
        ##print("before sending")
        # Sending ACK
        sndSock.sendto(pack.sequence_num.to_bytes(8,'little'), sndAddrPort)
        ##print("after sending")

        # If packet is not repeated
        if (file_packets[pack.sequence_num - 1].sequence_num == 0):
            rcvPackets = rcvPackets + 1
            file_packets[pack.sequence_num - 1] = pack
            rcvBytes = rcvBytes + pack.length
    
    
    final_frame = Packet(0, 0, 0, False, False, 0, b'')
    final_frame.sequence_num = totalPackets + 1
    while (pack.sequence_num != final_frame.sequence_num):
        pack, fromAddress = rcvSock.recvfrom(BUFFERLEN)
        pack=Packet.unpacking(pack)
        sndSock.sendto(pack.sequence_num.to_bytes(8,'little'), sndAddrPort)
        print(f"Total Bytes Recieved:{rcvBytes}")

    # Put file data from received packets into file on server side
    fptr = open(filename, "wb")
    for i in range(0, totalPackets):
        fptr.write(file_packets[i].payload)
    fptr.close()

    sndSock.close()
    rcvSock.close()
    sys.exit(0)


if __name__ == "__main__":
    main()


