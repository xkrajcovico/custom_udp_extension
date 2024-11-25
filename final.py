import socket
import threading
import struct
import time
import os
import random
# ===========================================================================
# SOURCE PARAMETERS
# Define individual flag bits
FLAG_SYN = 1 << 7           # 0b10000000
FLAG_ACK = 1 << 6           # 0b01000000
FLAG_NACK = 1 << 5          # 0b00100000
FLAG_FIN = 1 << 4           # 0b00010000
FLAG_DATA = 1 << 3          # 0b00001000
FLAG_FRAGMENTED = 1 << 2    # 0b00000100
FLAG_LAST_FRAGMENT = 1 << 1 # 0b00000010
FLAG_KEEPALIVE = 1 << 0     # 0b00000001

# Control messages
SYN_MSG = FLAG_SYN
SYNACK_MSG = FLAG_SYN | FLAG_ACK
ACK_MSG = FLAG_ACK
NACK_MSG = FLAG_NACK
FIN_MSG = FLAG_FIN
FINACK_MSG = FLAG_FIN | FLAG_ACK
KEEPALIVE_MSG = FLAG_KEEPALIVE

# Data messages
TEXT_MSG = FLAG_DATA
TEXT_MSG_FRAG = FLAG_DATA | FLAG_FRAGMENTED
TEXT_MSG_FRAG_L = FLAG_DATA | FLAG_FRAGMENTED | FLAG_LAST_FRAGMENT

FILE_MSG = FLAG_DATA | FLAG_FRAGMENTED  # Files are fragmented data
FILE_MSG_L = FLAG_DATA | FLAG_FRAGMENTED | FLAG_LAST_FRAGMENT

# ===========================================================================
# SOURCE PARAMETERS

def getSourceIp():
    hostName = socket.gethostname()
    try:
        ipAddress = socket.gethostbyname(hostName)
    except socket.gaierror:
        # Fallback in case gethostbyname fails
        ipAddress = '127.0.0.1'
    return ipAddress

def getListenPort():
    while True:
        try:
            LISTEN_PORT = int(input("Enter your listening port (value between 50,000 - 60,000): "))
            if LISTEN_PORT <= 50000 or LISTEN_PORT >= 60000:
                raise ValueError
            return LISTEN_PORT
        except ValueError:
            print("Invalid input! Please enter an integer between 50,000 - 60,000.")

# DESTINATION PARAMETERS

def IPisvalid(IPstr):
    parts = IPstr.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not (0 <= int(part) <= 255):
            return False
        # check for leading 0
        if part.startswith('0') and len(part) > 1:
            return False
    return True

def getDestinationIP():
    while True:
        try:
            DESTINATION_IP = input("Enter the recipient's IP address: ")
            if not IPisvalid(DESTINATION_IP):
                raise ValueError
            return DESTINATION_IP
        except ValueError:
            print("Invalid IP address format.")

class SamePort(Exception):
    pass

def getTargetPort(LISTEN_PORT):
    while True:
        try:
            TARGET_PORT = int(input("Enter the target port (value between 50,000 - 60,000): "))
            if TARGET_PORT <= 50000 or TARGET_PORT >= 60000:
                raise ValueError
            if TARGET_PORT == LISTEN_PORT:
                raise SamePort
            return TARGET_PORT
        except ValueError:
            print("Invalid input! Please enter an integer between 50,000 - 60,000.")
        except SamePort:
            print("Target port must not be the same as the listening port!")

# ===========================================================================
# CRC16 CHECKSUM FUNCTION

def crc16(data: bytes, poly=0x1021):
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000 != 0:
                crc = ((crc << 1) ^ poly) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc

# ===========================================================================
# CLASSES
class ProtocolHeader:
    def __init__(self, flags, fragNumber, ackNumber):
        self.flags = flags  # 16 bits
        self.fragNumber = fragNumber  # 32 bits
        self.ackNumber = ackNumber  # 32 bits

    def pack(self):
        header = struct.pack('!HII', self.flags, self.fragNumber, self.ackNumber)
        return header

    @staticmethod
    def unpack(data):
        if len(data) < 10:
            raise ValueError("Insufficient data to unpack ProtocolHeader")
        flags, fragNumber, ackNumber = struct.unpack('!HII', data)
        return ProtocolHeader(flags, fragNumber, ackNumber)

class MessageHandler:
    @staticmethod
    def createPacket(flags, fragNumber, ackNumber, data=b'', corrupt_crc=False):
        header = ProtocolHeader(flags, fragNumber, ackNumber).pack()
        if isinstance(data, str):
            data = data.encode("utf-8")
        packet_without_checksum = header + data
        # Compute checksum over header + data
        checksum = crc16(packet_without_checksum)
        if corrupt_crc:
            # Corrupt the checksum by flipping random 8 bits
            checksum ^= random.getrandbits(8)
        # Pack checksum into 2 bytes, big endian
        checksum_bytes = struct.pack('!H', checksum)
        # Append checksum to packet
        packet = packet_without_checksum + checksum_bytes
        return packet

    @staticmethod
    def unpackPacket(packet):
        # Extract checksum from the end
        if len(packet) < 12:  # header (10 bytes) + checksum (2 bytes)
            # Packet too short
            return None, None, False
        checksum_received = packet[-2:]
        packet_without_checksum = packet[:-2]
        checksum_calculated = crc16(packet_without_checksum)
        checksum_received = struct.unpack('!H', checksum_received)[0]
        # Verify checksum
        if checksum_calculated != checksum_received:
            # Checksum mismatch
            return None, None, False
        # Extract header and data
        header = packet_without_checksum[:10]
        data = packet_without_checksum[10:]
        return ProtocolHeader.unpack(header), data, True

class Peer:
    def __init__(self, source_ip, listen_port, destination_ip, target_port):
        self.sockListen = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sockListen.bind((source_ip, listen_port))
        self.sockSend = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Flags for connection termination
        self.FIN_sent = False
        self.FIN_received = False
        self.FINACK_sent = False
        self.FINACK_received = False
        self.close_requested = False
        self.buffer = {}
        # Instance variables for sending
        self.send_ackStatus = {}
        self.send_aktualWindowSize = 0
        self.eventWindowAcked = threading.Event()
        self.connection_closed = threading.Event()  # Event to signal connection closed
        self.errorPacketID = None  # Packet ID to corrupt
        # Connection status
        self.source_ip = source_ip
        self.listen_port = listen_port
        self.destination_ip = destination_ip
        self.target_port = target_port
        self.CONNECTION = False  # Instance variable

    def sendPacket(self, packet):
        # Optional: Simulate packet corruption for testing (remove in production)
        self.sockSend.sendto(packet, (self.destination_ip, self.target_port))

    # 3-way handshake
    def listenHandshake(self):
        global SYN_MSG, SYNACK_MSG, ACK_MSG

        self.sockListen.settimeout(15)
        while True:
            try:
                packet, _ = self.sockListen.recvfrom(1514)
            except socket.timeout:
                print("\nConnection timed out.")
                exit()
                break
            except Exception as e:
                print(f"Error receiving handshake packet: {e}")
                continue  # Continue listening

            try:
                header, _, checksum_valid = MessageHandler.unpackPacket(packet)
            except ValueError as ve:
                print(f"Failed to unpack handshake packet: {ve}")
                continue  # Ignore malformed packets

            if not checksum_valid:
                print("Invalid checksum in handshake packet.")
                continue

            if header.flags == SYN_MSG:
                print(f"=====================================")
                print(f"SYN received.")
                aktualFragNumber = 0
                aktualAckNumber = 0
                SYNACKpacket = MessageHandler.createPacket(SYNACK_MSG, aktualFragNumber, aktualAckNumber)
                self.sendPacket(SYNACKpacket)
                print(f"SYN-ACK packet sent.")

            elif header.flags == SYNACK_MSG:
                print(f"SYN-ACK received.")
                aktualFragNumber = 0
                aktualAckNumber = 0
                ACKpacket = MessageHandler.createPacket(ACK_MSG, aktualFragNumber, aktualAckNumber)
                self.sendPacket(ACKpacket)
                print(f"ACK packet sent.")
                print("--------------------------")
                print("3-way handshake completed.")
                print("=====================================\n")
                printConnectionEstablished(self.source_ip, self.listen_port, self.destination_ip, self.target_port)
                self.CONNECTION = True
                break

            elif header.flags == ACK_MSG:
                print(f"ACK packet received.")
                print("--------------------------")
                print("3-way handshake completed.")
                print("=====================================\n")
                printConnectionEstablished(self.source_ip, self.listen_port, self.destination_ip, self.target_port)
                self.CONNECTION = True
                break

    # Listening for incoming messages
    def listen(self):
        global ACK_MSG, FIN_MSG, FINACK_MSG, KEEPALIVE_MSG, NACK_MSG
        global TEXT_MSG, TEXT_MSG_FRAG, TEXT_MSG_FRAG_L
        global FILE_MSG, FILE_MSG_L

        fragmentBuffer = {}
        totalFragments = None
        startTime = None
        fileName = None

        self.sockListen.settimeout(15)  # Increased timeout
        while self.CONNECTION:
            try:
                packet, _ = self.sockListen.recvfrom(1514)
            except socket.timeout:
                self.CONNECTION = False
                print("The other side stopped responding")
                PEER.sockListen.close()
                PEER.sockSend.close()
                exit()
                break
            except Exception as e:
                print(f"Error receiving packet: {e}")
                continue  # Continue listening

            try:
                header, data, checksum_valid = MessageHandler.unpackPacket(packet)
            except ValueError as ve:
                print(f"Failed to unpack packet: {ve}")
                continue  # Ignore malformed packets

            if not checksum_valid:
                print("Checksum invalid for received packet.")
                # Send NACK if possible
                if len(packet) >= 12:
                    try:
                        header_bytes = packet[:10]
                        header_obj = ProtocolHeader.unpack(header_bytes)
                        fragNumber = header_obj.fragNumber
                        isFragmented = bool(header_obj.flags & FLAG_FRAGMENTED)
                        isData = bool(header_obj.flags & FLAG_DATA)
                        self.sendACK(fragNumber, isFragmented, isData, isCorrupted=True)
                        print(f"NACK sent for fragment {fragNumber}.")
                    except Exception as e:
                        print(f"Error sending NACK: {e}")
                continue

            if header.flags & FLAG_KEEPALIVE:
                continue

            if not (header.flags & FLAG_FRAGMENTED):  # Not fragmented message
                if header.flags & FLAG_DATA:
                    try:
                        message = data.decode("utf-8")
                        print(f"\n\nReceived message:\n{message}")
                        self.sendACK(header.fragNumber, False, False)
                    except UnicodeDecodeError:
                        print("Received data is not valid UTF-8.")
                        self.sendACK(header.fragNumber, False, False, isCorrupted=True)
                elif header.flags & FLAG_ACK or header.flags & FLAG_NACK:
                    # Handle ACK/NACK received for our sent data
                    self.processACKNACK(header)
                elif header.flags == FIN_MSG:
                    self.handleFin()
                elif header.flags == FINACK_MSG:
                    self.handleFinAck()
            else:  # Fragmented message
                if not (header.flags & FLAG_ACK) and not (header.flags & FLAG_NACK):  # Not fragmented ACK/NACK
                    if not (header.flags & FLAG_DATA):  # Not data
                        continue  # Ignore unexpected message
                    if not startTime:
                        startTime = time.time()

                    aktualFragNumber = header.fragNumber

                    if aktualFragNumber == 0:
                        # This is the file name packet
                        fileName = data.decode('utf-8')
                        print(f"Received file name: {fileName}")
                        # Send ACK for file name
                        self.sendACK(aktualFragNumber, True, bool(header.flags & FLAG_DATA))
                        continue  # Proceed to next packet

                    if header.flags & FLAG_LAST_FRAGMENT:  # Last fragment
                        totalFragments = aktualFragNumber

                    if aktualFragNumber not in fragmentBuffer:
                        fragmentBuffer[aktualFragNumber] = data
                        print(f"Received fragment {aktualFragNumber} and stored in buffer.")
                        self.sendACK(aktualFragNumber, True, bool(header.flags & FLAG_DATA))

                    # Check if all fragments are received
                    if totalFragments is not None and len(fragmentBuffer) == totalFragments:
                        if fileName:
                            # File data
                            print("--------------------------")
                            print("All fragments successfully received.")
                            print(f"Transfer time: {time.time() - startTime} s.")
                            print("--------------------------")
                            # Save the file in the specified directory
                            filePath = os.path.join(SAVE_PATH, fileName)
                            try:
                                with open(filePath, "wb") as file:
                                    for i in range(1, totalFragments + 1):
                                        if i in fragmentBuffer:
                                            file.write(fragmentBuffer[i])
                                        else:
                                            raise ValueError(f"Missing fragment {i}")
                                print(f"File '{fileName}' has been successfully saved in the directory '{SAVE_PATH}'.")
                            except Exception as e:
                                print(f"Failed to save file '{fileName}' in directory '{SAVE_PATH}'. Error: {e}")
                            fragmentBuffer.clear()
                            totalFragments = None
                            startTime = None
                            fileName = None
                        else:
                            # Text message
                            try:
                                fullMessage = "".join(
                                    fragmentBuffer[i].decode("utf-8") for i in range(1, totalFragments + 1)
                                )
                                print("--------------------------")
                                print("All fragments successfully received.")
                                print(f"Transfer time: {time.time() - startTime} s.")
                                print(f"Text size: {len(fullMessage)}.")
                                print("--------------------------")
                                print(f"\nReceived message:\n{fullMessage}")
                            except UnicodeDecodeError:
                                print("Received fragmented data is not valid UTF-8.")
                            fragmentBuffer.clear()
                            totalFragments = None
                            startTime = None
                else:  # Fragmented ACK/NACK
                    # Handle ACK/NACK received for our sent data
                    self.processACKNACK(header)

            # Check if user has requested to close the connection
            if self.close_requested and not self.FIN_sent:
                self.sendFin()

    def processACKNACK(self, header):
        # Handle ACK/NACK for sent data
        fragNumber = header.ackNumber
        if fragNumber == 0:
            eventAckReceived.set()
            return
        if fragNumber not in self.buffer and fragNumber not in self.send_ackStatus:
            # This fragment is not pending, ignore
            return
        if header.flags & FLAG_NACK:
            self.send_ackStatus[fragNumber] = False
            print(f"Received NACK for fragment {fragNumber}")

        elif header.flags & FLAG_ACK:
            self.send_ackStatus[fragNumber] = True
            print(f"Received ACK for fragment {fragNumber}")
            if fragNumber in self.buffer:
                del self.buffer[fragNumber]

        # Resend packets marked with NACK or those not acknowledged
        for frag_num in list(self.buffer.keys()):
            if self.send_ackStatus.get(frag_num) == False or frag_num in self.buffer:
                print(f"Packet {frag_num} lost or NACKed, regenerating and resending")
                try:
                    # Extract necessary information to regenerate the packet
                    packet_info = self.buffer[frag_num]
                    header_obj = ProtocolHeader.unpack(packet_info[:10])
                    flags, ackNumber, data = header_obj.flags, frag_num, packet_info[10:-2]
                    regenerated_packet = MessageHandler.createPacket(flags, frag_num, ackNumber, data)
                    self.sendPacket(regenerated_packet)
                    # Update the buffer with the regenerated packet
                    self.buffer[frag_num] = regenerated_packet
                    time.sleep(0.01)
                except Exception as e:
                    print(f"Error resending packet {frag_num}: {e}")

        # Check if all fragments have been ACKed
        if len(self.buffer) == 0:
            print("Entire window acknowledged")
            self.send_ackStatus.clear()
            self.eventWindowAcked.set()

    # 4-way handshake
    def handleFin(self):
        print(f"FIN received.")
        if not self.FINACK_sent:
            try:
                FINACKpacket = MessageHandler.createPacket(FINACK_MSG, 0, 0)
                self.sendPacket(FINACKpacket)
                print(f"FINACK packet sent.")
                self.FINACK_sent = True
            except Exception as e:
                print(f"Error sending FINACK: {e}")
        self.FIN_received = True

        # Automatically send FIN if not already sent
        if not self.FIN_sent:
            self.sendFin()
            self.FIN_sent = True

        # Check if termination conditions are met
        self.check_connection_close()

    def handleFinAck(self):
        print(f"FINACK received.")
        self.FINACK_received = True

        # Check if termination conditions are met
        self.check_connection_close()

    def check_connection_close(self):
        # Close connection if:
        # - This peer has sent FIN and received FINACK
        # OR
        # - This peer has received FIN and sent FINACK
        if (self.FIN_sent and self.FINACK_received) or (self.FIN_received and self.FINACK_sent):
            print("Termination conditions met. Closing connection.")
            self.close_connection()

    def close_connection(self):
        self.CONNECTION = False
        self.connection_closed.set()  # Signal that the connection is closed
        print("Connection closed.")
        try:
            self.sockListen.close()
            self.sockSend.close()
            print("Sockets closed")
        except OSError as e:
            print(f"Error closing sockets: {e}")

    # Keep alive
    def keepAlive(self):
        aktualFragNumber = 0
        aktualAckNumber = 0
        KEEPALIVEpacket = MessageHandler.createPacket(KEEPALIVE_MSG, aktualFragNumber, aktualAckNumber)

        while self.CONNECTION:
            try:
                self.sendPacket(KEEPALIVEpacket)
                time.sleep(5)
            except Exception as e:
                print(f"Error sending KEEPALIVE: {e}")
                break  # Exit keepAlive if sending fails

    # CONTROL MESSAGES
    def sendACK(self, fragNumber, isFragmented, isData, isCorrupted=False):
        flags = 0
        if isCorrupted:
            flags |= FLAG_NACK
        else:
            flags |= FLAG_ACK

        if isFragmented:
            flags |= FLAG_FRAGMENTED
        if isData:
            flags |= FLAG_DATA

        aktualFragNumber = 0
        aktualAckNumber = fragNumber
        try:
            ACKpacket = MessageHandler.createPacket(flags, aktualFragNumber, aktualAckNumber)
            self.sendPacket(ACKpacket)
            if isCorrupted:
                print(f"NACK sent for fragment {fragNumber}.")
            else:
                print(f"ACK sent for fragment {fragNumber}.")
        except Exception as e:
            print(f"Error sending ACK/NACK for fragment {fragNumber}: {e}")

    # sendFin is now a method of Peer
    def sendFin(self):
        if not self.FIN_sent:
            try:
                self.close_requested = True
                aktualSeqNumber = 0
                aktualAckNumber = 0
                FINpacket = MessageHandler.createPacket(FIN_MSG, aktualSeqNumber, aktualAckNumber)
                self.sendPacket(FINpacket)
                print(f"FIN sent.")
                self.FIN_sent = True
            except Exception as e:
                print(f"Error sending FIN: {e}")
        else:
            print("FIN already sent.")

# ===========================================================================
# SENDING DIFFERENT TYPES OF MESSAGES

# TEXT
def sendTEXT(PEER, FRAGMENT_SIZE, WINDOW_SIZE):
    global TEXT_MSG

    msg = input("\nEnter your message:\n")

    if len(msg) > FRAGMENT_SIZE:
        sendFragTEXT(PEER, msg, FRAGMENT_SIZE, WINDOW_SIZE)
    else:
        aktualFragNumber = 0
        aktualAckNumber = 0
        try:
            TEXTpacket = MessageHandler.createPacket(TEXT_MSG, aktualFragNumber, aktualAckNumber, msg)
            PEER.sendPacket(TEXTpacket)
            print(f"Message sent.")
            eventAckReceived.wait()
            eventAckReceived.clear()
        except Exception as e:
            print(f"Error sending TEXT message: {e}")

def sendFragTEXT(PEER, msg, FRAGMENT_SIZE, WINDOW_SIZE):
    ackNumber = 0

    dataChunks = [
        msg[i:i + FRAGMENT_SIZE]
        for i in range(0, len(msg), FRAGMENT_SIZE)
    ]

    totalPackets = []
    totalFragments = len(dataChunks)
    lastFragmentSize = 0
    for fragNumber, chunk in enumerate(dataChunks, start=1):
        if fragNumber == totalFragments:
            flags = TEXT_MSG_FRAG_L
            lastFragmentSize = len(chunk)
        else:
            flags = TEXT_MSG_FRAG

        # Check if this is the packet to corrupt
        corrupt_crc = False
        if PEER.errorPacketID == fragNumber:
            corrupt_crc = True
            print(f"Corrupting CRC for packet {fragNumber}")
            packet = MessageHandler.createPacket(flags, fragNumber, ackNumber, chunk, corrupt_crc=corrupt_crc)
        else:
            packet = MessageHandler.createPacket(flags, fragNumber, ackNumber, chunk, corrupt_crc=corrupt_crc)
        corrupt_crc = False        
        totalPackets.append((fragNumber, packet))
        # We will add packets to buffer in the window loop

    windows = [
        totalPackets[i:i + WINDOW_SIZE]
        for i in range(0, len(totalPackets), WINDOW_SIZE)
    ]

    for windowIndex, window in enumerate(windows):
        PEER.send_ackStatus.clear()
        PEER.buffer.clear()
        print(f"\nSending window {windowIndex + 1}/{len(windows)}. Packets in window: {len(window)}.")
        print("--------------------------")

        for fragNumber, packet in window:
            PEER.buffer[fragNumber] = packet
            try:
                PEER.sendPacket(packet)
                print(f"Packet {fragNumber} sent.")
                time.sleep(0.01)
            except Exception as e:
                print(f"Error sending packet {fragNumber}: {e}")

        while True:
            # Wait for acknowledgments
            if PEER.eventWindowAcked.wait(timeout=2):
                PEER.eventWindowAcked.clear()
                break
            else:
                # Resend unacknowledged packets
                if len(PEER.buffer) == 0:
                    break  # Exit if no packets are left to be resent
                for fragNumber in list(PEER.buffer.keys()):
                    if PEER.send_ackStatus.get(fragNumber) == False or fragNumber in PEER.buffer:
                        print(f"Packet {fragNumber} lost or not acknowledged, regenerating and resending")
                        try:
                            packet_info = PEER.buffer[fragNumber]
                            header_obj = ProtocolHeader.unpack(packet_info[:10])
                            flags, ackNumber, data = header_obj.flags, fragNumber, packet_info[10:-2]
                            regenerated_packet = MessageHandler.createPacket(flags, fragNumber, ackNumber, data)
                            PEER.sendPacket(regenerated_packet)
                            PEER.buffer[fragNumber] = regenerated_packet
                            time.sleep(0.01)
                        except Exception as e:
                            print(f"Error resending packet {fragNumber}: {e}")
        print("All packets in window received")
    print("--------------------------")
    print(f"Text size: {len(msg)}.")
    print(f"Fragment size: {FRAGMENT_SIZE}.")
    if FRAGMENT_SIZE != lastFragmentSize:
        print(f"Last fragment size: {lastFragmentSize}.")
    print("--------------------------")
    print("Message successfully sent.")
    PEER.errorPacketID = None  # Reset error packet ID after sending

# FILE
def sendFILE(PEER, FRAGMENT_SIZE, WINDOW_SIZE):
    global FILE_MSG, FILE_MSG_L

    while True:
        try:
            absolutePath = input("\nEnter the absolute path to the file you want to send:\n")
            if not os.path.exists(absolutePath):
                raise ValueError("The specified file does not exist!")
            elif not os.path.isfile(absolutePath):
                raise ValueError("The specified path is not a file!")
            else:
                break
        except ValueError as e:
            print(e)

    fileName = os.path.basename(absolutePath)
    fileSize = os.path.getsize(absolutePath)
    try:
        fileNamePacket = MessageHandler.createPacket(FILE_MSG, 0, 0, fileName.encode("utf-8"))
    except Exception as e:
        print(f"Error creating file name packet: {e}")
        return

    print(f"Sending file: {fileName}")
    print("--------------------------")
    try:
        PEER.sendPacket(fileNamePacket)
        print("Sending file name.")
    except Exception as e:
        print(f"Error sending file name packet: {e}")
        return

    while True:
        flag = eventAckReceived.wait(timeout=2)
        if flag:
            print("ACK for file name received.")
            break
        else:
            print("Timeout waiting for ACK. Resending packet")
            try:
                PEER.sendPacket(fileNamePacket)
            except Exception as e:
                print(f"Error resending file name packet: {e}")

    eventAckReceived.clear()
    print("--------------------------")

    dataChunks = []
    try:
        with open(absolutePath, "rb") as file:
            while True:
                chunk = file.read(FRAGMENT_SIZE)
                if not chunk:
                    break
                dataChunks.append(chunk)
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    totalPackets = []
    totalFragments = len(dataChunks)
    lastFragmentSize = 0
    ackNumber = 0
    # Start fragNumber from 1
    for fragNumber, chunk in enumerate(dataChunks, start=1):
        if fragNumber == totalFragments:
            flags = FILE_MSG_L
            lastFragmentSize = len(chunk)
        else:
            flags = FILE_MSG

        # Check if this is the packet to corrupt
        corrupt_crc = False
        if PEER.errorPacketID == fragNumber:
            PEER.errorPacketID = None
            corrupt_crc = True
            print(f"Corrupting CRC for packet {fragNumber}")

        try:
            packet = MessageHandler.createPacket(flags, fragNumber, ackNumber, chunk, corrupt_crc=corrupt_crc)
        except Exception as e:
            print(f"Error creating packet {fragNumber}: {e}")
            continue
        totalPackets.append((fragNumber, packet))
        # We will add packets to buffer in the window loop

    windows = [
        totalPackets[i:i + WINDOW_SIZE]
        for i in range(0, len(totalPackets), WINDOW_SIZE)
    ]

    for windowIndex, window in enumerate(windows):
        PEER.send_ackStatus.clear()
        PEER.buffer.clear()
        print(f"\nSending window {windowIndex + 1}/{len(windows)}. Packets in window: {len(window)}.")
        print("--------------------------")

        for fragNumber, packet in window:
            PEER.buffer[fragNumber] = packet
            try:
                PEER.sendPacket(packet)
                print(f"Packet {fragNumber} sent.")
                time.sleep(0.01)
            except Exception as e:
                print(f"Error sending packet {fragNumber}: {e}")

        while True:
            # Wait for acknowledgments
            if PEER.eventWindowAcked.wait(timeout=2):
                PEER.eventWindowAcked.clear()
                break
            else:
                # Resend unacknowledged packets
                if len(PEER.buffer) == 0:
                    break  # Exit if no packets are left to be resent
                for fragNumber in list(PEER.buffer.keys()):
                    if PEER.send_ackStatus.get(fragNumber) == False or fragNumber in PEER.buffer:
                        print(f"Packet {fragNumber} lost or not acknowledged, regenerating and resending")
                        try:
                            packet_info = PEER.buffer[fragNumber]
                            header_obj = ProtocolHeader.unpack(packet_info[:10])
                            flags, ackNumber, data = header_obj.flags, fragNumber, packet_info[10:-2]
                            regenerated_packet = MessageHandler.createPacket(flags, fragNumber, ackNumber, data)
                            PEER.sendPacket(regenerated_packet)
                            PEER.buffer[fragNumber] = regenerated_packet
                            time.sleep(0.01)
                        except Exception as e:
                            print(f"Error resending packet {fragNumber}: {e}")
            print("All packets in window received")
    print("--------------------------")
    print(f"File size: {fileSize} bytes.")
    print(f"Fragment size: {FRAGMENT_SIZE} bytes.")
    if FRAGMENT_SIZE != lastFragmentSize:
        print(f"Last fragment size: {lastFragmentSize} bytes.")
    print("--------------------------")
    if PEER.errorPacketID is None:  # Reset error packet ID after sending
        print("File successfully sent.")

def sendFin(PEER):
    # This function is no longer needed as sendFin is now a method of Peer
    pass  # Placeholder if needed

# ===========================================================================
# FUNCTIONS

# USER INPUT HANDLING
def handleUserInput(PEER, FRAGMENT_SIZE, WINDOW_SIZE):
    printMenu()
    while True:
        command = input()
        if command == '1':
            sendTEXT(PEER, FRAGMENT_SIZE, WINDOW_SIZE)
        elif command == '2':
            sendFILE(PEER, FRAGMENT_SIZE, WINDOW_SIZE)
        elif command == '3':
            changeFragmentSize()
        elif command == '4':
            changeSavePath()
        elif command == '5':
            PEER.sendFin()  # Call the Peer class method
            break
        elif command == '6':
            introduceCRCErrror(PEER)
        elif command == 'm':
            printMenu()
        else:
            print("----Invalid command!!!----")
            print("Press 'm' for menu.")

# NEW FUNCTION FOR INTRODUCING CRC ERROR
def introduceCRCErrror(PEER):
    print("\nIntroduce Artificial CRC Error")
    while True:
        try:
            packet_id = int(input("Enter the packet ID (fragment number) you want to corrupt: "))
            if packet_id <= 0:
                raise ValueError("Packet ID must be a positive integer.")
            PEER.errorPacketID = packet_id
            print(f"Packet {packet_id} will have its CRC corrupted.")
            break
        except ValueError as e:
            print(f"Invalid input: {e}")
    print("Now, please proceed to send your message or file.")
    print(f"Note: The CRC of packet with fragment number {packet_id} will be corrupted.")

# CHANGING FRAGMENT SIZE
def changeFragmentSize():
    global FRAGMENT_SIZE
    while True:
        try:
            newFragSize = int(input("Enter the maximum fragment size (value between 1 - 1420): "))
            if newFragSize < 1 or newFragSize > 1420:
                raise ValueError
            FRAGMENT_SIZE = newFragSize
            print(f"Fragment size changed to: {FRAGMENT_SIZE} bytes.")
            break
        except ValueError:
            print("Invalid input! Please enter an integer between 1 - 1420.")

# CHANGING SAVE PATH
def changeSavePath():
    global SAVE_PATH
    while True:
        newPath = input("Enter the absolute path where files should be saved: ")
        if os.path.isdir(newPath):
            SAVE_PATH = newPath
            print(f"Save path changed to: {SAVE_PATH}")
            break
        else:
            print("Invalid path! Please enter a valid directory.")

# PRINT MENU FOR COMMANDS
def printMenu():
    print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("1. Send a text message")
    print("2. Send a file")
    print("3. Change maximum fragment size")
    print("4. Change file save path")
    print("5. Request connection termination")
    print("6. Introduce artificial CRC error")
    print("\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~")
    print("Enter command:", end=" ")

# DETERMINE IF I'M SENDER
def setSender(SOURCE_IP, DESTINATION_IP, LISTEN_PORT, TARGET_PORT):
    SYN_SENDER = False
    if SOURCE_IP == DESTINATION_IP:
        if LISTEN_PORT < TARGET_PORT:
            SYN_SENDER = True
    elif SOURCE_IP < DESTINATION_IP:
        SYN_SENDER = True
    return SYN_SENDER

# STARTING POINT OF 3-WAY HANDSHAKE
def startHandshake(PEER):
    aktualFragNumber = 0
    aktualAckNumber = 0

    input("Press Enter after starting the other side to continue.")

    try:
        SYNpacket = MessageHandler.createPacket(SYN_MSG, aktualFragNumber, aktualAckNumber)
        PEER.sendPacket(SYNpacket)
        print("\n=====================================")
        print("SYN packet sent.")
    except Exception as e:
        print(f"Error sending SYN packet: {e}")

# SUMMARY OF CONNECTION
def printConnectionEstablished(source_ip, listen_port, destination_ip, target_port):
    print("=====================================")
    print(f"Connection established with {destination_ip}")
    print(f"Listening on port {listen_port}")
    print(f"Sending to port {target_port}")
    print("=====================================")

# ===========================================================================
# GLOBAL VARIABLES
# Removed global CONNECTION
SYN_SENDER = False

# Adjusted event to properly manage connection close
eventAckReceived = threading.Event()

FRAGMENT_SIZE = 1420
WINDOW_SIZE = 50
SAVE_PATH = os.getcwd()

# MAIN
if __name__ == "__main__":
    SOURCE_IP = getSourceIp()
    print(f"Your IP address: {SOURCE_IP}")
    LISTEN_PORT = getListenPort()
    DESTINATION_IP = getDestinationIP()
    TARGET_PORT = getTargetPort(LISTEN_PORT)

    print(f"\nSource IP: {SOURCE_IP}\nListening port: {LISTEN_PORT}\n")
    print(f"Destination IP: {DESTINATION_IP}\nTarget port: {TARGET_PORT}\n")
    print(f"Default file save path: {SAVE_PATH}")

    SYN_SENDER = setSender(SOURCE_IP, DESTINATION_IP, LISTEN_PORT, TARGET_PORT)
    PEER = Peer(SOURCE_IP, LISTEN_PORT, DESTINATION_IP, TARGET_PORT)

    threadListenHandshake = threading.Thread(target=PEER.listenHandshake)
    if SYN_SENDER:
        startHandshake(PEER)
        threadListenHandshake.start()
    else:
        threadListenHandshake.start()

    threadListenHandshake.join()

    threadKeepAlive = threading.Thread(target=PEER.keepAlive)
    threadKeepAlive.daemon = True
    threadKeepAlive.start()

    threadListen = threading.Thread(target=PEER.listen)
    threadListen.daemon = True
    threadListen.start()

    threadUserInput = threading.Thread(target=handleUserInput, args=(PEER, FRAGMENT_SIZE, WINDOW_SIZE))
    threadUserInput.daemon = True
    threadUserInput.start()

    # Wait until the connection is closed
    PEER.connection_closed.wait()

    print("\nConnection terminated")
    try:
        PEER.sockListen.close()
        PEER.sockSend.close()
        print("Sockets closed")
    except OSError as e:
        print(f"Error closing sockets: {e}")
    print("Exiting program")
