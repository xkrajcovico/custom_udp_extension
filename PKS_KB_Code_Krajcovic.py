import socket
import threading
import struct

SYN = 0b0001
ACK = 0b0010
SYN_ACK = SYN|ACK
FIN = 0b0100


class Header:
    def __init__(self, type_of_message, handshake_flags, flags, flag_offset, fragment_offset, sequence_number, total_fragments):
        self.type_of_message = type_of_message                  # text message / file
        self.handshake_flags = handshake_flags    # handshake flags (SYN, ACK, etc.)
        self.flags = flags                                      # flags (e.g., data, control)
        self.flag_offset = flag_offset                          # reserved to 0
        self.fragment_offset = fragment_offset                  # current fragment
        self.sequence_number = sequence_number                  # sequence number
        self.total_fragments = total_fragments                  # total number of fragments

    def to_bytes(self):
        TOS = (self.type_of_message << 4) | self.handshake_flags  # bitshift, then add
        F = (self.flags << 4) | self.flag_offset                         # bitshift, then add
        return struct.pack('!BBHQHH', TOS, F, self.fragment_offset, self.sequence_number, self.total_fragments, 0)

    @classmethod
    def from_bytes(cls, data):
        unpacked_data = struct.unpack('!BBHQHH', data[:16])  # Ensure exactly 14 bytes are unpacked
        TOS = unpacked_data[0]
        F = unpacked_data[1]

        type_of_message = (TOS >> 4) & 0xF  # Upper 4 bits
        handshake_flags = TOS & 0xF  # Lower 4 bits
        flags = (F >> 4) & 0xF              # Upper 4 bits
        flag_offset = F & 0xF               # Lower 4 bits

        fragment_offset = unpacked_data[2]
        sequence_number = unpacked_data[3]
        total_fragments = unpacked_data[4]

        return cls(type_of_message, handshake_flags, flags, flag_offset, fragment_offset, sequence_number, total_fragments)


def send_messages(target_ip, target_port, sock_send, header_template):
    while True:
        message = input("Enter your message: ")
        if message.strip().lower() == 'exit':
            break

        header_template.handshake_flags = 0b0000 #not handskake
        packed_header = header_template.to_bytes()
        sock_send.sendto(packed_header + message.encode('utf-8'), (target_ip, target_port))

    # exit
    header_template.handshake_flags = FIN
    sock_send.sendto(header_template.to_bytes(), (target_ip, target_port))

    sock_send.close()


def receive_messages(sock_receive, header_template):
    while True:
        data, address = sock_receive.recvfrom(1024)
        if len(data) >= 14:
            header = Header.from_bytes(data[:16])
            message = data[16:].decode('utf-8')

            # Check for handshake flags
            if header.handshake_flags == SYN:  
                print(f"SYN received")
                header_template.handshake_flags = SYN_ACK
                sock_receive.sendto(header_template.to_bytes(), address)

            elif header.handshake_flags == ACK:  # ACK received
                print(f"ACK received")

            elif header.handshake_flags == SYN_ACK:  # SYN-ACK received
                print(f"SYN-ACK received")
                header_template.handshake_flags = ACK  # send ACK
                sock_receive.sendto(header_template.to_bytes(), address)

            elif header.handshake_flags == FIN:  # FIN received
                print(f"FIN received - Closing connection")
                sock_receive.close()
                break

            else:
                # Normal message
                print(f"Received message: {message}")

    sock_receive.close()

def handshake(sock, target_ip, target_port, header_template):
    header_template.handshake_flags = SYN

    retries = 3
    for attempt in range(retries): #try sending 3 syn-requesty
        try:
            sock.sendto(header_template.to_bytes(), (target_ip, target_port))
            data, address = sock.recvfrom(1024)
            if len(data) >= 14:
                header = Header.from_bytes(data[:16])

                if header.handshake_flags == SYN_ACK:  # SYN-ACK received
                    print(f"SYN-ACK received")
                    header_template.handshake_flags = ACK  #send ACK
                    sock.sendto(header_template.to_bytes(), (target_ip, target_port))
                    print("Handshake complete")
                    break
        except ConnectionResetError as e:
            print(f"Connection init error")
        except socket.timeout:
            print(f"Retrying handshake")

    if attempt == retries - 1:
        print("Failed Hanshake")


if __name__ == '__main__':
    local_listen_ip = input("Enter your local listening IP addressess: ")
    local_listen_port = int(input("Enter your local listening port: "))

    target_ip = input("Enter the point's IP addressess: ")
    target_port = int(input("Enter the point's port: "))
    
    sock_send = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_receive = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_receive.bind((local_listen_ip, local_listen_port))

    temp_header = Header(type_of_message=SYN, handshake_flags=0b0000, flags=0b1111, flag_offset=0b0000, fragment_offset=0, sequence_number=1, total_fragments=1)

    # Handshake
    threading.Thread(target=handshake, args=(sock_send, target_ip, target_port, temp_header)).start()

    # Receiving thread
    recv_thread = threading.Thread(target=receive_messages, args=(sock_receive, temp_header))
    recv_thread.daemon = True
    recv_thread.start()

    # Sending thread
    send_thread = threading.Thread(target=send_messages, args=(target_ip, target_port, sock_send, temp_header))
    send_thread.start()

    send_thread.join()

    print("exiting")
