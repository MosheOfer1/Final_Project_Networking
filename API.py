import math
import queue
import socket
import struct
import threading
import time
import FTP_server

mac_to_bytes = lambda mac_address: bytes([int(x, 16) for x in mac_address.split(":")])
bytes_to_mac = lambda mac_bytes: ":".join(f"{mac_bytes[x]:02x}" for x in range(6))
BUFFER_SIZE = 65536  # The buffer size is the maximum amount of data that can be received at once
threshold = 32
LO_HOST = "127.0.0.1"
CLIENT_PORT_DHCP = 68
SERVER_PORT_DHCP = 67
DNS_PORT = 53
FTP_PORT = 21
FTP20_PORT = 20
DISCOVER = 1
OFFER = 2
REQUEST = 3
ACKNOWLEDGMENT = 5
TYPE_CODE = 53
GATEWAY_CODE = 3
SUBNET_CODE = 1
LEASETIME_CODE = 51
DNS_CODE = 6
YIPR_CODE = 54


class RUDPHeader:
    """
    +-+-+-+-+-+-+-+-+---------------+
    |S|A|E| | | | | |    Header     |
    |Y|C|A|0|0|0|0|0|    Length     |
    |N|K|K| | | | | |               |
    +-+-+-+-+-+-+-+-+---------------+
    |  Seq Number   |   Ack Number  |
    +---------------+---------------+
    |            Checksum           |
    +---------------+---------------+
    /            Options            /
    \                               \
    /                               /
    +-------------------------------+

    """
    # Define the format string for struct.pack and struct.unpack
    FORMAT: str = '!BBBBH'
    # Calculate the minimum length of the header
    MIN_LENGTH: int = struct.calcsize(FORMAT)

    def __init__(self, flags: int, header_length: int, sequence_number: int, ack_number: int, checksum: int,
                 options: list = None):
        if options is None:
            self.options = b''
        else:
            self.options = self.list_to_bytes(options)
        self.flags = flags
        self.header_length = header_length
        self.sequence_number = sequence_number
        self.ack_number = ack_number
        self.checksum = checksum

    def pack(self) -> bytes:
        """
        Pack the header into a bytes object
        """
        return struct.pack(self.FORMAT, self.flags, self.header_length, self.sequence_number, self.ack_number,
                           self.checksum) + self.options

    @staticmethod
    def unpack(data: bytes) -> 'RUDPHeader':
        """
        Unpack a bytes object into a header object
        """
        flags, header_length, sequence_number, ack_number, checksum = struct.unpack(RUDPHeader.FORMAT,
                                                                                    data[:RUDPHeader.MIN_LENGTH])
        return RUDPHeader(flags=flags, header_length=header_length, sequence_number=sequence_number,
                          ack_number=ack_number, checksum=checksum,
                          options=RUDPHeader.bytes_to_list(data[RUDPHeader.MIN_LENGTH:]))

    @staticmethod
    def Checksum(data):
        """
        Calculates the Internet checksum of a byte object.
        """
        # If the length of the data is odd, pad it with a zero byte
        if len(data) % 2 == 1:
            data += b'\x00'

        # Calculate the sum of the 16-bit words in the data
        total = sum(struct.unpack('!{}H'.format(len(data) // 2), data))

        # Fold any carries back into the sum
        while (total >> 16) != 0:
            total = (total & 0xffff) + (total >> 16)

        # Take the one's complement of the sum to get the checksum
        checksum = (~total) & 0xffff

        return checksum

    @staticmethod
    def initiate_syn_header(sequence_number: int, th: int) -> 'RUDPHeader':
        return RUDPHeader(flags=0b10000000, header_length=7, sequence_number=sequence_number,
                          ack_number=0, checksum=0, options=[th])

    @staticmethod
    def initiate_syn_ack_header(sequence_number: int, th: int) -> 'RUDPHeader':
        return RUDPHeader(flags=0b11000000, header_length=7, sequence_number=sequence_number,
                          ack_number=0, checksum=0, options=[th])

    @staticmethod
    def initiate_ack_header(sequence_number: int, ack_number: int) -> 'RUDPHeader':
        return RUDPHeader(flags=0b01000000, header_length=6, sequence_number=sequence_number,
                          ack_number=ack_number, checksum=0)

    @staticmethod
    def initiate_eack_header(sequence_num: int, ack_num: int, out_of_seq: list) -> 'RUDPHeader':
        header_length = RUDPHeader.MIN_LENGTH + len(out_of_seq)
        return RUDPHeader(header_length=header_length, flags=0b01100000, sequence_number=sequence_num,
                          ack_number=ack_num, checksum=0, options=out_of_seq)

    @staticmethod
    def initiate_update_win_size_header(sequence_num: int, ack_num: int, win_size: list) -> 'RUDPHeader':
        header_length = RUDPHeader.MIN_LENGTH + len(win_size)
        return RUDPHeader(header_length=header_length, flags=0b01100000, sequence_number=sequence_num,
                          ack_number=ack_num, checksum=0, options=win_size)

    @staticmethod
    def list_to_bytes(out_of_seq: list[int]) -> bytes:
        b = b''
        for n in out_of_seq:
            b += n.to_bytes(1, "big", signed=False)
        return b

    @staticmethod
    def bytes_to_list(out_of_seq_bytes: bytes) -> list[int]:
        out_of_seq = []
        for i in range(0, len(out_of_seq_bytes)):
            out_of_seq.append(int.from_bytes(out_of_seq_bytes[i:i + 1], "big"))
        return out_of_seq


class SharedSet:
    _lock = threading.Lock()
    _shared_set = set()

    @classmethod
    def add_to_set(cls, value):
        with cls._lock:
            cls._shared_set.add(value)

    @classmethod
    def remove_from_set(cls, value):
        with cls._lock:
            cls._shared_set.remove(value)

    @classmethod
    def has_in_set(cls, e) -> bool:
        with cls._lock:
            return e in cls._shared_set

    @classmethod
    def __str__(cls):
        return str(cls._shared_set)

    @classmethod
    def get_last(cls) -> int:
        return max(cls._shared_set)

    @classmethod
    def clear(cls):
        cls._shared_set.clear()


class RUDPConnection:

    def __init__(self, sock: socket.socket, destination: tuple[str, int], Sequence_num: int, threshold: int,
                 ftp_client: FTP_server.ConnectedClient = None):
        """
        A RUDP connection
        :param Sequence_num: The sequence number field contains the initial sequence number selected for this connection
        :param
        """
        self.client = ftp_client
        self.sock = sock
        self.dest_IP, self.dest_port = destination
        self.seq_num = Sequence_num
        self.window_size = 2
        self.threshold = threshold

    def sendall(self, data: bytes) -> int:
        # First split the data to the necessary number of packets
        packt_size = int((BUFFER_SIZE - RUDPHeader.MIN_LENGTH) / 2)
        count = 0
        packets_to_send = []
        for x in range(0, len(data), packt_size):
            CS = RUDPHeader.Checksum(data[x:x + packt_size])
            SN = int(self.seq_num + count)
            packets_to_send.append(RUDPHeader(flags=0, header_length=6, sequence_number=SN,
                                              ack_number=0, checksum=CS).pack() +
                                   data[x:min(x + packt_size, len(data))])
            count += 1
        packets_numbers = set(range(len(packets_to_send)))
        print(f"Has {packets_numbers} packets to send")
        print(f"{len(packets_numbers)} packets")
        while True:
            try:
                for i in range(self.window_size):
                    if len(packets_numbers) == 0:
                        break
                    self.sock.sendto(packets_to_send[min(packets_numbers)], (self.dest_IP, self.dest_port))
                    packets_numbers.remove(min(packets_numbers))

                m = len(packets_to_send)
                if len(packets_numbers) > 0:
                    m = min(packets_numbers)
                ack_n = -1
                while ack_n != m:
                    # Wait for ACK or EACK
                    if self.client is None:
                        data = self.sock.recv(BUFFER_SIZE)
                    # The Server_Side
                    else:
                        data, _ = self.client.get_packet()
                    ack = RUDPHeader.unpack(data)
                    print(f"The ack is {ack.ack_number}")
                    if ack.flags == 0b01100000:
                        print(f"The lost packets are{ack.bytes_to_list(ack.options)}")

                        break

                    else:
                        ack_n = ack.ack_number

                # ACK
                if ack.flags == 0b01000000:
                    if ack.ack_number == len(packets_to_send):
                        print("finished transfer")
                        break

                    elif ack.ack_number == min(packets_numbers):
                        if self.window_size < self.threshold:
                            self.window_size *= 2
                        else:
                            self.window_size += 1
                        print(f"extending window size to {self.window_size}")


                # EACK
                elif ack.flags == 0b01100000:
                    lost_packets = ack.bytes_to_list(ack.options)
                    for p in lost_packets:
                        packets_numbers.add(p)
                    self.window_size //= 2
                print(f"Has {packets_numbers} packets to send")

            except Exception as e:
                print(e)
        self.window_size = 2

    def recv(self, b=BUFFER_SIZE) -> bytes:
        data = None
        # The Client-Side
        if self.client is None:
            self.sock.settimeout(5)
            try:
                data = self.sock.recv(b)
            except socket.timeout:
                print("Socket timed out!")
                # handle timeout exception
            ack = RUDPHeader.initiate_ack_header(sequence_number=0, ack_number=1)
            self.sock.sendto(ack.pack(), (self.dest_IP, self.dest_port))
        # The Server_Side
        else:
            data, addr = self.client.get_packet()

        return data

    @classmethod
    def accept(cls, ftp_server: FTP_server.Server) -> tuple['RUDPConnection', tuple[str, int]]:
        if ftp_server.sock.type != socket.SOCK_DGRAM:
            raise ValueError("Socket has to be UDP")
        # Wait for SYN
        data, addr = ftp_server.get_syn_packet()
        pkt = RUDPHeader.unpack(data=data)
        if pkt.flags != 0b10000000:
            raise ValueError("The received packet is not SYN")
        seq_num = pkt.sequence_number
        # Send SYN-ACK
        ack_syn = RUDPHeader.initiate_syn_ack_header(sequence_number=pkt.sequence_number,
                                                     th=pkt.bytes_to_list(pkt.options)[0])
        ftp_server.sock.sendto(ack_syn.pack(), addr)

        # wait for ACK
        data, addr = ftp_server.get_syn_packet()
        pkt = RUDPHeader.unpack(data=data)
        if pkt.flags != 0b01000000:
            raise ValueError("The received packet is not ACK")
        if pkt.ack_number != ack_syn.ack_number:
            raise ValueError("The received packet is not the right ACK")
        new_conn_client = FTP_server.ConnectedClient(addr)
        ftp_server.register_client(new_conn_client)
        conn = RUDPConnection(ftp_client=new_conn_client, sock=ftp_server.sock, destination=addr,
                              Sequence_num=seq_num, threshold=threshold)
        return conn, addr

    @classmethod
    def connect(cls, rudp_sock: socket.socket, dest: tuple[str, int]) -> 'RUDPConnection':
        if rudp_sock.type != socket.SOCK_DGRAM:
            raise ValueError("Socket has to be UDP")
        # Send SYN
        first_seq_num = 0  # random.randint(0, 63)
        syn = RUDPHeader.initiate_syn_header(first_seq_num, threshold).pack()
        rudp_sock.sendto(syn, dest)

        # Wait for SYN-ACK
        data, addr = rudp_sock.recvfrom(BUFFER_SIZE)
        pkt = RUDPHeader.unpack(data=data)
        if pkt.flags != 0b11000000:
            raise ValueError("The received packet is not SYN ACK")
        if pkt.sequence_number != first_seq_num:
            raise ValueError("The received packet is not the right SYN ACK")

        # Send ACK
        ack = RUDPHeader.initiate_ack_header(sequence_number=pkt.sequence_number, ack_number=0)
        rudp_sock.sendto(ack.pack(), addr)
        conn = RUDPConnection(sock=rudp_sock, destination=addr, Sequence_num=first_seq_num,
                              threshold=threshold)
        return conn

    @classmethod
    def receiver(cls, data_sock: 'RUDPConnection', size: int, result_queue: queue.Queue):
        q = queue.PriorityQueue()
        size_so_far = 0
        while size_so_far < size:
            data = data_sock.recv()
            if data is None:
                continue
            pkt = RUDPHeader.unpack(data)
            data = data[pkt.header_length:]
            if RUDPHeader.Checksum(data) == pkt.checksum:
                if not SharedSet.has_in_set(pkt.sequence_number - data_sock.seq_num):
                    q.put((pkt.sequence_number - data_sock.seq_num, data))
                    SharedSet.add_to_set(pkt.sequence_number - data_sock.seq_num)
                    size_so_far += len(data)
                    print(f"size so far {size_so_far}\tGot packet num {pkt.sequence_number - data_sock.seq_num}")
                    print(SharedSet.__str__())
                else:
                    print(f"dup  packet num {pkt.sequence_number - data_sock.seq_num}")
            else:
                print("Problem with the CheckSum")

        dat = b''
        while not q.empty():
            num, chunk = q.get_nowait()
            dat += chunk
            print(f'Packet num: {num} At size: {len(chunk)}')
        result_queue.put(dat)

    @classmethod
    def receive_safely(cls, data_sock: 'RUDPConnection', size: int) -> bytes:
        result_queue = queue.Queue()
        SharedSet.clear()
        receive_thread = threading.Thread(target=cls.receiver, args=(data_sock, size, result_queue))
        receive_thread.start()
        last_received = 0
        while receive_thread.is_alive():
            time.sleep(data_sock.window_size * 0.07)
            lost_packets = []
            for i in range(data_sock.window_size + last_received):
                if not SharedSet.has_in_set(i):
                    lost_packets.append(i)

            c = 0
            while SharedSet.has_in_set(c):
                c += 1
            last_received = c - 1
            print(f'last received: {last_received}')
            print(f'window size {data_sock.window_size}')

            if len(lost_packets) == 0:
                print("sending ACK")
                # extend the window size
                if data_sock.window_size < data_sock.threshold:
                    data_sock.window_size *= 2
                else:
                    data_sock.window_size += 1

                ack = RUDPHeader.initiate_ack_header(sequence_number=0,
                                                     ack_number=last_received + 1)
                data_sock.sock.sendto(ack.pack(), (data_sock.dest_IP, data_sock.dest_port))
            else:
                # Lower the window size
                data_sock.window_size //= 2

                print(f"sending EACK with lost packets {lost_packets}")
                if receive_thread.is_alive():
                    eack = RUDPHeader.initiate_eack_header(sequence_num=0, ack_num=lost_packets[0],
                                                           out_of_seq=lost_packets)
                    data_sock.sock.sendto(eack.pack(), (data_sock.dest_IP, data_sock.dest_port))
                else:
                    # last = SharedSet.get_last()
                    print(f"Canceling EACKing... sending ACK {last_received + 1}")
                    ack = RUDPHeader.initiate_ack_header(sequence_number=0,
                                                         ack_number=last_received + 1)
                    data_sock.sock.sendto(ack.pack(), (data_sock.dest_IP, data_sock.dest_port))
        data_sock.window_size = 2
        # Retrieve the data from the result queue
        dat = result_queue.get()
        return dat


class DHCPHeader:
    # Define the format of the header
    FORMAT: str = '!BBBBLHH4s4s4s4s16s64s128s4s'
    SERVER_NAME: bytes = b'MOSHE&MATANIA_DHCP_SERVER'
    MIN_LENGTH: int = struct.calcsize(FORMAT)
    # the practical limit for DHCP options is 274 bytes
    MAX_LENGTH: int = MIN_LENGTH + 274
    OPCODE_BOOTREQUEST: int = 1
    OPCODE_BOOTREPLY: int = 2

    def __init__(self, opcode: int, hardware_type: int, hardware_address_length: int, hops: int,
                 transaction_id: int, seconds: int, flags: int, client_ip_address: bytes,
                 your_ip_address: bytes, server_ip_address: bytes, gateway_ip_address: bytes,
                 client_hardware_address: bytes, server_name: bytes, file: bytes, options: bytes) -> None:
        self.opcode = opcode
        self.hardware_type = hardware_type
        self.hardware_address_length = hardware_address_length
        self.hops = hops
        self.transaction_id = transaction_id
        self.seconds = seconds
        self.flags = flags
        self.client_ip_address = client_ip_address
        self.your_ip_address = your_ip_address
        self.server_ip_address = server_ip_address
        self.gateway_ip_address = gateway_ip_address
        self.client_hardware_address = client_hardware_address
        self.server_name = server_name
        self.file = file
        self.options = options
        # The magic cookie is a specific sequence of bytes (0x63, 0x82, 0x53, 0x63)
        # that is serves as a marker to indicate that a message is a DHCP message rather than a BOOTP message.
        self.magic_cookie = b'\x63\x82\x53\x63'

    def unpackOptionsList(self) -> dict[int:bytes]:
        if not isinstance(self.options, bytes):
            raise TypeError("Input must be of type bytes")

        length = len(self.options)

        options = {}
        count = 0
        while count < length:
            code = int.from_bytes(self.options[count:count + 1], "big", signed=False)
            count += 1

            val_len = int.from_bytes(self.options[count:count + 1], "big", signed=False)
            count += 1
            value = self.options[count:count + val_len]
            count += val_len
            options[code] = value
        return options

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT, self.opcode, self.hardware_type, self.hardware_address_length, self.hops,
                           self.transaction_id, self.seconds, self.flags, self.client_ip_address, self.your_ip_address,
                           self.server_ip_address, self.gateway_ip_address, self.client_hardware_address,
                           self.server_name, self.file, self.magic_cookie) + self.options

    @classmethod
    def unpack_dhcp_header(cls, data: bytes) -> 'DHCPHeader':
        if len(data) < cls.MIN_LENGTH:
            raise ValueError(
                f'The data is too short ({len(data)} bytes) to be a valid DHCP header')
        if len(data) > cls.MAX_LENGTH:
            raise ValueError(
                f'The data is too long ({len(data)} bytes) to be a valid DHCP header')
        unpacked_header = struct.unpack(DHCPHeader.FORMAT, data[:cls.MIN_LENGTH])
        return DHCPHeader(*unpacked_header[:-1], options=data[cls.MIN_LENGTH:])

    @staticmethod
    def dict_to_tlv(d: dict[int,]) -> bytes:
        tlv = b''
        for key, value in d.items():
            if not (isinstance(value, int) or isinstance(value, bytes)):
                raise ValueError(f'{value} is not int or bytes')

            type_ = key.to_bytes(1, byteorder='big')
            if isinstance(value, int):
                value_len_in_bytes = int(math.ceil(math.log2(value + 1) / 8))
                length = value_len_in_bytes.to_bytes(int(math.ceil(math.log2(value_len_in_bytes + 1) / 8)),
                                                     byteorder='big')
                val = value.to_bytes(value_len_in_bytes, byteorder='big')
            else:
                length = len(value).to_bytes(int(math.ceil(math.log2(len(value) + 1) / 8)), byteorder='big')
                val = value
            tlv += type_ + length + val
        return tlv + b'\xff'

    @staticmethod
    def what_type(msg_type: int):
        if msg_type == DISCOVER:
            return "Discover"
        elif msg_type == OFFER:
            return "Offer"
        elif msg_type == REQUEST:
            return "Request"
        elif msg_type == ACKNOWLEDGMENT:
            return "Ack"

    @staticmethod
    def init_discover_header(client_hardware_address: bytes, transaction_id: int, options: bytes,
                             hardware_type: int = 0,
                             hardware_address_length: int = 6, hops: int = 0, seconds: int = 0, flags: int = 0,
                             client_ip_address: bytes = b'',
                             your_ip_address: bytes = b'', server_ip_address: bytes = b'',
                             gateway_ip_address: bytes = b'',
                             sname: bytes = SERVER_NAME, file: bytes = b'\x00' * 128) -> bytes:
        discover = DHCPHeader(opcode=DHCPHeader.OPCODE_BOOTREQUEST, hardware_type=hardware_type,
                              hardware_address_length=hardware_address_length,
                              hops=hops, transaction_id=transaction_id, seconds=seconds, flags=flags,
                              client_ip_address=client_ip_address,
                              your_ip_address=your_ip_address, server_ip_address=server_ip_address,
                              gateway_ip_address=gateway_ip_address,
                              client_hardware_address=client_hardware_address, server_name=sname,
                              file=file, options=options)
        return discover.pack()

    @staticmethod
    def init_request_header(options: bytes, client_hardware_address: bytes, transaction_id: int, hardware_type: int = 0,
                            hardware_address_length: int = 0,
                            hops: int = 0, seconds: int = 0, flags: int = 0,
                            client_ip_address: bytes = b'',
                            your_ip_address: bytes = b'', server_ip_address: bytes = b'',
                            gateway_ip_address: bytes = b'',
                            sname: bytes = SERVER_NAME,
                            file: bytes = b'\x00' * 128) -> bytes:
        request = DHCPHeader(opcode=DHCPHeader.OPCODE_BOOTREQUEST, hardware_type=hardware_type,
                             hardware_address_length=hardware_address_length,
                             hops=hops, transaction_id=transaction_id, seconds=seconds, flags=flags,
                             client_ip_address=client_ip_address,
                             your_ip_address=your_ip_address, server_ip_address=server_ip_address,
                             gateway_ip_address=gateway_ip_address,
                             client_hardware_address=client_hardware_address, server_name=sname,
                             file=file, options=options)
        return request.pack()

    @staticmethod
    def init_offer_header(client_hardware_address: bytes, transaction_id: int, your_ip_address: bytes,
                          server_ip_address: bytes,
                          options: bytes, hardware_type: int = 0, hardware_address_length: int = 6,
                          hops: int = 0, seconds: int = 0, flags: int = 0, client_ip_address: bytes = b'',
                          gateway_ip_address: bytes = b'',
                          sname: bytes = SERVER_NAME, file: bytes = b'\x00' * 128) -> bytes:
        offer = DHCPHeader(opcode=DHCPHeader.OPCODE_BOOTREPLY, hardware_type=hardware_type,
                           hardware_address_length=hardware_address_length,
                           hops=hops, transaction_id=transaction_id, seconds=seconds, flags=flags,
                           client_ip_address=client_ip_address,
                           your_ip_address=your_ip_address, server_ip_address=server_ip_address,
                           gateway_ip_address=gateway_ip_address,
                           client_hardware_address=client_hardware_address, server_name=sname,
                           file=file, options=options)
        return offer.pack()

    @staticmethod
    def init_ack_header(client_hardware_address: bytes, transaction_id: int, options: bytes, your_ip_address: bytes,
                        hardware_type: int = 0, hardware_address_length: int = 6,
                        hops: int = 0, seconds: int = 0, flags: int = 0, client_ip_address: bytes = b'',
                        server_ip_address: bytes = b'', gateway_ip_address: bytes = b'',
                        sname: bytes = SERVER_NAME, file: bytes = b'\x00' * 128) -> bytes:
        ack = DHCPHeader(opcode=DHCPHeader.OPCODE_BOOTREPLY, hardware_type=hardware_type,
                         hardware_address_length=hardware_address_length,
                         hops=hops, transaction_id=transaction_id, seconds=seconds, flags=flags,
                         client_ip_address=client_ip_address,
                         your_ip_address=your_ip_address, server_ip_address=server_ip_address,
                         gateway_ip_address=gateway_ip_address,
                         client_hardware_address=client_hardware_address, server_name=sname,
                         file=file, options=options)
        return ack.pack()


class DNSHeader:
    # Define the format of the header
    FORMAT: str = '!6H'
    MIN_LENGTH: int = struct.calcsize(FORMAT)
    QUERY = 0
    REPLY = 1

    def __init__(self, identification: int, flags: int, num_questions: int, num_answers: int,
                 num_authority_rr: int, num_additional_rr: int, questions=None, answers=None) -> None:
        if answers is None:
            answers = {}
        if questions is None:
            questions = {}
        self.identification = identification
        self.flags = flags
        self.num_questions = num_questions
        self.num_answers = num_answers
        self.num_authority_rr = num_authority_rr
        self.num_additional_rr = num_additional_rr
        name_offset_dict, self.questions = self.questions_to_bytes({}, questions)
        self.answers = self.answers_to_bytes(name_offset_dict=name_offset_dict, answers=answers)

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT, self.identification, self.flags, self.num_questions,
                           self.num_answers, self.num_authority_rr,
                           self.num_additional_rr) + self.questions + self.answers

    @classmethod
    def unpack_dns_header(cls, data: bytes) -> 'DNSHeader':
        if len(data) < cls.MIN_LENGTH:
            raise ValueError(f'The data is too short ({len(data)} bytes) to be a valid DNS header')
        unpacked_header = struct.unpack(DNSHeader.FORMAT, data[:cls.MIN_LENGTH])
        return DNSHeader(*unpacked_header)

    @staticmethod
    def pack_dns_flags(flags: tuple[bool, int, bool, bool, bool, bool, int]) -> int:
        qr = int(flags[0]) << 15
        opcode = flags[1] << 11
        aa = int(flags[2]) << 10
        tc = int(flags[3]) << 9
        rd = int(flags[4]) << 8
        ra = int(flags[5]) << 7
        RCODE = flags[6]
        return qr | opcode | aa | tc | rd | ra | RCODE

    @staticmethod
    def unpack_dns_flags(flags: int) -> tuple[bool, int, bool, bool, bool, bool, int]:
        qr = flags & (1 << 15)  # flags & 0b1_000000000000000
        opcode = (flags >> 11) & ((1 << 4) - 1)  # flags & 0b0_00001111_00000000
        aa = flags & (1 << 10)  # flags & 0b0_00000000_10000000
        tc = flags & (1 << 9)  # flags & 0b0_00000000_01000000
        rd = flags & (1 << 8)  # flags & 0b0_00000000_00100000
        ra = flags & (1 << 7)  # flags & 0b0_00000000_00010000
        RCODE = flags & ((1 << 4) - 1)  # flags & 0b0_00000000_00001111
        return bool(qr), opcode, bool(aa), bool(tc), bool(rd), bool(ra), RCODE

    @staticmethod
    def compress_name(idx: int, name: str, name_offset_dict: dict) -> bytearray:
        dns_format = bytearray()
        if name in name_offset_dict:
            # If it has, add the offset pointer to the bytearray
            # The number 0b11000000 represents the value 192 in decimal. So we added 00000000 to it
            # and by oring it with (name_offset_dict[name]) we get the 2 ones bits and the address of the pointer
            # In the code, this binary number is used as a prefix for a DNS offset pointer
            dns_format += (0b1100000000000000 | (name_offset_dict[name])).to_bytes(2, "big")
        else:
            # If not, encode the name and add it to the name offset dictionary
            name_offset_dict[name] = idx + DNSHeader.MIN_LENGTH  # the header is 12b
            # encode the name by split
            labels = name.split(".")
            for label in labels:
                # Each label is prefixed by the length of that label
                dns_format.append(len(label))
                dns_format += label.encode("utf-8")
            # finish with 0
            dns_format.append(0)
        return dns_format

    @staticmethod
    def questions_to_bytes(name_offset_dict: dict, questions: list[tuple[str, int, int]]) -> tuple[dict, bytes]:
        dns_format = bytearray()
        for question in questions:
            name = question[0]
            q_type = question[1]
            q_class = question[2]
            dns_format += DNSHeader.compress_name(len(dns_format), name, name_offset_dict)
            # encode the type and class
            dns_format += q_type.to_bytes(2, "big")
            dns_format += q_class.to_bytes(2, "big")
        return name_offset_dict, bytes(dns_format)

    @staticmethod
    def answers_to_bytes(name_offset_dict: dict, answers: list[tuple[str, int, int, int, int, bytes]]) -> bytes:
        dns_format = bytearray()
        for ans in answers:
            name = ans[0]
            q_type = ans[1]
            q_class = ans[2]
            q_ttl = ans[3]
            q_rd_length = ans[4]
            q_rd = ans[5]

            dns_format += DNSHeader.compress_name(len(dns_format), name, name_offset_dict)
            # encode the type and class
            dns_format += q_type.to_bytes(2, "big")
            dns_format += q_class.to_bytes(2, "big")
            dns_format += q_ttl.to_bytes(4, "big")
            dns_format += q_rd_length.to_bytes(2, "big")
            dns_format += q_rd

        return bytes(dns_format)

    @staticmethod
    def from_bytes(data: bytes) -> tuple[list[tuple[str, int, int]], list[tuple[str, int, int, int, int, bytes]]]:
        """
        Returns a tuple containing two lists of tuples:

        First list represents the questions in the format (name: str, type: int, class: int)
        Second list represents the answers in the format (name: str, type: int, class: int, ttl: int, data: bytes)
        """
        questions = []
        answers = []
        idx = 12  # Start reading after the DNS header

        num_questions, num_answers = struct.unpack('!HH', data[4:8])
        for _ in range(num_questions):
            question, idx = DNSHeader.read_question(data, idx)
            questions.append(question)

        for _ in range(num_answers):
            answer, idx = DNSHeader.read_answers(data, idx)
            answers.append(answer)

        return questions, answers

    @staticmethod
    def read_question(data: bytes, idx: int) -> tuple[tuple[str, int, int], int]:
        """
        Reads the question section of a DNS packet.

        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                                               /
        /                    NAME                       /
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    TYPE                       |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                   CLASS                       |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        :param data: The packet bytes.
        :param idx: The offset.
        :return: tuple[str, int, int, int]: name, type, class and next offset.
        """
        name, idx = DNSHeader.read_name(data, idx)
        qtype, qclass = struct.unpack('!HH', data[idx:idx + 4])
        idx += 4
        return (name, qtype, qclass), idx

    @staticmethod
    def read_answers(data: bytes, idx: int) -> tuple[tuple[str, int, int, int, int,], int]:
        """
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                                               |
        /                                               /
        /                    NAME                       /
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    TYPE                       |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                   CLASS                       |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    TTL                        |
        |                                               |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                  RDLENGTH                     |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
        /                   RDATA                       /
        /                                               /
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        :param data: The packet bytes.
        :param idx: The offset
        :return: tuple[list[tuple[str, int, int, int, int, bytes]], int]: a list of all fields and the next offset
        """
        name, idx = DNSHeader.read_name(data, idx)
        rrtype, rrclass, ttl, rdlength = struct.unpack('!HHiH', data[idx:idx + 10])
        idx += 10
        rdata = data[idx:idx + rdlength]
        if rrclass == 1:
            rdata = socket.inet_ntoa(rdata)
        idx += rdlength
        return (name, rrtype, rrclass, ttl, rdlength, rdata), idx

    @staticmethod
    def read_name(data: bytes, offset: int) -> tuple[str, int]:
        """
          Extract a domain name from the `data` bytes starting at `offset`
          and return the name as a string and the new offset after reading the name.

          Args:
          - data (bytes): The bytes to be interpreted as the domain name.
          - offset (int): The starting position of the domain name in the bytes.

          Returns:
          tuple[str, int]: The domain name as string and the next offset.
          """
        name = []
        while True:
            length = data[offset]
            # The end
            if length == 0:
                break
            offset += 1
            # Mark to Pointer
            if length == 192:
                # The pointer is extracted by taking the first two bytes at the
                # current offset and masking off the top two bits.
                # 0x3fff in binary is:11111111111111, 14 digits.
                ptr = struct.unpack('!H', data[offset - 1:offset + 1])[0] & 0x3fff
                name2, idx2 = DNSHeader.read_name(data, ptr)
                name.extend(name2.split("."))
                break
            name.append(data[offset:offset + length].decode('utf-8'))
            offset += length
        return '.'.join(name), offset + 1

    @classmethod
    def init_DNS_QUERY(cls, domain_name: str, DNS_id: int) -> bytes:
        question = [(domain_name, 1, 1)]
        query = DNSHeader(identification=DNS_id,
                          flags=DNSHeader.pack_dns_flags((False, 0, False, False, True, False, 0)),
                          num_questions=len(question), num_answers=0,
                          num_authority_rr=0, num_additional_rr=0, questions=question)
        return query.pack()
