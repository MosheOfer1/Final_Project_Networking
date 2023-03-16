import argparse
import os
import random
import socket
import threading
import time
import API


class Client:
    def __init__(self):
        self.transaction_id = random.randint(1, (2 ** 8) - 1)
        random_mac = [random.randint(0x00, 0x7f), random.randint(0x00, 0x7f), random.randint(0x00, 0x7f),
                      random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff)]
        self.client_mac = ':'.join(map(lambda x: "%02x" % x, random_mac))
        self.client_ip = None
        self.dns_ip = None
        self.app_ip = None
        self.gateway = None
        self.sub_net = None
        self.dns_identification = random.randint(1, (2 ** 16) - 1)


def receive_safely_TCP(data_sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) != size:
        chunk = data_sock.recv(API.BUFFER_SIZE)
        if not chunk:
            break
        data += chunk
    return data


def download(data_sock, size: int, name: str):
    # Receive the file data from the server
    if isinstance(data_sock, API.RUDPConnection):
        data = API.RUDPConnection.receive_safely(data_sock=data_sock, size=int(size))
    else:
        data = receive_safely_TCP(data_sock=data_sock, size=int(size))
    # Save the img
    with open(f"{name}", "wb") as f:
        f.write(data)
    f.close()


def printMsg(connection) -> str:
    data = connection.recv(API.BUFFER_SIZE)
    if isinstance(connection, API.RUDPConnection):
        data = data[API.RUDPHeader.unpack(data).header_length:]
    data = data.decode()
    print(data)
    return data


def connect_tp_FTP(connection, data_connection, user_name: str, password: str):
    # Receive the welcome msg
    printMsg(connection)
    # Log in to the server
    connection.sendall("USER {}\r\n".format(user_name).encode())
    data = printMsg(connection)

    if not data.startswith("550"):
        connection.sendall("PASS {}\r\n".format(password).encode())
        data = printMsg(connection)

        if not data.startswith("550"):

            # Request a list of files in the current directory
            connection.sendall("LIST\r\n".encode())
            data = printMsg(connection)

            while not data.startswith("550"):
                # Receive the directory listing from the server
                data = data_connection.recv(API.BUFFER_SIZE)
                if isinstance(connection, API.RUDPConnection):
                    data = data[API.RUDPHeader.unpack(data).header_length:]
                files = data.decode().split("\r\n")[0:-1]
                files = [eval(t) for t in files]\

                for file in files:
                    print(f"file name:\r {file}")
                printMsg(connection)

                data = "550"
                # Check for wrong name
                if data.startswith("550"):
                    name = input("Choose file to download or enter y for exit: ")
                    if name == 'y':
                        connection.sendall("QUIT\r\n".encode())
                        data = printMsg(connection)
                        break
                    if not name.endswith('jpg') and not name.endswith('PNG'):
                        name += '.jpg'
                    size = 0
                    for file in files:
                        if file[0] == name:
                            size = file[1]
                            break
                    # Download the file
                    connection.sendall("RETR {}\r\n".format(name).encode())
                    data = printMsg(connection)

                    if data.startswith("550"):
                        print("Not such file")
                        continue

                    print("Downloading file: ", name)

                    down_thread = threading.Thread(target=download, args=(data_connection, size, name))
                    down_thread.start()
                    down_thread.join()
                    printMsg(connection)
                    # Request a list of files in the current directory
                    connection.sendall("LIST\r\n".encode())
                    data = printMsg(connection)

        else:
            print("Wrong Password")
    else:
        print("Wrong user name")


def connect_to_DNS():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        print("trying to call DNS server")
        sock.settimeout(5)
        # Define the domain name to look up
        query = API.DNSHeader.init_DNS_QUERY(domain_name="app.co.il", DNS_id=new_client.dns_identification)
        sock.sendto(query, (new_client.dns_ip, API.DNS_PORT))
        # Wait for the DNS response
        response, server = sock.recvfrom(API.BUFFER_SIZE)
        header = API.DNSHeader.unpack_dns_header(response)
        questions, answers = API.DNSHeader.from_bytes(data=response)
        print(f"Got {header.num_answers} answers from the DNS server {answers}")
        new_client.app_ip = answers[-1][5]


def connect_to_DHCP():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Bind the socket to any available IP address on port 68
        sock.bind((API.LO_HOST, API.CLIENT_PORT_DHCP))

        discovery = API.DHCPHeader.init_discover_header(
            options=API.DHCPHeader.dict_to_tlv({API.TYPE_CODE: API.DISCOVER})
            , client_hardware_address=API.mac_to_bytes(new_client.client_mac)
            , transaction_id=new_client.transaction_id)
        # replace with 255.255.255.255 for broadcast
        sock.sendto(discovery, (API.LO_HOST, API.SERVER_PORT_DHCP))
        data, addr = sock.recvfrom(API.BUFFER_SIZE)

        received_pkt = API.DHCPHeader.unpack_dhcp_header(data)
        options = received_pkt.unpackOptionsList()
        msg_type = API.DHCPHeader.what_type(int.from_bytes(options[API.TYPE_CODE], "big"))

        print(f"Received: {msg_type} from {addr}")

        offered_ip_offer = socket.inet_ntoa(received_pkt.your_ip_address)

        def createRequest(received_packet: 'API.DHCPHeader', offered_ip_offer: str):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                # Bind the socket to any available IP address on port 68
                sock.bind((API.LO_HOST, API.CLIENT_PORT_DHCP))

                # create the request
                request_pkt = API.DHCPHeader.init_request_header(
                    options=API.DHCPHeader.dict_to_tlv({API.TYPE_CODE: API.REQUEST,
                                                        API.YIPR_CODE: received_packet.your_ip_address}),
                    client_hardware_address=API.mac_to_bytes(new_client.client_mac),
                    transaction_id=received_packet.transaction_id
                )
                while True:
                    sock.sendto(request_pkt, (API.LO_HOST, API.SERVER_PORT_DHCP))
                    rec_data, rec_addr = sock.recvfrom(API.BUFFER_SIZE)

                    received_packet = API.DHCPHeader.unpack_dhcp_header(rec_data)
                    offered_ip_ack = socket.inet_ntoa(received_packet.your_ip_address)
                    options_list = received_packet.unpackOptionsList()
                    msgType = API.DHCPHeader.what_type(int.from_bytes(options_list[API.TYPE_CODE], "big"))
                    print(f"Received: {msgType} from {rec_addr}")
                    # confirm that the same ip was offered and was in the ack
                    if offered_ip_offer == offered_ip_ack:
                        print(f'Client IP is {offered_ip_ack}')
                        new_client.client_ip = offered_ip_ack
                        new_client.dns_ip = socket.inet_ntoa(options_list[API.DNS_CODE])
                        new_client.gateway = socket.inet_ntoa(options_list[API.GATEWAY_CODE])
                        new_client.sub_net = socket.inet_ntoa(options_list[API.SUBNET_CODE])
                    else:
                        raise ValueError('The IP from offer and ack not the same')
                    time_for_reconnect = int.from_bytes(options_list[API.LEASETIME_CODE], "big") / 2
                    time.sleep(time_for_reconnect)

        thread = threading.Thread(target=createRequest, args=(received_pkt, offered_ip_offer))
        sock.close()
        thread.start()


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description="The Client.")

    arg_parser.add_argument("-p", "--protocol", type=str,
                            default='rudp', help="The protocol to download the photo")
    args = arg_parser.parse_args()
    protocol = str(args.protocol).lower()
    new_client = Client()
    connect_to_DHCP()
    time.sleep(0.2)
    connect_to_DNS()

    # Call the function with the appropriate parameters
    while True:
        username = input("enter user name")
        password = input("enter password")

        if protocol == 'rudp':
            # RUDP connection
            # Use of our 'RUDPConnection' class as a RUDP connection
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                # Moshe's last 3 digits is '652'
                sock.bind((API.LO_HOST, 20652))
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as data_sock:
                    # Matania's last 3 digits is '991'
                    data_sock.bind((API.LO_HOST, 30991))
                    conn = API.RUDPConnection.connect(rudp_sock=sock, dest=(new_client.app_ip, API.FTP_PORT))
                    data_conn = API.RUDPConnection.connect(rudp_sock=data_sock,
                                                           dest=(new_client.app_ip, API.FTP20_PORT))
                    connect_tp_FTP(connection=conn, data_connection=data_conn, user_name=username, password=password)
        else:
            # TCP connection
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as data_sock:
                    sock.connect((new_client.app_ip, API.FTP_PORT))
                    data_sock.connect((new_client.app_ip, API.FTP20_PORT))
                    connect_tp_FTP(connection=sock, data_connection=data_sock, user_name=username, password=password)
