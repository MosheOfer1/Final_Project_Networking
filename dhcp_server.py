import argparse
import socket
import threading
import time
import API

LEASE_TIME = 86400  # 86400 is one day which is the time that has to update again
# In order to avoid a case which 2 clients get the ip offer, we keep a list of the offered IPs
available_ips = ["192.168.1." + str(i) for i in range(101, 201)]
offered_ips = []
clients = []
DNS_server_IP = API.LO_HOST  # "192.168.1.2"
DHCP_server_IP = API.LO_HOST  # "192.168.1.1"
SUB_NET = "255.255.255.0"
gate_way = API.LO_HOST  # "gateway ip"


def start_dhcp_server():
    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Bind the socket to any available IP address on port 67
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((DHCP_server_IP, API.SERVER_PORT_DHCP))

        print(f"There is {len(available_ips)} available IPs for this local net")
        threads = []
        while True:
            try:
                # Receive data from clients
                data_and_addr = sock.recvfrom(API.BUFFER_SIZE)
                thread = threading.Thread(target=client_handler, args=(sock, data_and_addr))
                thread.start()
                threads.append(thread)
            except KeyboardInterrupt:
                print("Shutting down...")
                break

        for thread in threads:  # Wait for all the threads to finish
            thread.join()


def remove_with_timeout(ip, timeout):
    time.sleep(timeout)
    if ip in offered_ips:
        available_ips.append(ip)
        offered_ips.remove(ip)


def client_handler(sock: socket.socket, data_and_addr: tuple[bytes,]) -> None:
    received_pkt = API.DHCPHeader.unpack_dhcp_header(data_and_addr[0])
    options = received_pkt.unpackOptionsList()
    msg_type = API.DHCPHeader.what_type(int.from_bytes(options[API.TYPE_CODE], "big", signed=False))
    print(
        f"Received: {msg_type} from {data_and_addr[1]} \tMac Address: {API.bytes_to_mac(received_pkt.client_hardware_address)}")

    if msg_type == 'Discover':
        if available_ips:
            # Offer the first IP in the list
            ip = available_ips.pop()
            offered_ips.append(ip)
            # The dynamic allocation approach
            timeout_thread = threading.Thread(target=remove_with_timeout, args=(ip, 2))
            timeout_thread.start()
            # Create and send a DHCP offer packet
            offer_pkt = API.DHCPHeader.init_offer_header(
                options=API.DHCPHeader.dict_to_tlv({API.TYPE_CODE: API.OFFER, API.LEASETIME_CODE: LEASE_TIME}),
                client_hardware_address=received_pkt.client_hardware_address,
                transaction_id=received_pkt.transaction_id,
                your_ip_address=socket.inet_aton(ip), server_ip_address=socket.inet_aton(DHCP_server_IP))
            # each time a client sends a discovery packet the server erase his previous instance
            for c in clients:
                if getattr(c, 'mac_addr') == received_pkt.client_hardware_address:
                    clients.remove(c)
                    break
            clients.append(
                ClientInfo(transaction_id=received_pkt.transaction_id, mac_addr=received_pkt.client_hardware_address))
            sock.sendto(offer_pkt, data_and_addr[1])

    elif msg_type == 'Request':
        req_ip = socket.inet_ntoa(options[API.YIPR_CODE])
        # confirm that this is a known client and check for match between the mac addr and the transaction ID
        for c in clients:
            if getattr(c, 'transaction_id') == received_pkt.transaction_id \
                    and getattr(c, 'mac_addr') == received_pkt.client_hardware_address:
                # 2 options, or it's an extent request,
                # or it's first connect request and then the ip is stored for 2 secs in the offered_ips list
                if getattr(c, 'ip') == req_ip or req_ip in offered_ips:
                    acknowledge_pkt = API.DHCPHeader.init_ack_header(
                        your_ip_address=options[API.YIPR_CODE],
                        client_hardware_address=received_pkt.client_hardware_address,
                        transaction_id=received_pkt.transaction_id,
                        options=API.DHCPHeader.dict_to_tlv(
                            {API.TYPE_CODE: API.ACKNOWLEDGMENT,
                             API.GATEWAY_CODE: socket.inet_aton(gate_way),
                             API.SUBNET_CODE: socket.inet_aton(SUB_NET),
                             API.LEASETIME_CODE: LEASE_TIME,
                             API.DNS_CODE: socket.inet_aton(DNS_server_IP)}))
                    sock.sendto(acknowledge_pkt, data_and_addr[1])
                    if req_ip in offered_ips:
                        offered_ips.remove(req_ip)
                        c.ip = req_ip
                        print(
                            f"Allocation of IP address is successfully done.\t{len(available_ips)} available IPs left in "
                            f"this local net\n{req_ip} for {API.bytes_to_mac(received_pkt.client_hardware_address)}")
                    else:
                        print(
                            f"Reconnection of IP address is successfully done.\n{req_ip} for {API.bytes_to_mac(received_pkt.client_hardware_address)}")
                    c.start_timeout(LEASE_TIME)

                    break
        else:
            print(f"{req_ip} is no longer available")


class ClientInfo:
    def __init__(self, transaction_id: int, mac_addr: bytes, ip: str = None):
        self.transaction_id = transaction_id
        self.ip = ip
        self.mac_addr = mac_addr
        self.timeOutThreads: [threading.Thread] = []

    def start_timeout(self, lease_time: int):
        self.timeOutThreads.append(threading.Thread(target=self.oneDayTimeOut, args=(lease_time,)))
        self.timeOutThreads[-1].start()

    def oneDayTimeOut(self, lease_time: int):
        time.sleep(lease_time)
        self.timeOutThreads.remove(threading.current_thread())
        if len(self.timeOutThreads) == 0:
            # one day passed and no reconnection reestablish so remove this client and return his ip to the list
            available_ips.append(self.ip)
            # need to notify the router that this client is out #
            clients.remove(self)
            print(f"Time out for {API.bytes_to_mac(self.mac_addr)} no reconnection establish from {self.ip}")


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description="DHCP server.")

    arg_parser.add_argument("-H", "--host", type=str,
                            default=API.LO_HOST, help="The host to connect to.")

    args = arg_parser.parse_args()

    DHCP_server_IP = args.host
    start_dhcp_server()
