import argparse
import socket
import threading
import API

DNS_server_IP = API.LO_HOST  # "192.168.1.2"
domains = {'app.co.il': API.LO_HOST}
clients = []


def start_dns():
    # Create a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # Bind the socket to any available IP address on port 53
        sock.bind((API.LO_HOST, API.DNS_PORT))
        print("DNS server is on")
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


def client_handler(sock: socket.socket, data_and_addr: tuple[bytes, str]) -> None:
    data, address = data_and_addr
    header = API.DNSHeader.unpack_dns_header(data=data)
    # the flag says its response
    if API.DNSHeader.unpack_dns_flags(header.flags)[0]:
        print("response")
        trans_id = header.identification
        for c in clients:
            if c[1] == trans_id:
                sock.sendto(data, c[0])
                break
    else:
        received_pkt = API.DNSHeader.from_bytes(data=data)
        print(f"Got Dns Request {received_pkt}")
        for name in received_pkt[0][0]:
            if name in domains:
                ip_b = socket.inet_aton(domains[name])
                answers = [(name, 1, 1, 64, len(ip_b), ip_b)]
                reply = API.DNSHeader(identification=header.identification,
                                      flags=API.DNSHeader.pack_dns_flags((True, 0, True, True, False, False, 0)),
                                      num_questions=len(received_pkt[0]),
                                      num_answers=len(answers), num_authority_rr=0, questions=received_pkt[0],
                                      num_additional_rr=0, answers=answers)
                sock.sendto(reply.pack(), address)

                break
            else:
                clients.append((address, header.identification))
                sock.sendto(data, ('8.8.8.8', API.DNS_PORT))


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description="DNS server.")

    arg_parser.add_argument("-H", "--host", type=str,
                            default=API.LO_HOST, help="The host to connect to.")

    args = arg_parser.parse_args()

    DNS_server_IP = args.host
    start_dns()
