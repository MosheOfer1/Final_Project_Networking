import argparse
import os
import socket
import threading
import time
from io import BytesIO
import requests
from PIL import _imaging
from PIL import Image

import API

# Get the current and add new dir named "images"
current_dir = os.getcwd() + "/images"
users = {'Moshe': '12345',
         'Matanya': '678910',
         'm': '1'}
# a dict which keep the usernames with the connections
connection_dict = dict()
# A dict which save all the user who logged in successfully
# remove them automatically in 2 hours
logged_in = dict()


class ConnectedClient:
    def __init__(self, name):
        self.name = name
        self._queue = []

    def set_packet(self, packet):
        self._queue.append(packet)

    def get_packet(self) -> tuple:
        # Block until there is a packet
        while len(self._queue) == 0:
            time.sleep(0.01)
        return self._queue.pop(0)


class Server:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.clients = {}
        self.lock = threading.Lock()
        self.syn_packets = []

    def get_syn_packet(self) -> tuple:
        # Block until there is a packet
        while len(self.syn_packets) == 0:
            pass
        return self.syn_packets.pop(0)

    def register_client(self, client):
        with self.lock:
            self.clients[client.name] = client

    def unregister_client(self, client_name):
        with self.lock:
            del self.clients[client_name]

    def send_packet(self, data, addr):
        with self.lock:
            # SYN
            if API.RUDPHeader.unpack(data).flags == 0b10000000:
                self.syn_packets.append((data, addr))
            elif addr in self.clients:
                client = self.clients[addr]
                client.set_packet((data, addr))
            else:
                self.syn_packets.append((data, addr))

    def start(self):
        self.sock.bind((self.ip, self.port))
        while True:
            data, addr = self.sock.recvfrom(API.BUFFER_SIZE)
            self.send_packet(data, addr)

    def run(self):
        thread = threading.Thread(target=self.start)
        thread.start()

    def reset(self):
        pass


def generate_random_pictures(num_pictures: int, output_dir: str, prompt: str) -> tuple[list, list, list]:
    # Create the output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    else:
        pass
        # If it does exist remove all files in the directory
        for filename in os.listdir(output_dir):
            if filename != 'heavyFile.jpg':
                file_path = os.path.join(output_dir, filename)
                os.remove(file_path)

    # Define a list to hold the file names and sizes and last change
    file_info = []

    # Define the Unsplash API endpoint and parameters
    unsplash_endpoint = "https://api.unsplash.com/photos/random"
    unsplash_params = {
        "query": prompt,
        "count": num_pictures,
        "orientation": "squarish",
        "client_id": "p7UF-MZvOyRBf79unfjIAc4fZetOcypQ8T6M2razM5Q"
    }

    # Send a request to the Unsplash API and retrieve the image URLs
    response = requests.get(unsplash_endpoint, params=unsplash_params)
    images = response.json()

    # Generate the random pictures
    for i, image in enumerate(images):
        # Download the image and open it with Pillow
        img_data = requests.get(image["urls"]["regular"]).content
        img = Image.open(BytesIO(img_data))

        # Generate a random file name and save the image
        description = str(images[i]['description']).replace("\n", '').replace('.', '').replace('/', '').\
            replace("\r", '').replace("|", '')
        description = description[:min(len(description), 20)]
        if description != 'None' and not None:
            filename = f"{description}.jpg"
        else:
            filename = f"Pic_Num_{i + 1}.jpg"

        filepath = os.path.join(output_dir, filename)
        img.save(filepath)

        # Append the file name, size and date to the file info list
        created = images[i]['created_at']
        if created is None:
            created = ""
        file_info.append((filename, os.path.getsize(filepath), created))
    file_info.append(("heavyFile.jpg", os.path.getsize(os.path.join(output_dir, "heavyFile.jpg")), "an heavy file"))

    # sort by filename
    sorted_by_filename = sorted(file_info, key=lambda x: x[0])

    # sort by file size
    sorted_by_file_size = sorted(file_info, key=lambda x: x[1])

    # sort by creation date
    sorted_by_creation_date = sorted(file_info, key=lambda x: x[2])

    # Return the file info list
    return sorted_by_filename, sorted_by_file_size, sorted_by_creation_date


# Define the server welcome message
WELCOME_MSG = "220 Welcome to the FTP server.\r\n"


def remove_with_timeout(dic, name, timeout):
    time.sleep(timeout * 60)
    if name in dic:
        del dic[name]
        print("timeout reached")


# Define the FTP command handler functions:

# Verify UserName
def handle_USER(sock, user_name: str, data_conn):
    if user_name in users:
        reply = "331 User name okay, need password.\r\n"
        connection_dict[user_name] = data_conn
        # add the dict with timeout of 10 min
        timeout_thread = threading.Thread(target=remove_with_timeout, args=(connection_dict, user_name, 10))
        timeout_thread.start()
    else:
        reply = "550 Requested action not taken.\r\n"
    sock.sendall(reply.encode())


# Verify password
def handle_PASS(sock, password: str, data_conn):
    reply = "550 Requested action not taken.\r\n"
    if data_conn in connection_dict.values():
        # Get the username associated with the connection_number
        username = ''
        for key, val in connection_dict.items():
            if val == data_conn:
                username = key
        # Check if the provided password matches the password for that username
        if users.get(username) == password:
            reply = "230 User logged in, proceed.\r\n"
            logged_in[username] = data_conn
            # keep the client in for 2 hours
            timeout_thread = threading.Thread(target=remove_with_timeout, args=(logged_in, username, 120))
            timeout_thread.start()
    sock.sendall(reply.encode())


# Sends a list of all files
def handle_LIST(sock, args: str, data_conn):
    reply = "550 Requested action not taken.\r\n"

    if data_conn in logged_in.values():
        files = lists[1]  # choose the size list os.listdir(current_dir)
        reply = f"150 Here comes the directory listing.{len(files)} files\r\n"
        sock.sendall(reply.encode())
        list_b = b''
        for f in files:
            list_b += f"{f}\r\n".encode()
        data_conn.sendall(list_b)
        reply = "226 Directory send OK.\r\n"

    sock.sendall(reply.encode())


# Sends the file
def handle_RETR(sock, filename: str, data_conn):
    reply = "550 Requested action not taken.\r\n"
    # can download only if logged in
    if data_conn in logged_in.values():
        # loop the files and find if it exists or not
        for name in lists[1]:
            if filename == name[0]:
                try:
                    with open(f"{current_dir}/{filename}", "rb") as f:
                        reply = "150 Opening data connection.\r\n"
                        sock.sendall(reply.encode())
                        data = f.read()
                        if not data:
                            raise ValueError("could not read the file")
                        data_conn.sendall(data)
                        # chunks += API.BUFFER_SIZE
                        reply = "226 Transfer complete.\r\n"
                except FileNotFoundError as e:
                    print(e)
                    reply = "550 Requested action not taken.\r\n"
                break
    sock.sendall(reply.encode())


def handle_QUIT(sock, filename: str, data_conn):
    for k, v in logged_in.items():
        if v == data_conn:
            del logged_in[k]
            break
    reply = "221 Connection closed. Goodbye.\r\n"
    sock.sendall(reply.encode())


# FTP command handler lookup table
HANDLERS = {
    "USER": handle_USER,
    "PASS": handle_PASS,
    "LIST": handle_LIST,
    "RETR": handle_RETR,
    "QUIT": handle_QUIT
}


def connection_establish(main_conn, client_address: tuple[str, int], data_conn) -> None:
    client_addr = f"{client_address[0]}:{client_address[1]}"
    print(f"New client connected: {client_addr}")
    main_conn.sendall(WELCOME_MSG.encode())
    # with tcp_conn:
    print(f"Connection established with {client_addr}")
    while True:
        data = main_conn.recv(API.BUFFER_SIZE)
        if isinstance(main_conn, API.RUDPConnection):
            data = data[API.RUDPHeader.unpack(data).header_length:]
        ack = API.RUDPHeader.initiate_ack_header(sequence_number=0, ack_number=1)
        if isinstance(main_conn, API.RUDPConnection):
            main_conn.sock.sendto(ack.pack(), (main_conn.dest_IP, main_conn.dest_port))
        if not data:
            break
        # try:
        print(f"Got data of length {len(data)} bytes")
        cmd = data.decode().strip()
        print(f"Received command: {cmd}")
        cmd_parts = cmd.split()
        if len(cmd_parts) > 0:
            # try:
            cmd_name = cmd_parts[0].upper()
            cmd_args = " ".join(cmd_parts[1:])
            handler = HANDLERS.get(cmd_name)
            if handler:
                handler(main_conn, cmd_args, data_conn)
                if cmd_name == 'QUIT':
                    return
            else:
                reply = "502 Command not implemented.\r\n"
                main_conn.sendall(reply.encode())
                # Close the client connection
                print(f"Closing client connection: {client_addr}")
                main_conn.close()

            # except Exception as e:
            #     print(f"Unexpected server error: {e}")


def tcp_listener():
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_socket.bind(('localhost', API.FTP_PORT))
    tcp_socket.listen(5)
    # Create a TCP socket for the data connection and bind it to port 20
    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    data_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    data_sock.bind(("localhost", API.FTP20_PORT))
    data_sock.listen(5)

    threads = []
    while True:
        try:
            conn, addr = tcp_socket.accept()
            new_conn, new_addr = data_sock.accept()
            if addr[0] == new_addr[0]:
                thread = threading.Thread(target=connection_establish, args=(conn, addr, new_conn))
                thread.start()
                threads.append(thread)
        except KeyboardInterrupt:
            print("Shutting down...")
            break

    for thread in threads:
        thread.join()


def rudp_listener():
    rudp_socket = Server('localhost', API.FTP_PORT)
    rudp_socket.run()
    data_socket = Server('localhost', API.FTP20_PORT)
    data_socket.run()

    threads = []
    while True:
        try:
            rudp_conn, addr = API.RUDPConnection.accept(rudp_socket)
            data_conn, new_addr = API.RUDPConnection.accept(data_socket)
            if addr[0] == new_addr[0]:
                thread = threading.Thread(target=connection_establish, args=(rudp_conn, addr, data_conn))
                thread.start()
                threads.append(thread)
        except KeyboardInterrupt:
            print("Shutting down...")
            break

    for thread in threads:
        thread.join()


if __name__ == '__main__':
    arg_parser = argparse.ArgumentParser(description="The FTP server.")

    arg_parser.add_argument("-p", "--prompt", type=str,
                            default="animals", help="The prompt to download the photos")
    arg_parser.add_argument("-n", "--num", type=int,
                            default=3, help="Number of images")
    args = arg_parser.parse_args()
    prompt = args.prompt
    n = args.num
    # Generate n random pictures
    lists = generate_random_pictures(num_pictures=n, output_dir=current_dir, prompt=prompt)
    for lis in lists:
        print("\nNew List:")
        for x in lis:
            print(f"name: {x[0]}\t\t\tSize: {x[1]}\t\t\tDate: {x[2]}")

    tcp_thread = threading.Thread(target=tcp_listener)
    udp_thread = threading.Thread(target=rudp_listener)

    # start both threads
    tcp_thread.start()
    udp_thread.start()
