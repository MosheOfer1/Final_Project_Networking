# Final_Project_Networking
Please have a look at the [attached PDF](https://github.com/MosheOfer1/Final_Project_Networking/blob/main/final_project.pdf)
## System Characterization
### System Overview

This project's goal is to demonstrate how a client connects to several servers and carries out
different activities. It demonstrates how a client connects to an application server via RUDP
or TCP, acquires an IP address from a DHCP server, then asks the DNS for the FTP server
IP, and uses an FTP server to read and download files by entering a username and
password.

The architecture of the script is created to step-by-step demonstrate these procedures,
giving a clear knowledge of each phase of the client-server interaction. The client first
requests an IP address from a DHCP server, then gets the IP by creating a DNS request,
after which it connects to the application server and then the FTP server.

## How To Run the Code

To run this code on Linux, open a terminal, navigate to the directory where the file is located,
and run the following command:

```$ python dhcp_server.py```

```$ python DNS_server.py```

```$ python FTP_server.py```

This will run the 3 servers, with the default API.LO_HOST value, and 3 photos of 'animals'
for the FTP server.
Alternatively, you can specify the server IP address or hostname using the -H/--host
argument:
You can specify the prompt and the number of photos for the FTP server, as well.

```$ python dhcp_server.py -H 192.168.1.1```

```$ python DNS_server.py -H 192.168.1.2```

```$ python FTP_server.py -p dogs -n 10```

This will run the script with DHCP_server_IP set to 192.168.1.1 and DNS_server_ip set to
192.168.1.2
For the FTP server, it will download from "unsplash.com" API 10 random photos of dogs.
Finally run the client.py script which communicate with all 3 servers.

```$ python client.py -[protocol]```

In the protocol option you can choose between 'tcp' and 'rudp'.

```$ python client.py -p rudp```



## Components and Subsystems
## DHCP_server
Software application that sends DHCP discover, offer, and request messages to obtain an IP
address.
### Properties:
To prevent two clients from receiving the same IP, the server keeps a list of available and
offered IPs. 
When a client sends it a DHCP discovery packet, it listens for it and sends back
DHCP offer packets in which the client can find an IP address to use. 
The server sends a
DHCP acknowledgement packet to the client to confirm the lease of the IP address after the
client accepts the given IP address by sending a DHCP request packet to the server.
With a 24-hour lease time, the server dynamically assigns IP addresses from a pool of
accessible IPs (86400 seconds). The server does not provide a fresh IP address if a client
requests the same IP address more than once; instead, it delivers an acknowledgement
packet. With the acknowledgement packet, the server also transmits the client the gateway,
subnet mask, DNS server IP, and lease time options. In addition, each client must resend a
request each half time of the lease time. So, the server has running thread which keep
logged in clients by sending them acknowledge for each request. If the timeout occur the IP
is return to the available IPs list and might be assigned to different device.
A timeout thread is defined in the script to remove the IP address from the list of available
IPs after two seconds, and a Client Info class is defined to hold the transaction ID, MAC
address, and assigned IP address of the client.


## DNS_server
Software application that sends DNS responses and receives DNS queries.
### Properties:
The DNS gets a request from the client and check, the domain name is extracted from the
request and checked to see if it is in the list of recognized domains, (in our case there is just
"app.co.il", the app server).
If so, it generates a DNS response packet with the domain's IP address and forwards it back
to the client. It adds the client to a list of pending clients.
If the domain is not known, it adds the client to a list of pending clients and forwards the
request to Google's DNS server. This script offers a simple implementation of a DNS server
that can resolve IP addresses for domain names. Nevertheless, it is not a fully functional
DNS server solution. 


## FTP_Server
Software application that connects to an FTP server and downloads files.
### Properties:
First the server downloads from "unsplash.com" free images API, couple of images into a
new directory named 'images'. Then the server listens on TCP and UDP simultaneously on
port 21 for incoming client connections and then accepts data connections on port 20 for file
transfers.
The server implements several FTP commands, such as USER, PASS, LIST, RETR, and
QUIT, using handlers in the HANDLERS lookup table. The connection_establish function is
the main function that handles the communication with the client.
The remove_with_timeout function is a helper function used for removing a dictionary item
after a specified timeout period. It is used in the handle_USER and handle_PASS functions
to keep track of the data connection associated with a user after successful authentication.
Similarly, the handle_QUIT function removes the data connection associated with a user
after the user has disconnected.


## Our RUDP Protocol

### SYN: 
Set for initialize a new connection. The header will include relevant data Like the
threshold.
### ACK: 
Set for acknowledge. The Ack Number indicates the next expected packet to be send.
### EAK: 
Set for EACK message which includes the lost packets.
### Checksum: 
Error Correction Technique. For Reliable transportation.
### Options: 
Extend the header with more data.
SYN uses for adding connection information.
EACK uses for adding lost packets.
The Algorithm for sending the data:
1. Receive the data from the sender.
2. Divide the data into packets of the required size, and assign each packet an header
with a sequence number.
3. Store each packet in a list and mark each packet's number in a set .
4. Send packets within the window size, removing the sent packet's number from the
set .
5. Wait for ACK or EACK to confirm the receipt of packets .
o If an ACK is received, adjust the window size according to the protocol's
rules .
o If an EACK is received, First add the lost packets into the set and resend
them, second reduce the window size by halving it.
6. Repeat steps 4-5 until the set is empty which means all packets have been
acknowledged.
11
The Algorithm for receiving the data:
TRHEAD-1 the receiver:
1. Create a priority queue q to store the received packet according to the sequence
numbers. It's done to overcome the out of order problem.
2. Receive packet using recv() and store it in data .
3. If the packet is not a duplicate and the checksum is valid, add the packet to the
priority queue q, update the size so far, and add the packet number to the shared set
SharedSet.
4. Once the size of received data is equal to or greater than expected size, exit the
loop.
5. Iterate through the priority queue q and append each packet's payload .
THREAD-2 sends Acknowledge.
1. Initialize the last_received variable to 0, which will store the sequence number of the
last received packet .
2. While the thread-1 is still running :
a. Wait for a time period equal to the window size multiplied by 0.07 (a heuristic
value used to determine the waiting time) .
b. Check the shared set to identify which packets have been lost (i.e., not
received yet).
c. Update the last_received variable to the highest sequence number that has
been received.
d. If no packets have been lost, send an acknowledgment (ACK) packet to the
sender to indicate the highest sequence number received successfully .
i. If the window size is less than the threshold, double the window size .
ii. Otherwise, increase the window size by one .
e. If packets have been lost, send an extended acknowledgment (EACK) packet
to the sender to indicate the lost packets .
i. Reduce the window size by half .
ii. If the receive thread is still running, create and send the EACK
packet to the sender .
iii. If the receive thread has completed, send an ACK packet to the
sender instead.
3. Return the received data to the caller.
The receiver also sends ACKs to the sender in response to the received packets. The
receiver maintains a sliding window of received packets using the SharedSet. The receiver
12
periodically sends ACKs to the sender based on the sliding window's status. If there are no
lost packets, the receiver sends a regular ACK to the sender with the last received packet's
sequence number plus one. If there are lost packets, the receiver sends an extended ACK
(EACK) with the list of lost packet numbers.
