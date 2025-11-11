import socket
from dns_classes import *
from dns_utils import *
from io import BytesIO

reader = BytesIO()
query = build_dns_query("www.example.com", 1)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.sendto(query, ("localhost", 53))

response, _ = sock.recvfrom(1024)
parsed_query = parse_dns_packet(response)
