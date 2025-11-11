import selectors
import socket
from dataclasses import dataclass
from time import time
import logging
import argparse
from dns_utils import *

receive_default_size = 4096

logger = logging.getLogger(__name__)
logging.basicConfig(filename='server.log', encoding='utf-8', level=logging.DEBUG)

sel = selectors.DefaultSelector()

def receive(conn: socket.socket, mask, callback_args):
    data = conn.recv(receive_default_size)
    
    print(parse_dns_packet(data))
    
    
    sel.unregister(conn)
    conn.close()

    
    
    
def main():
    parser = argparse.ArgumentParser(description='DNS Server')
    parser.add_argument('port', type=int, nargs='?', default=53, help='Port number to listen on (default: 5353)')

    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', args.port))
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ, (receive, None))

    logger.info(f'DNS server started on localhost:{args.port}')
    print(f'DNS server listening on localhost:{args.port}')

    while True:
        events = sel.select()
        for key, mask in events:
            callback = key.data[0]
            callback_args = key.data[1]
            callback(key.fileobj, mask, callback_args)

if __name__ == '__main__':
    main()