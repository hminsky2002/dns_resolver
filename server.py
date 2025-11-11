import selectors
import socket
from dataclasses import dataclass
from time import time
import logging
import argparse
from dns_utils import *
import threading 

cache = dict[tuple[str, int, int],dnsRecordCache]()

cachelock = threading.Lock()

receive_default_size = 4096

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log', encoding='utf-8'),
        logging.StreamHandler()  
    ])

sel = selectors.DefaultSelector()

def resolve(sock, domain_name, record_type, client_query_id):
    logger.info(f"resolve() called with domain_name={repr(domain_name)}")
    nameserver = "198.41.0.4"
    while True:
        query = build_query(domain_name, record_type, client_query_id)

        sock.sendto(query, (nameserver, 53))

        response, addr = sock.recvfrom(receive_default_size)

        decoded_response = parse_dns_packet(response)

        if ip := get_answer(decoded_response):
            return response

        elif nsIP := get_nameserver_ip(decoded_response):
            nameserver = nsIP

        elif ns_domain := get_nameserver(decoded_response):
            logger.info(f"Resolving NS domain: {repr(ns_domain)}")

            ns_response = resolve(sock, ns_domain, 1, None)

            ns_packet = parse_dns_packet(ns_response)
            if ns_packet.answers and ns_packet.answers[0].type_ == 1:
                nameserver = ns_packet.answers[0].data 
                logger.info(f"Resolved {ns_domain} to {nameserver}")
            else:
                raise Exception(f"Failed to resolve NS domain {ns_domain}")

        else:
            raise Exception("oopsy daisy")

def handle_client(data: bytes, addr, server_sock: socket.socket, thread_sock: socket.socket):
    try:
        query = parse_dns_packet(data)
    except Exception as e:
        logger.error(f"Failed to parse query from {addr}: {e}")
        thread_sock.close()
        return

    if not query.questions:
        logger.error(f"No questions in query from {addr}")
        thread_sock.close()
        return

    domain_name = query.questions[0].name.decode('utf-8').rstrip('\x00')
    record_type = query.questions[0].type_
    class_val = query.questions[0].class_

    key = (domain_name, record_type, class_val)

    cachelock.acquire()
    if key in cache:
        if cache[key].cached_at + cache[key].ttl > time():
            logger.info(f"Cache hit for {domain_name} (type={record_type}, class={class_val})")
            cached_response = cache[key].response_bytes
            cachelock.release()

            server_sock.sendto(cached_response, addr)
            thread_sock.close()
            return
        else:
            logger.info(f"Cache expired for {domain_name}")
            del cache[key]

    cachelock.release()

    logger.info(f"Cache miss for {domain_name} (type={record_type}, class={class_val}), resolving...")

    try:
        resolved_answer = resolve(thread_sock, domain_name, record_type, query.header.id)
    except Exception as e:
        logger.error(f"Failed to resolve {domain_name}: {e}")
        thread_sock.close()
        return

    parsed_response = parse_dns_packet(resolved_answer)

    cachelock.acquire()

    min_ttl = float('inf')

    for i in parsed_response.answers:
        if i.ttl < min_ttl:
            min_ttl = i.ttl

    if parsed_response.answers and min_ttl != float('inf'):
        cache[key] = dnsRecordCache(resolved_answer, int(time()), int(min_ttl))
        logger.info(f"Cached {domain_name} with TTL={int(min_ttl)}s")
    else:
        logger.info(f"Not caching {domain_name} (no answers or invalid TTL)")

    cachelock.release()

    server_sock.sendto(resolved_answer, addr)
    thread_sock.close()
    
    
    
def main():
    parser = argparse.ArgumentParser(description='DNS Server')
    parser.add_argument('port', type=int, nargs='?', default=53, help='Port number to listen on (default: 5353)')

    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('localhost', args.port))

    logger.info(f'DNS server started on localhost:{args.port}')
    print(f'DNS server listening on localhost:{args.port}')

    while True:
        data, addr = sock.recvfrom(receive_default_size)
        thread_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        thread = threading.Thread(target=handle_client, args=(data, addr, sock, thread_sock))
        thread.start()


if __name__ == '__main__':
    main()