from dns_classes import *
import dataclasses
import struct
import random
from io import BytesIO
import socket



ROOT_ADDR = "199.7.91.13" #UMD server, go terrapins

random.seed(1)

def ip_to_string(ip):
    return ".".join([str(x) for x in ip])

def dns_type_to_string(dns_type: int):
    match dns_type:
        case 1:
            return 'A'
        case 2:
            return 'NS'
        case 5:
            return 'CNAME'
        case 6:
            return 'SOA'
        case 11:
            return 'WKS'
        case 12:
            return 'PTR'
        case 13:
            return 'HINFO'
        case 14:
            return 'MINFO'
        case 15:
            return 'MX'
        case 16:
            return 'TXT'
        case _:
            return 'unknown'
        

def dns_class_to_string(dns_class: int) -> str:
    match dns_class:
        case 1:
            return 'IN'
        case 3:
            return 'CH'
        case 4:
            # i doubt we're getting hesiod records but hey
            return 'HS'
        case _:
            return 'unknown'
            

def header_to_bytes(header: DNSHeader):
    fields = dataclasses.astuple(header)
    return struct.pack("!HHHHHH", *fields)

def question_to_bytes(question: DNSQuestion):
    return question.name + struct.pack("!HH", question.type_, question.class_)

def encode_dns_name(domain_name):
    encoded = b""
    for part in domain_name.encode("ascii").split(b"."):
        encoded += bytes([len(part)]) + part
    return encoded + b"\x00"


def build_dns_query(domain_name, record_type):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    RECURSION_DESIRED = 1 << 8
    header = DNSHeader(id=id, num_questions=1, flags=RECURSION_DESIRED)
    question = DNSQuestion(name=name, type_=record_type, class_=1)
    return header_to_bytes(header) + question_to_bytes(question)


def parse_header(reader):
    items = struct.unpack("!HHHHHH", reader.read(12))
    return DNSHeader(*items)

def decode_name(reader):
    parts = []
    while (length := reader.read(1)[0]) != 0:
        if length & 0b1100_0000:
            parts.append(decode_compressed_name(length, reader))
            break
        else:
            parts.append(reader.read(length))
    return b".".join(parts)


def decode_compressed_name(length, reader):
    pointer_bytes = bytes([length & 0b0011_1111]) + reader.read(1)
    pointer = struct.unpack("!H", pointer_bytes)[0]
    current_pos = reader.tell()
    reader.seek(pointer)
    result = decode_name(reader)
    reader.seek(current_pos)
    return result

def parse_question(reader):
    name = decode_name(reader)
    data = reader.read(4)
    type_, class_ = struct.unpack("!HH", data)
    return DNSQuestion(name, type_, class_)

def parse_record(reader: BytesIO):
    name = decode_name(reader)
    data = reader.read(10)
    type_, class_, ttl, data_len = struct.unpack("!HHIH", data) 
    type = dns_type_to_string(type_)
    if type == 'NS': 
        data = decode_name(reader)
    elif type == 'A':
        data = ip_to_string(reader.read(data_len))
    else:
        data = reader.read(data_len)
    return DNSRecord(name, type_, class_, ttl, data) # type: ignore

def parse_dns_packet(data):
    reader = BytesIO(data)
    header = parse_header(reader)
    questions = [parse_question(reader) for _ in range(header.num_questions)]
    answers = [parse_record(reader) for _ in range(header.num_answers)]
    authorities = [parse_record(reader) for _ in range(header.num_authorities)]
    additionals = [parse_record(reader) for _ in range(header.num_additionals)]

    return DNSPacket(header, questions, answers, authorities, additionals)

def build_query(domain_name, record_type):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    header = DNSHeader(id=id, num_questions=1, flags=0)
    question = DNSQuestion(name=name, type_=record_type, class_=1)
    return header_to_bytes(header) + question_to_bytes(question)

def get_nameserver(packet):
    for x in packet.authorities:
        if x.type_ == 2:
            return x.data.decode('utf-8')
        
def get_nameserver_ip(packet):
    for x in packet.additionals:
        if x.type_ == 1:
            return x.data
