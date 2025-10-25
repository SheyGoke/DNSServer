import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rdtypes
import dns.rdtypes.ANY
from dns.rdtypes.ANY.MX import MX
from dns.rdtypes.ANY.SOA import SOA
import dns.rdata
import dns.rrset
import socket
import threading
import signal
import os
import sys

import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import ast

def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    key = kdf.derive(password.encode('utf-8'))
    key = base64.urlsafe_b64encode(key)
    return key

def encrypt_with_aes(input_string, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    encrypted_data = f.encrypt(input_string.encode('utf-8'))
    return encrypted_data

def decrypt_with_aes(encrypted_data, password, salt):
    key = generate_aes_key(password, salt)
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data.decode('utf-8')

def decrypt_with_aes_b64(encrypted_data_b64, password, salt):
    encrypted_data = base64.urlsafe_b64decode(encrypted_data_b64.encode('utf-8'))
    return decrypt_with_aes(encrypted_data, password, salt)

salt = b'some_salt_value'
password = 'mysecretpassword'
input_string = 'Hello, DNS!'

encrypted_value = encrypt_with_aes(input_string, password, salt)
encrypted_value_b64 = base64.urlsafe_b64encode(encrypted_value).decode('utf-8')
decrypted_value = decrypt_with_aes_b64(encrypted_value_b64, password, salt)

def generate_sha256_hash(input_string):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_string.encode('utf-8'))
    return sha256_hash.hexdigest()

# DNS records: use tuples for AAAA, NS, TXT; list of tuples for MX
dns_records = {
    'example.com.': {
        dns.rdatatype.A: '192.168.1.101',
        dns.rdatatype.AAAA: ('2001:0db8:85a3:0000:0000:8a2e:0370:7334',),
        dns.rdatatype.MX: [(10, 'mail.example.com.')],
        dns.rdatatype.CNAME: 'www.example.com.',
        dns.rdatatype.NS: ('ns.example.com.',),
        dns.rdatatype.TXT: ('This is a TXT record',),
        dns.rdatatype.SOA: (
            'ns1.example.com.',
            'admin.example.com.',
            2023081401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
    'nyu.edu.': {
        dns.rdatatype.A: '128.122.138.1',
        dns.rdatatype.AAAA: ('2607:f470:8:1000::1',),
        dns.rdatatype.MX: [(10, 'mx.nyu.edu.')],
        dns.rdatatype.NS: ('ns.nyu.edu.',),
        dns.rdatatype.TXT: (encrypted_value_b64,),  # exfiltrated value as base64 string
        dns.rdatatype.SOA: (
            'ns.nyu.edu.',
            'hostmaster.nyu.edu.',
            2023102401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
    'safebank.com.': {
        dns.rdatatype.A: '10.10.10.10',
        dns.rdatatype.NS: ('ns.safebank.com.',),
        dns.rdatatype.MX: [(10, 'mail.safebank.com.')],
        dns.rdatatype.TXT: ('SafeBank TXT record',),
        dns.rdatatype.SOA: (
            'ns.safebank.com.',
            'admin.safebank.com.',
            2023102401,
            3600,
            1800,
            604800,
            86400,
        ),
    },
    # Add more records as needed
}

def run_dns_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(('127.0.0.1', 53))

    while True:
        try:
            data, addr = server_socket.recvfrom(1024)
            request = dns.message.from_wire(data)
            response = dns.message.make_response(request)

            question = request.question[0]
            qname = question.name.to_text()
            qtype = question.rdtype

            if qname in dns_records and qtype in dns_records[qname]:
                answer_data = dns_records[qname][qtype]
                rdata_list = []

                if qtype == dns.rdatatype.MX:
                    for pref, server in answer_data:
                        rdata_list.append(MX(dns.rdataclass.IN, dns.rdatatype.MX, pref, server))
                elif qtype == dns.rdatatype.SOA:
                    mname, rname, serial, refresh, retry, expire, minimum = answer_data
                    rdata = SOA(dns.rdataclass.IN, dns.rdatatype.SOA, mname, rname, serial, refresh, retry, expire, minimum)
                    rdata_list.append(rdata)
                else:
                    # Always treat as tuple for AAAA, NS, TXT
                    if isinstance(answer_data, str):
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, answer_data)]
                    else:
                        rdata_list = [dns.rdata.from_text(dns.rdataclass.IN, qtype, data) for data in answer_data]
                for rdata in rdata_list:
                    rrset = dns.rrset.RRset(question.name, dns.rdataclass.IN, qtype)
                    rrset.add(rdata)
                    response.answer.append(rrset)

            response.flags |= 1 << 10

            print("Responding to request:", qname)
            server_socket.sendto(response.to_wire(), addr)
        except KeyboardInterrupt:
            print('\nExiting...')
            server_socket.close()
            sys.exit(0)

def run_dns_server_user():
    print("Input 'q' and hit 'enter' to quit")
    print("DNS server is running...")

    def user_input():
        while True:
            cmd = input()
            if cmd.lower() == 'q':
                print('Quitting...')
                os.kill(os.getpid(), signal.SIGINT)

    input_thread = threading.Thread(target=user_input)
    input_thread.daemon = True
    input_thread.start()
    run_dns_server()

if __name__ == '__main__':
    run_dns_server_user()
    #print("Encrypted Value:", encrypted_value_b64)
    #print("Decrypted Value:", decrypted_value)