"""
Exercise 6.12 - NSLOOKUP
Author: Noam Cohen
"""


from scapy.all import *
import scapy.layers.inet
import sys
from scapy.layers.dns import DNS, DNSQR, DNSRR


ADDRESS_INDEX = 1
TYPE_INDEX = 2
# IP of DNS server:
DST_IP = '8.8.8.8'
# Source port:
SRC_PORT = 24603
# DNS port:
DST_PORT = 53
# Amount of queries:
QUERIES = 1


def reverse(ip_of_query):
    """
    Reverse the IP.
    """
    break_ip = ip_of_query.split('.')
    return '.'.join(break_ip[:: -1])


def create_mapping(address):
    """
    This function create a new mapping packet, in the 'scapy' folder.
    """
    # Create a new packet:
    dns_packet = scapy.layers.inet.IP(dst=DST_IP) / scapy.layers.inet.UDP(sport=SRC_PORT, dport=DST_PORT) / DNS(qdcount=QUERIES) / DNSQR(qname=address)

    # And return it:
    return dns_packet


def create_reverse(ip_of_query, type_of_query):
    """
    This function create a new *reverse mapping* packet, in the 'scapy' folder.
    """
    # Reverse the IP:
    ip = reverse(ip_of_query) + ".in-addr.arpa"

    # Create a new packet:
    dns_packet = \
        scapy.layers.inet.IP(dst=DST_IP) / scapy.layers.inet.UDP(sport=SRC_PORT, dport=DST_PORT) \
        / DNS(qdcount=QUERIES) / DNSQR(qname=ip, qtype=type_of_query)

    # And return it:
    return dns_packet


def print_response(dns_packet, address):
    """
    Print the response (or responses) of the query
    """
    # The response of the DNS server:
    global data
    response = sr1(dns_packet)

    # Amount of answers:
    num_ans = response[DNS].ancount

    # Check if the address is not valid:
    try:
        # Data of the response:
        data = response[DNSRR]

    except Exception:
        print("*** dns.israelinternet.co.il can't find " + address + ": Non-existent domain")

    # Print all the answers:
    for i in range(num_ans):
        # If the type of the data is 'bytes':
        if type(data[i].rdata) == bytes:
            # Then convert it to a string and print it (print it without 'b' in the beginning)
            print(data[i].rdata.decode())

        # Else, if the type of the data is 'str':
        else:
            print(data[i].rdata)


def main():
    # If the user did not enter an address:
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        # Then print:
        print("There is no address to send.\n")

    # Else, if the user was enter an address (maybe also the type):
    else:
        address = sys.argv[ADDRESS_INDEX]
        # If the user was enter just an address
        if len(sys.argv) == 2:
            # Then create a new mapping packet:
            dns_packet = create_mapping(address)
            # Print all the answers:
            print_response(dns_packet, address)

        # Else, if the user was enter an address *and* a type (A or PTR):
        elif len(sys.argv) == 3:
            # If the type is A:
            if sys.argv[TYPE_INDEX] == 'type=A':
                # Then create a new mapping packet:
                dns_packet = create_mapping(address)
                # Print all the answers:
                print_response(dns_packet, address)

            # Else, if the type is PTR:
            elif sys.argv[TYPE_INDEX] == 'type=PTR':
                # Then create a new reverse packet:
                dns_packet = create_reverse(address, 'PTR')
                # Print all the answers:
                print_response(dns_packet, address)

            # Else, if the type that the user was enter is not A and is not PTR:
            else:
                # Then print:
                print("The type of the query is not valid.")


if __name__ == "__main__":
    main()
