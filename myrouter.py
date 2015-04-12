#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''
import collections
import ipaddress
import datetime
import inspect
import copy

# from typing import Dict, List, Sequence, Any
# i am commenting this out, because you probably don't have mypy installed

import switchyard.lib.packet as packet
import switchyard.lib.common as common


def in_in(dictionary, item):
    '''
    checks if the `item` provided is `in` any of the keys of the dictionary.

    helpful if you have a dictionary with keys of networks and you want
    to see if an address is in any of them
    '''
    for key in dictionary:
        if item in key:
            return True
    return False


def get_in(dictionary, item):
    '''
    Return the first value in the dictionary that `item` is `in`.
    '''
    for (key, value) in dictionary.items():
        if item in key:
            return value
    raise KeyError()


def sort_network_dict(dictionary):
    '''
    sorts the dictionary so that the most specific network will comes first
    '''
    return collections.OrderedDict(sorted(
        dictionary.items(),
        key=lambda item: item[0].num_addresses
    ))


class DebugBase(object):

    '''
    Logs whenever a method is called on a class
    '''

    def __getattribute__(self, name):
        returned = object.__getattribute__(self, name)
        if inspect.isfunction(returned) or inspect.ismethod(returned):
            common.log_debug('called ' + returned.__name__)
        return returned


class ARPRequestInfo(object):

    def __init__(self, request_number: int, sent_time: datetime.datetime):
        self.request_number = request_number
        self.sent_time = sent_time

    def __repr__(self):
        return 'request_number: {} sent_time: {}'.format(self.request_number, self.sent_time)


class Router(DebugBase):
    TABLE_FILE = 'forwarding_table.txt'
    ARP_REQUEST_MAX_TRIES = 5
    ARP_REQUEST_TIMEOOUT = datetime.timedelta(seconds=1)

    # list of addresses that are internal (IPs of interfaces)
    internal_address = []  # type: List[ipaddress.IPv4Address]

    # ARP table for entries on this router, to reply to ARP requests
    internal_network_to_mac = {}  # type: Dict[ipaddress.IPv4Network, str]

    # ARP table for addresses not on this router. used to find the mac
    # address for the next_hop
    network_to_mac = {}  # type: Dict[ipaddress.IPv4Network, str]

    # IP table mapping network to next ip address hop
    network_to_next_hop = {}  # type: Dict[ipaddress.IPv4Network, ipaddress.IPv4Address]

    # map each destination network to the interface it is reachable by
    network_to_interface = {}  # type: Dict[ipaddress.IPv4Network, common.Interface]

    # maps IP address -> FIFO (appened on the left) queue of packets to be sent
    waiting_on_arp = collections.defaultdict(collections.deque)  # type: Dict[ipaddress.IPv4Address, Sequence[packet.Packet]]

    # maps IP -> ARPRequestInfo. for every ARP request sent, that hasn't
    # been awknowledged yet, one mapping occures. If a request either succeeds
    # or is retried too many times it is dropped from this dict
    current_arp_requests = {}  # type: Dict[ipaddress.IPv4Address, ARPRequestInfo]

    def __init__(self, net):
        self.net = net

        # add all internal IP -> mac pairs
        for interface in self.net.interfaces():
            network = ipaddress.IPv4Network('{0.ipaddr}/{0.netmask}'.format(interface), strict=False)
            self.internal_network_to_mac[network] = interface.ethaddr
            self.internal_address.append(interface.ipaddr)
            self.network_to_interface[network] = interface
        # add mapping of network -> next hop as well as next_hop -> interface
        for line in open(self.TABLE_FILE).readlines():
            address, mask, next_hop, interface = line.split()
            network = ipaddress.IPv4Network('{}/{}'.format(address, mask))
            self.network_to_next_hop[network] = ipaddress.IPv4Address(next_hop)
            self.network_to_interface[network] = self.net.interface_by_name(interface)

        # sort the network_to_next_hop so that it is ordered with the
        # most specific networks first
        self.network_to_next_hop = sort_network_dict(self.network_to_next_hop)
        self.network_to_interface = sort_network_dict(self.network_to_interface)

    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            # lets iterate through all our current arp requests and see if
            # any have timed out
            for (ip, arp_request_info) in copy.copy(self.current_arp_requests).items():
                timeout_time = arp_request_info.sent_time + self.ARP_REQUEST_TIMEOOUT
                if timeout_time < datetime.datetime.now():
                    # if we have sent the max number already, then remove
                    # from list so we stop trying to send and drop
                    # all packets which we were waiting on
                    if arp_request_info.request_number >= self.ARP_REQUEST_MAX_TRIES:
                        del self.current_arp_requests[ip]
                        del self.waiting_on_arp[ip]
                    else:
                        # otherwise we can try to send it again
                        arp_request_info.request_number += 1
                        common.log_debug('sending ARP request: try #{}'.format(
                            arp_request_info.request_number
                        ))
                        self.send_arp_request(ip)

            try:
                dev, pkt = self.net.recv_packet(timeout=1.0)
            except common.NoPackets:
                continue
            except common.Shutdown:
                return
            common.log_debug('recieved packet: {}'.format(pkt))
            if pkt.has_header(packet.Arp):
                if pkt.get_header(packet.Arp).operation == packet.ArpOperation.Request:
                    self.send_arp_reply(dev, pkt)
                else:
                    self.process_arp_reply(pkt)
            elif pkt.has_header(packet.IPv4):
                self.process_ipv4(pkt)
            else:
                common.log_debug('got a packet, but didnt know how to process it: {}'.format(pkt))

    def send_arp_reply(self, dev: str, pkt: packet.Packet):
        arp = pkt.get_header(packet.Arp)
        if in_in(self.internal_network_to_mac, arp.targetprotoaddr):
            reply = packet.create_ip_arp_reply(
                srchw=get_in(self.internal_network_to_mac, arp.targetprotoaddr).raw,
                srcip=arp.targetprotoaddr,
                dsthw=arp.senderhwaddr,
                targetip=arp.senderprotoaddr,

            )
            self.net.send_packet(dev, reply)

    def send_arp_request(self, ip: ipaddress.IPv4Address):
        sending_interface = get_in(self.network_to_interface, ip)
        request = packet.create_ip_arp_request(
            srchw=sending_interface.ethaddr,
            srcip=sending_interface.ipaddr,
            targetip=ip,
        )
        self.net.send_packet(sending_interface.name, request)

    def process_arp_reply(self, pkt: packet.Packet):
        arp = pkt.get_header(packet.Arp)
        ip = arp.senderprotoaddr
        mac = arp.senderhwaddr
        self.network_to_mac[ipaddress.IPv4Network(ip)] = mac
        self.current_arp_requests.pop(ipaddress.IPv4Address(ip), None)
        for pkt in self.waiting_on_arp[ip]:
            self.forward_ipv4_packet(pkt, ip)
        self.waiting_on_arp.pop(ip, None)

    def process_ipv4(self, pkt: packet.Packet):
        ip = pkt.get_header(packet.IPv4)

        # if dest in internal network, then drop packet
        if ip.dstip in self.internal_address:
            return
        # if right next to router, can send w/ out next hop
        if in_in(self.internal_network_to_mac, ip.dstip):
            self.try_forwarding_ipv4(pkt, ip.dstip)
            return
        # ok so we have determined we need to get one hope away to reach
        # it, if we have don't have that next hope we can drop
        if not in_in(self.network_to_next_hop, ip.dstip):
            return
        self.try_forwarding_ipv4(pkt, get_in(self.network_to_next_hop, ip.dstip))

    def try_forwarding_ipv4(self, pkt: packet.Packet, next_hop: ipaddress.IPv4Address):
        '''
        will forward an ip packet, but first makes sure we know the mac address
        of the destination. if we don't, then we can add it to queue
        and process it later
        '''
        # if we know the mac of the destination ip, we can go ahead and send the
        # packet
        if in_in(self.network_to_mac, next_hop):
            self.forward_ipv4_packet(pkt, next_hop)
            return
        # if we arent already looking for this arp, add it to the queue
        if next_hop not in self.current_arp_requests:
            self.send_arp_request(next_hop)
            self.current_arp_requests[next_hop] = ARPRequestInfo(
                1,
                datetime.datetime.now()
            )
        self.waiting_on_arp[next_hop].appendleft(pkt)

    def forward_ipv4_packet(self, pkt: packet.Packet, next_hop: ipaddress.IPv4Address):
        ip = pkt.get_header(packet.IPv4)

        ip.ttl -= 1

        ethernet = pkt.get_header(packet.Ethernet)
        next_hop_mac = get_in(self.network_to_mac, next_hop)
        output_interface = get_in(self.network_to_interface, next_hop)

        ethernet.src = output_interface.ethaddr
        ethernet.dst = next_hop_mac

        self.net.send_packet(output_interface.name, pkt)


def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
