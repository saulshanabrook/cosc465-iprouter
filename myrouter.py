#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''
import collections
import ipaddress
import datetime
import inspect
import copy
import functools
import types

# from typing import Dict, List, Sequence, Any
# i am commenting this out, because you probably don't have mypy installed

import switchyard.lib.packet as packet
import switchyard.lib.common as common

#from debug_logging import DebugMetaClass

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
    raise KeyError("{} not in {}".format(str(item), str(dictionary)))


def sort_network_dict(dictionary):
    '''
    sorts the dictionary so that the most specific network will comes first
    '''
    return collections.OrderedDict(sorted(
        dictionary.items(),
        key=lambda item: item[0].num_addresses
    ))


def set_header(pkt, new_header):
    TRANSPORT_LAYER_INDEX = 2

    header_class = new_header.__class__

    header_index = pkt.get_header_index(header_class)
    if header_index == -1:
        # this means that the header currently doesn't exist in this class
        if isinstance(new_header, packet.ICMP) or isinstance(new_header, packet.IPv4):
            header_index = TRANSPORT_LAYER_INDEX
        else:
            raise RuntimeError(
                "Dont know where to update header {}".format(str(new_header))
            )
    pkt[header_index] = new_header


    if header_index == TRANSPORT_LAYER_INDEX:
        # if we changed the transport protocal, we should also change it on the
        # ip packet
        pkt[pkt.get_header_index(packet.IPv4)].protocol = getattr(
            packet.IPProtocol,
            header_class.__name__
        )

        # if we updated the transport layer header, we should remove all packets
        # after it
        while len(list(pkt)) > (header_index + 1):
            del pkt[len(list(pkt)) - 1]

class ARPRequestInfo(object):
    def __init__(self, request_number: int, sent_time: datetime.datetime) -> None:
        self.request_number = request_number
        self.sent_time = sent_time

    def __str__(self):
        return 'request_number: {} sent_time: {}'.format(self.request_number, self.sent_time)


# class Router(metaclass=DebugMetaClass, log_function=common.log_debug):
class Router():
    TABLE_FILE = 'forwarding_table.txt'
    ARP_REQUEST_MAX_TRIES = 5
    ARP_REQUEST_TIMEOOUT = datetime.timedelta(seconds=1)
    IP_TTL = 64 # from http://superuser.com/a/721762

    # placeholder that you can set the srcip of a IP header of a packet
    # so that when it gets sent it will be changed to the IP of the
    # interface sending it
    IP_OF_SENDING_INTERFACE = object()

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

        print('Network interfaces')
        for interface in self.net.interfaces():
            print('{0.ipaddr} {0.netmask} {0.name} {0.ethaddr}'.format(interface))

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
            self.check_arp_timeouts()
            try:
                dev, pkt = self.net.recv_packet(timeout=1.0)
            except common.NoPackets:
                continue
            except common.Shutdown:
                return
            if pkt.has_header(packet.Arp):
                if pkt.get_header(packet.Arp).operation == packet.ArpOperation.Request:
                    self.send_arp_reply(dev, pkt)
                else:
                    self.process_arp_reply(pkt)
            elif pkt.has_header(packet.IPv4):
                self.process_ipv4(pkt)
            else:
                common.log_debug('got a packet, but didnt know how to process it: {}'.format(pkt))

    def check_arp_timeouts(self):
        # lets iterate through all our current arp requests and see if
        # any have timed out
        for (ip, arp_request_info) in copy.copy(self.current_arp_requests).items():
            timeout_time = arp_request_info.sent_time + self.ARP_REQUEST_TIMEOOUT
            if timeout_time < datetime.datetime.now():
                # if we have sent the max number already, then remove
                # from list so we stop trying to send
                if arp_request_info.request_number >= self.ARP_REQUEST_MAX_TRIES:
                    while self.waiting_on_arp[ip]:
                        pkt = self.waiting_on_arp[ip].popleft()
                        self.modify_pkt(
                            pkt,
                            new_header=self.generate_icmp_error(
                                pkt,
                                icmptype=packet.ICMPType.DestinationUnreachable,
                                icmpcode_name="HostUnreachable"
                            ),
                            srcip=self.IP_OF_SENDING_INTERFACE
                        )
                        ip_header = pkt.get_header(packet.IPv4)
                        self.try_forwarding_ipv4(pkt, self.get_next_hop(ip_header.dstip))
                    del self.current_arp_requests[ip]
                    del self.waiting_on_arp[ip]
                else:
                    # otherwise we can try to send it again
                    arp_request_info.request_number += 1
                    common.log_debug('sending ARP request: try #{}'.format(
                        arp_request_info.request_number
                    ))
                    self.send_arp_request(ip)

    def send_packet(self, interface_name, request):
        self.net.send_packet(interface_name, request)

    def send_arp_reply(self, dev: str, pkt: packet.Packet):
        arp = pkt.get_header(packet.Arp)
        if in_in(self.internal_network_to_mac, arp.targetprotoaddr):
            reply = packet.create_ip_arp_reply(
                srchw=get_in(self.internal_network_to_mac, arp.targetprotoaddr).raw,
                srcip=arp.targetprotoaddr,
                dsthw=arp.senderhwaddr,
                targetip=arp.senderprotoaddr,

            )
            self.send_packet(dev, reply)

    def send_arp_request(self, ip: ipaddress.IPv4Address):
        sending_interface = get_in(self.network_to_interface, ip)
        request = packet.create_ip_arp_request(
            srchw=sending_interface.ethaddr,
            srcip=sending_interface.ipaddr,
            targetip=ip,
        )
        self.send_packet(sending_interface.name, request)

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

        if ip.dstip in self.internal_address:
            icmp = pkt.get_header(packet.ICMP)
            if icmp and icmp.icmptype == packet.ICMPType.EchoRequest:
                self.modify_pkt(
                    pkt,
                    new_header=self.generate_icmp_echo_reply(icmp),
                    srcip=ip.dstip
                )
            else:
                self.modify_pkt(
                    pkt,
                    new_header=self.generate_icmp_error(
                        pkt,
                        icmptype=packet.ICMPType.DestinationUnreachable,
                        icmpcode_name="PortUnreachable"
                    ),
                    srcip=self.IP_OF_SENDING_INTERFACE
                )
        else:
            ip.ttl -= 1
            if ip.ttl <= 0:
                self.modify_pkt(
                    pkt,
                    new_header=self.generate_icmp_error(
                        pkt,
                        icmptype=packet.ICMPType.TimeExceeded,
                        icmpcode_name="TTLExpired",
                    ),
                    srcip=self.IP_OF_SENDING_INTERFACE
                )

        try:
            next_hop = self.get_next_hop(ip.dstip)
        except KeyError:
            # If we cant find that next hop, then wen need to send out an error
            self.modify_pkt(
                pkt,
                new_header=self.generate_icmp_error(
                    pkt,
                    icmptype=packet.ICMPType.DestinationUnreachable,
                    icmpcode_name="NetworkUnreachable",
                ),
                srcip=self.IP_OF_SENDING_INTERFACE
            )
            next_hop = self.get_next_hop(ip.dstip)

        self.try_forwarding_ipv4(pkt, next_hop)

    def get_next_hop(self, ip: ipaddress.IPv4Address) -> ipaddress.IPv4Address:
        # if right next to router, can send w/ out next hop
        if in_in(self.internal_network_to_mac, ip):
            return ip
        return get_in(self.network_to_next_hop, ip)

    def try_forwarding_ipv4(self, pkt: packet.Packet, next_hop: ipaddress.IPv4Address) -> None:
        '''
        will forward an ip packet, but first makes sure we know the mac address
        of the next hop. if we don't, then we can add it to queue
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

        ethernet = pkt.get_header(packet.Ethernet)
        next_hop_mac = get_in(self.network_to_mac, next_hop)
        output_interface = get_in(self.network_to_interface, ip.dstip)

        ethernet.src = output_interface.ethaddr
        ethernet.dst = next_hop_mac

        if ip.srcip == ip.dstip:
            ip.srcip = output_interface.ipaddr

        self.send_packet(output_interface.name, pkt)

    def generate_icmp_echo_reply(self, icmp_request):
        icmp_response = packet.ICMP()
        icmp_response.icmptype = packet.common.ICMPType.EchoReply
        icmp_response.icmpdata.data = icmp_request.icmpdata.data
        icmp_response.icmpdata.identifier = icmp_request.icmpdata.identifier
        icmp_response.icmpdata.sequence = icmp_request.icmpdata.sequence
        return icmp_response

    def generate_icmp_error(self, pkt, icmptype, icmpcode_name):
        icmp = packet.ICMP()
        icmp.icmptype = icmptype
        for icmpcode in packet.ICMPTypeCodeMap[icmptype]:
            if icmpcode.name == icmpcode_name:
                icmp.icmpcode = icmpcode

        pkt_without_ethernet = copy.copy(pkt)
        del pkt_without_ethernet[pkt.get_header_index(packet.Ethernet)]
        icmp.icmpdata.data = pkt_without_ethernet.to_bytes()[:28]

        return icmp

    def modify_pkt(self, pkt, new_header, srcip=IP_OF_SENDING_INTERFACE):
        set_header(pkt, new_header)
        ip = pkt.get_header(packet.IPv4)

        # if we want the the source ip to that of the interface sending
        # we can set the IPs to be the same and check for it later
        # when we know the sending interface
        if srcip == self.IP_OF_SENDING_INTERFACE:
            srcip = ip.srcip
        ip.srcip, ip.dstip = srcip, ip.srcip
        ip.ttl = self.IP_TTL


def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
