#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *


class Router(object):
    def __init__(self, net):
        self.net = net
        self.ip_to_mac = {interface.ipaddr: interface.ethaddr for interface in net.interfaces()}

    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True
            try:
                dev, pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break
            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                if pkt.has_header(Arp):
                    arp = pkt.get_header(Arp)
                    if arp.targetprotoaddr in self.ip_to_mac:
                        reply = create_ip_arp_reply(
                            srchw=self.ip_to_mac[arp.targetprotoaddr].raw,
                            srcip=arp.targetprotoaddr,
                            dsthw=arp.senderhwaddr,
                            targetip=arp.senderprotoaddr,

                        )
                        self.net.send_packet(dev, reply)


def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
