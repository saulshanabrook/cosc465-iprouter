# Stubs for switchyard.lib.packet.igmp (Python 3.4)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from switchyard.lib.packet.packet import PacketHeaderBase

class IGMP(PacketHeaderBase):
    def __init__(self): pass
    def size(self): pass
    def to_bytes(self): pass
    def from_bytes(self, raw): pass
    def __eq__(self, other): pass
    def next_header_class(self): pass
    def pre_serialize(self, raw, pkt, i): pass