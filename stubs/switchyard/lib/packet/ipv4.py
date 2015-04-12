# Stubs for switchyard.lib.packet.ipv4 (Python 3.4)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Undefined, Any
from switchyard.lib.packet.packet import PacketHeaderBase
from collections import namedtuple

IPTypeClasses = Undefined(Any)

class IPOption:
    def __init__(self, optnum): pass
    @property
    def optnum(self): pass
    def length(self): pass
    def to_bytes(self): pass
    def from_bytes(self, raw): pass
    def __eq__(self, other): pass

class IPOptionNoOperation(IPOption):
    def __init__(self): pass

class IPOptionEndOfOptionList(IPOption):
    def __init__(self): pass

class IPOptionXRouting(IPOption):
    def __init__(self, ipoptnum, numaddrs=9): pass
    def length(self): pass
    def __len__(self): pass
    def to_bytes(self): pass
    pointer = Undefined(Any)
    def from_bytes(self, raw): pass
    def num_addrs(self): pass
    def __getitem__(self, index): pass
    def __setitem__(self, index, addr): pass
    def __delitem__(self, index): pass
    def __eq__(self, other): pass

class IPOptionLooseSourceRouting(IPOptionXRouting):
    def __init__(self): pass

class IPOptionStrictSourceRouting(IPOptionXRouting):
    def __init__(self): pass

class IPOptionRecordRoute(IPOptionXRouting):
    def __init__(self): pass

TimestampEntry = namedtuple('TimestampEntry', ['ipv4addr', 'timestamp'])

class IPOptionTimestamp(IPOption):
    def __init__(self, tslist=Undefined): pass
    def length(self): pass
    def to_bytes(self): pass
    def from_bytes(self, raw): pass
    def num_timestamps(self): pass
    def timestamp_entry(self, index): pass

class IPOption4Bytes(IPOption):
    def __init__(self, optnum, value=0, copyflag=False): pass
    def length(self): pass
    def from_bytes(self, raw): pass
    def to_bytes(self): pass
    def __eq__(self, other): pass

class IPOptionRouterAlert(IPOption4Bytes):
    def __init__(self): pass

class IPOptionMTUProbe(IPOption4Bytes):
    def __init__(self): pass

class IPOptionMTUReply(IPOption4Bytes):
    def __init__(self): pass

IPOptionClasses = Undefined(Any)

class IPOptionList:
    def __init__(self): pass
    @staticmethod
    def from_bytes(rawbytes): pass
    def to_bytes(self): pass
    def append(self, opt): pass
    def __len__(self): pass
    def __getitem__(self, i): pass
    def __setitem__(self, i, val): pass
    def __delitem__(self, i): pass
    def raw_length(self): pass
    def size(self): pass
    def __eq__(self, other): pass

class IPv4(PacketHeaderBase):
    tos = Undefined(Any)
    ipid = Undefined(Any)
    ttl = Undefined(Any)
    protocol = Undefined(Any)
    srcip = Undefined(Any)
    dstip = Undefined(Any)
    def __init__(self): pass
    def size(self): pass
    def pre_serialize(self, raw, pkt, i): pass
    def to_bytes(self): pass
    flags = Undefined(Any)
    fragment_offset = Undefined(Any)
    def from_bytes(self, raw): pass
    def __eq__(self, other): pass
    def next_header_class(self): pass
    @property
    def options(self): pass
    @property
    def total_length(self): pass
    @property
    def dscp(self): pass
    @property
    def hl(self): pass
    @property
    def checksum(self): pass
