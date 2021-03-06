# Stubs for switchyard.lib.address (Python 3.4)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Undefined, Any
from enum import Enum

IPAddr = Undefined(Any)

class EthAddr:
    def __init__(self, addr=None): pass
    def isBridgeFiltered(self): pass
    @property
    def is_bridge_filtered(self): pass
    def isGlobal(self): pass
    def isLocal(self): pass
    @property
    def is_local(self): pass
    @property
    def is_global(self): pass
    def isMulticast(self): pass
    @property
    def is_multicast(self): pass
    def toRaw(self): pass
    @property
    def raw(self): pass
    @property
    def packed(self): pass
    def toTuple(self): pass
    def toStr(self, separator=''): pass
    def __eq__(self, other): pass
    def __lt__(self, other): pass
    def __hash__(self): pass
    def __len__(self): pass

ethaddr = Undefined(Any)
macaddr = Undefined(Any)

class SpecialIPv6Addr(Enum):
    UNDEFINED = Undefined(Any)
    ALL_NODES_LINK_LOCAL = Undefined(Any)
    ALL_ROUTERS_LINK_LOCAL = Undefined(Any)
    ALL_NODES_INTERFACE_LOCAL = Undefined(Any)
    ALL_ROUTERS_INTERFACE_LOCAL = Undefined(Any)

class SpecialIPv4Addr(Enum):
    IP_ANY = Undefined(Any)
    IP_BROADCAST = Undefined(Any)

class SpecialEthAddr(Enum):
    ETHER_ANY = Undefined(Any)
    ETHER_BROADCAST = Undefined(Any)
    BRIDGE_GROUP_ADDRESS = Undefined(Any)
    LLDP_MULTICAST = Undefined(Any)
    PAE_MULTICAST = Undefined(Any)
    NDP_MULTICAST = Undefined(Any)

def netmask_to_cidr(dq): pass
def cidr_to_netmask(bits): pass
def parse_cidr(addr, infer=True, allow_host=False): pass
def infer_netmask(addr): pass
