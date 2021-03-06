# Stubs for switchyard.lib.packet.common (Python 3.4)
#
# NOTE: This dynamically typed stub was automatically generated by stubgen.

from typing import Undefined, Any
from enum import Enum

class EtherType(Enum):
    NoType = Undefined(Any)
    IP = Undefined(Any)
    IPv4 = Undefined(Any)
    ARP = Undefined(Any)
    x8021Q = Undefined(Any)
    Vlan = Undefined(Any)
    VLAN = Undefined(Any)
    IPv6 = Undefined(Any)
    SLOW = Undefined(Any)
    MPLS = Undefined(Any)
    x8021AD = Undefined(Any)
    LLDP = Undefined(Any)
    x8021AH = Undefined(Any)
    IEEE8023 = Undefined(Any)

class ArpHwType(Enum):
    Ethernet = Undefined(Any)

class ArpOperation(Enum):
    Request = Undefined(Any)
    Reply = Undefined(Any)
    RequestReverse = Undefined(Any)
    ReplyReverse = Undefined(Any)

class IPProtocol(Enum):
    IPv6HopOption = Undefined(Any)
    ICMP = Undefined(Any)
    IGMP = Undefined(Any)
    IPinIP = Undefined(Any)
    TCP = Undefined(Any)
    UDP = Undefined(Any)
    IPv6Encap = Undefined(Any)
    IPv6RouteOption = Undefined(Any)
    IPv6Fragment = Undefined(Any)
    RSVP = Undefined(Any)
    GRE = Undefined(Any)
    EncapsulatingSecurityPayload = Undefined(Any)
    AuthenticationHeader = Undefined(Any)
    IPMobility = Undefined(Any)
    TLSP = Undefined(Any)
    ICMPv6 = Undefined(Any)
    IPv6NoNext = Undefined(Any)
    IPv6DestinationOption = Undefined(Any)
    EIGRP = Undefined(Any)
    OSPF = Undefined(Any)
    IPIP = Undefined(Any)
    EtherIP = Undefined(Any)
    SCTP = Undefined(Any)
    IPv6Mobility = Undefined(Any)
    MPLSinIP = Undefined(Any)
    IPv6Shim6 = Undefined(Any)

class IPFragmentFlag(Enum):
    NoFragments = Undefined(Any)
    DontFragment = Undefined(Any)
    MoreFragments = Undefined(Any)

class IPOptionNumber(Enum):
    EndOfOptionList = Undefined(Any)
    NoOperation = Undefined(Any)
    LooseSourceRouting = Undefined(Any)
    Timestamp = Undefined(Any)
    RecordRoute = Undefined(Any)
    StrictSourceRouting = Undefined(Any)
    MTUProbe = Undefined(Any)
    MTUReply = Undefined(Any)
    RouterAlert = Undefined(Any)

class ICMPType(Enum):
    EchoReply = Undefined(Any)
    DestinationUnreachable = Undefined(Any)
    SourceQuench = Undefined(Any)
    Redirect = Undefined(Any)
    EchoRequest = Undefined(Any)
    RouterAdvertisement = Undefined(Any)
    RouterSolicitation = Undefined(Any)
    TimeExceeded = Undefined(Any)
    ParameterProblem = Undefined(Any)
    Timestamp = Undefined(Any)
    TimestampReply = Undefined(Any)
    InformationRequest = Undefined(Any)
    InformationReply = Undefined(Any)
    AddressMaskRequest = Undefined(Any)
    AddressMaskReply = Undefined(Any)

class ICMPCodeEchoReply(Enum):
    EchoReply = Undefined(Any)

class ICMPCodeDestinationUnreachable(Enum):
    NetworkUnreachable = Undefined(Any)
    HostUnreachable = Undefined(Any)
    ProtocolUnreachable = Undefined(Any)
    PortUnreachable = Undefined(Any)
    FragmentationRequiredDFSet = Undefined(Any)
    SourceRouteFailed = Undefined(Any)
    DestinationNetworkUnknown = Undefined(Any)
    DestinationHostUnknown = Undefined(Any)
    SourceHostIsolated = Undefined(Any)
    NetworkAdministrativelyProhibited = Undefined(Any)
    HostAdministrativelyProhibited = Undefined(Any)
    NetworkUnreachableForTOS = Undefined(Any)
    HostUnreachableForTOS = Undefined(Any)
    CommunicationAdministrativelyProhibited = Undefined(Any)
    HostPrecedenceViolation = Undefined(Any)
    PrecedenceCutoffInEffect = Undefined(Any)

class ICMPCodeSourceQuench(Enum):
    SourceQuench = Undefined(Any)

class ICMPCodeRedirect(Enum):
    RedirectForNetwork = Undefined(Any)
    RedirectForHost = Undefined(Any)
    RedirectForTOSAndNetwork = Undefined(Any)
    RedirectForTOSAndHost = Undefined(Any)

class ICMPCodeEchoRequest(Enum):
    EchoRequest = Undefined(Any)

class ICMPCodeRouterAdvertisement(Enum):
    RouterAdvertisement = Undefined(Any)

class ICMPCodeRouterSolicitation(Enum):
    RouterSolicitation = Undefined(Any)

class ICMPCodeTimeExceeded(Enum):
    TTLExpired = Undefined(Any)
    FragmentReassemblyTimeExceeded = Undefined(Any)

class ICMPCodeParameterProblem(Enum):
    PointerIndictatesError = Undefined(Any)
    MissingRequiredOption = Undefined(Any)
    BadLength = Undefined(Any)

class ICMPCodeTimestamp(Enum):
    Timestamp = Undefined(Any)

class ICMPCodeTimestampReply(Enum):
    TimestampReply = Undefined(Any)

class ICMPCodeInformationRequest(Enum):
    InformationRequest = Undefined(Any)

class ICMPCodeInformationReply(Enum):
    InformationReply = Undefined(Any)

class ICMPCodeAddressMaskRequest(Enum):
    AddressMaskRequest = Undefined(Any)

class ICMPCodeAddressMaskReply(Enum):
    AddressMaskReply = Undefined(Any)

ICMPTypeCodeMap = Undefined(Any)

class ICMPv6Type(Enum):
    DestinationUnreachable = Undefined(Any)
    PacketTooBig = Undefined(Any)
    TimeExceeded = Undefined(Any)
    ParameterProblem = Undefined(Any)
    PrivateExperimentation1 = Undefined(Any)
    PrivateExperimentation2 = Undefined(Any)
    EchoRequest = Undefined(Any)
    EchoReply = Undefined(Any)
    MulticastListenerQuery = Undefined(Any)
    MulticastListenerReport = Undefined(Any)
    MulticastListenerDone = Undefined(Any)
    RouterSolicitation = Undefined(Any)
    RouterAdvertisement = Undefined(Any)
    NeighborSolicitation = Undefined(Any)
    NeighborAdvertisement = Undefined(Any)
    RedirectMessage = Undefined(Any)
    RouterRenumbering = Undefined(Any)
    ICMPNodeInformationQuery = Undefined(Any)
    ICMPNodeInformationResponse = Undefined(Any)
    InverseNeighborDiscoverySolicitationMessage = Undefined(Any)
    InverseNeighborDiscoveryAdvertisementMessage = Undefined(Any)
    Version2MulticastListenerReport = Undefined(Any)
    HomeAgentAddressDiscoveryRequestMessage = Undefined(Any)
    HomeAgentAddressDiscoveryReplyMessage = Undefined(Any)
    MobilePrefixSolicitation = Undefined(Any)
    MobilePrefixAdvertisement = Undefined(Any)
    CertificationPathSolicitationMessage = Undefined(Any)
    CertificationPathAdvertisementMessage = Undefined(Any)
    ICMPmessagesutilizedbyexperimentalmobilityprotocolssuchasSeamoby = Undefined(Any)
    MulticastRouterAdvertisement = Undefined(Any)
    MulticastRouterSolicitation = Undefined(Any)
    MulticastRouterTermination = Undefined(Any)
    FMIPv6Messages = Undefined(Any)
    RPLControlMessage = Undefined(Any)
    ILNPv6LocatorUpdateMessage = Undefined(Any)
    DuplicateAddressRequest = Undefined(Any)
    DuplicateAddressConfirmation = Undefined(Any)
    Privateexperimentation3 = Undefined(Any)
    Privateexperimentation4 = Undefined(Any)

ICMPv6TypeCodeMap = Undefined(Any)

def checksum(data, start=0, skip_word=None): pass
