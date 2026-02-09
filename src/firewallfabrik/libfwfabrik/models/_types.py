"""Non-ORM value types: dataclasses, IntEnums, and custom SQLAlchemy type."""

import dataclasses
import enum
import ipaddress
import socket
import typing

import sqlalchemy.engine
import sqlalchemy.types


@dataclasses.dataclass
class InetAddr:
    """
    Wrapper for IPv4 / IPv6 addresses.

    Replaces C++ struct in_addr / in6_addr with Python ipaddress types.
    """

    address_family: int = socket.AF_INET
    ipv4: ipaddress.IPv4Address = dataclasses.field(
        default_factory=lambda: ipaddress.IPv4Address(0),
    )
    ipv6: ipaddress.IPv6Address = dataclasses.field(
        default_factory=lambda: ipaddress.IPv6Address(0),
    )


@dataclasses.dataclass
class InetAddrMask:
    """Holder of an address / netmask pair."""

    address: typing.Optional[InetAddr] = None
    netmask: typing.Optional[InetAddr] = None
    broadcast_address: typing.Optional[InetAddr] = None
    network_address: typing.Optional[InetAddr] = None
    last_host: typing.Optional[InetAddr] = None


@dataclasses.dataclass
class Inet6AddrMask(InetAddrMask):
    """IPv6-specific address/mask pair."""
    pass


class TCPFlag(enum.IntEnum):
    """TCP header flag bits."""

    URG = 0
    ACK = 1
    PSH = 2
    RST = 3
    SYN = 4
    FIN = 5


class PolicyAction(enum.IntEnum):
    """Actions for policy rules."""

    Unknown = 0
    Accept = 1
    Reject = 2
    Deny = 3
    Scrub = 4
    Return = 5
    Skip = 6
    Continue = 7
    Accounting = 8
    Modify = 9
    Pipe = 10
    Custom = 11
    Branch = 12


class Direction(enum.IntEnum):
    """Traffic direction for policy rules."""

    Undefined = 0
    Inbound = 1
    Outbound = 2
    Both = 3


class NATAction(enum.IntEnum):
    """Actions for NAT rules."""

    Translate = 0
    Branch = 1


class NATRuleType(enum.IntEnum):
    """NAT rule classification."""

    Unknown = 0
    NONAT = 1
    NATBranch = 2
    SNAT = 3
    Masq = 4
    DNAT = 5
    SDNAT = 6
    SNetnat = 7
    DNetnat = 8
    Redirect = 9
    Return = 10
    Skip = 11
    Continue = 12
    LB = 13


class RoutingRuleType(enum.IntEnum):
    """Routing rule classification."""

    Undefined = 0
    SinglePath = 1
    MultiPath = 2


class StandardId(enum.IntEnum):
    """Well-known object IDs in the database."""

    ROOT = 0
    ANY_ADDRESS = 1
    ANY_SERVICE = 2
    ANY_INTERVAL = 3
    STANDARD_LIB = 4
    USER_LIB = 5
    TEMPLATE_LIB = 6
    DELETED_OBJECTS = 7
    DUMMY_ADDRESS = 8
    DUMMY_SERVICE = 9
    DUMMY_INTERFACE = 10


class JSONEncodedSet(sqlalchemy.types.TypeDecorator):
    """Stores a Python ``set[str]`` as a JSON list in the database."""

    impl = sqlalchemy.types.JSON
    cache_ok = True

    def process_bind_param(
            self,
            value: set[str] | None, dialect: sqlalchemy.engine.Dialect
    ) -> list[str] | None:
        if value is not None:
            return sorted(value)
        return value

    def process_result_value(
            self,
            value: list[str] | None, dialect: sqlalchemy.engine.Dialect
    ) -> set[str] | None:
        if value is not None:
            return set(value)
        return value
