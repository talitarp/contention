"""Of_core.v0x04.action"""

from napps.kytos.of_core.flow import ActionBase
from napps.kytos.of_core.v0x04.flow import ActionSetVlan
from pyof.foundation.basic_types import HWAddress, IPAddress, IPv6Address
from pyof.v0x04.common.action import ActionSetField as OFActionSetField
from pyof.v0x04.common.flow_match import (
    OxmMatchFields,
    OxmOfbMatchField,
    OxmTLV,
    VlanId,
)


class ActionSetIPv4Dst(ActionBase):
    """Action to set IPv4 destination."""

    def __init__(self, ipv4_dst):
        self.ipv4_dst = ipv4_dst
        self.action_type = "set_ipv4_dst"

    @classmethod
    def from_of_action(cls, of_action):
        """Return a high-level ActionSetIPv4Dst instance from pyof."""
        ip_address = IPAddress()
        ip_address.unpack(of_action.field.oxm_value)
        return cls(
            ipv4_dst=str(ip_address),
        )

    def as_of_action(self):
        """Return a pyof ActionSetIPv4Dst instance."""
        ip_addr = IPAddress(self.ipv4_dst)
        tlv = OxmTLV(
            oxm_field=OxmOfbMatchField.OFPXMT_OFB_IPV4_DST,
            oxm_hasmask=False,
            oxm_value=ip_addr.pack(),
        )
        return OFActionSetField(field=tlv)


class ActionSetIPv6Dst(ActionBase):
    """Action to set IPv6 destination."""

    def __init__(self, ipv6_dst):
        self.ipv6_dst = ipv6_dst
        self.action_type = "set_ipv6_dst"

    @classmethod
    def from_of_action(cls, of_action):
        """Return a high-level ActionSetIPv4Dst instance from pyof."""
        ip_address = IPv6Address()
        ip_address.unpack(of_action.field.oxm_value)
        return cls(
            ipv6_dst=str(ip_address),
        )

    def as_of_action(self):
        """Return a pyof ActionSetIPv4Dst instance."""
        ip_addr = IPv6Address(self.ipv6_dst)
        tlv = OxmTLV(
            oxm_field=OxmOfbMatchField.OFPXMT_OFB_IPV6_DST,
            oxm_hasmask=False,
            oxm_value=ip_addr.pack(),
        )
        return OFActionSetField(field=tlv)


class ActionSetTCPDst(ActionBase):
    """Action to set TCP dst port."""

    def __init__(self, port):
        self.port = port
        self.action_type = "set_tcp_dst"

    @classmethod
    def from_of_action(cls, of_action):
        """Return a high-level instance from pyof."""
        port = int.from_bytes(of_action.field.oxm_value, 'big')
        return cls(port)

    def as_of_action(self):
        """Return a pyof ActionSetIPv4Dst instance."""
        tlv = OxmTLV(
            oxm_field=OxmOfbMatchField.OFPXMT_OFB_TCP_DST,
            oxm_value=self.port.to_bytes(2, 'big'),
        )
        return OFActionSetField(field=tlv)


class ActionSetUDPDst(ActionBase):
    """Action to set UDP dst port."""

    def __init__(self, port):
        self.port = port
        self.action_type = "set_udp_dst"

    @classmethod
    def from_of_action(cls, of_action):
        """Return a high-level instance from pyof."""
        port = int.from_bytes(of_action.field.oxm_value, 'big')
        return cls(port)

    def as_of_action(self):
        """Return a pyof instance."""
        tlv = OxmTLV(
            oxm_field=OxmOfbMatchField.OFPXMT_OFB_UDP_DST,
            oxm_value=self.port.to_bytes(2, 'big'),
        )
        return OFActionSetField(field=tlv)


class ActionSetETHDst(ActionBase):
    """Action to set Ethernet dst addr."""

    def __init__(self, eth_addr):
        self.eth_addr = eth_addr
        self.action_type = "set_eth_dst"

    @classmethod
    def from_of_action(cls, of_action):
        """Return a high-level instance from pyof."""
        eth_addr = HWAddress()
        eth_addr.unpack(of_action.field.oxm_value)
        return cls(str(eth_addr))

    def as_of_action(self):
        """Return a pyof instance."""
        tlv = OxmTLV(
            oxm_field=OxmOfbMatchField.OFPXMT_OFB_ETH_DST,
            oxm_value=HWAddress(self.eth_addr).pack()
        )
        return OFActionSetField(field=tlv)


class ActionSetFieldFactory(OFActionSetField):
    _subclass_set_field = {
        OxmOfbMatchField.OFPXMT_OFB_VLAN_VID: ActionSetVlan,
        OxmOfbMatchField.OFPXMT_OFB_IPV4_DST: ActionSetIPv4Dst,
        OxmOfbMatchField.OFPXMT_OFB_IPV6_DST: ActionSetIPv6Dst,
        OxmOfbMatchField.OFPXMT_OFB_TCP_DST: ActionSetTCPDst,
        OxmOfbMatchField.OFPXMT_OFB_UDP_DST: ActionSetUDPDst,
        OxmOfbMatchField.OFPXMT_OFB_ETH_DST: ActionSetETHDst,
    }

    @classmethod
    def from_of_action(cls, of_action):
        """Return a high-level ActionSetField to call specific subclass."""
        subclass = cls._subclass_set_field.get(of_action.field.oxm_field)
        return subclass.from_of_action(of_action) if subclass else None

    @classmethod
    def add_set_field_subclass(cls, oxm_field, subclass):
        """Add a subclass for ActionSetField based on OXM Field."""
        cls._subclass_set_field[oxm_field] = subclass
