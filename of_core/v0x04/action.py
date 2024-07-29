"""Of_core.v0x04.action"""

from napps.kytos.of_core.flow import ActionBase

class ActionSetIpv4dst(ActionBase):
    """Action to send INT report."""

    def __init__(self, ip):
        self.ip = ip
        self.action_type = "set_ipv4_dst"

    @classmethod
    def from_of_action(cls, of_action):
    """Return a high-level ActionSetIpv4dst instance from pyof."""
        return cls()

    def as_of_action(self):
    """Return a pyof ActionSetIpv4dst instance."""
        return OFActionSetIpv4dst()

