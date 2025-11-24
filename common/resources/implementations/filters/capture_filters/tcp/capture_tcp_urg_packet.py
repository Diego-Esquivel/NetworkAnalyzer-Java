from dataclasses import dataclass

@dataclass
class CaptureTCPUrgPacketFilter:
    """
    Filter to capture TCP URG packets from network traffic.

    This filter captures TCP packets with the URG flag set, which indicate that the
    urgent pointer field is significant. It is useful for monitoring urgent data
    transmission and analyzing network behavior.

    Attributes:
        description (str): A brief description of the filter.
        filter_expression (str): The BPF (Berkeley Packet Filter) expression used to capture TCP URG packets.
    """
    description: str = "Filter to capture TCP URG packets"
    filter_expression: str = "tcp[13] & 0x20 != 0"  # BPF expression for TCP URG packets"
