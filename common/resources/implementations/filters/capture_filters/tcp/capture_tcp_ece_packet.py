from dataclasses import dataclass

@dataclass
class CaptureTCPEcPacketFilter:
    """
    Filter to capture TCP ECE packets from network traffic.

    This filter captures TCP packets with the ECE (ECN-Echo) flag set, which indicates
    that the packet is ECN-capable and that congestion was experienced in the network.
    It is useful for monitoring ECN behavior and analyzing network performance.

    Attributes:
        description (str): A brief description of the filter.
        filter_expression (str): The BPF (Berkeley Packet Filter) expression used to capture TCP ECE packets.
    """
    description: str = "Filter to capture TCP ECE packets"
    filter_expression: str = "tcp[13] & 0x40 != 0"  # BPF expression for TCP ECE packets"
