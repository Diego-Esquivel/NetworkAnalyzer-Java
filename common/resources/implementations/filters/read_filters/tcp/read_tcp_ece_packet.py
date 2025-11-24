from dataclasses import dataclass

@dataclass
class ReadTCPEcePacketFilter:
    """
    Filter to read TCP ECE packets from network traffic.

    This filter captures TCP packets with the ECE (ECN-Echo) flag set, which are used
    in Explicit Congestion Notification (ECN) to indicate network congestion without
    dropping packets. It is useful for monitoring ECN behavior and analyzing network
    performance.

    Attributes:
        description (str): A brief description of the filter.
        filter_expression (str): The BPF (Berkeley Packet Filter) expression used to read TCP ECE packets.
    """
    description: str = "Filter to read TCP ECE packets"
    filter_expression: str = "tcp[13] & 0x40 != 0"  # BPF expression for TCP ECE packets"
