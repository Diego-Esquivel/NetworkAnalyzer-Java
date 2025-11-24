from dataclasses import dataclass

@dataclass
class CaptureTCPCwrPacketFilter:
    """
    Filter to capture TCP CWR packets from network traffic.

    This filter captures TCP packets with the CWR (Congestion Window Reduced) flag set,
    which indicates that the sender has reduced its congestion window. It is useful for
    monitoring network congestion and performance.

    Attributes:
        description (str): A brief description of the filter.
        filter_expression (str): The BPF (Berkeley Packet Filter) expression used to capture TCP CWR packets.
    """
    description: str = "Filter to capture TCP CWR packets"
    filter_expression: str = "tcp[13] & 0x80 != 0"  # BPF expression for TCP CWR packets"
