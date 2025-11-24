from dataclasses import dataclass

@dataclass
class ReadTCPCwrPacketFilter:
    """
    Filter to read TCP CWR packets from network traffic.

    This filter captures TCP packets with the CWR (Congestion Window Reduced) flag set,
    which indicates that the sender has reduced its congestion window. It is useful for
    monitoring congestion control mechanisms in TCP connections and analyzing network behavior.

    Attributes:
        description (str): A brief description of the filter.
        filter_expression (str): The BPF (Berkeley Packet Filter) expression used to read TCP CWR packets.
    """
    description: str = "Filter to read TCP CWR packets"
    filter_expression: str = "tcp[13] & 0x80 != 0"  # BPF expression for TCP CWR packets"
