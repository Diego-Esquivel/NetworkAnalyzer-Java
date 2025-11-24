from dataclasses import dataclass

@dataclass
class ReadTCPFinPacketFilter:
    """
    Filter to read TCP FIN packets from network traffic.

    This filter captures TCP packets with the FIN flag set, which are used to gracefully
    terminate a TCP connection. It is useful for monitoring connection teardowns and
    analyzing network behavior.

    Attributes:
        description (str): A brief description of the filter.
        filter_expression (str): The BPF (Berkeley Packet Filter) expression used to read TCP FIN packets.
    """
    description: str = "Filter to read TCP FIN packets"
    filter_expression: str = "tcp[13] & 0x01 != 0"  # BPF expression for TCP FIN packets"