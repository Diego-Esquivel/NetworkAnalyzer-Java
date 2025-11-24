from dataclasses import dataclass

@dataclass
class ReadTCPFinAckPacketFilter:
    """
    Filter to read TCP FIN-ACK packets from network traffic.

    This filter captures TCP packets with both the FIN and ACK flags set, which are used
    to gracefully terminate a TCP connection. It is useful for monitoring connection
    teardowns and analyzing network behavior.

    Attributes:
        description (str): A brief description of the filter.
        filter_expression (str): The BPF (Berkeley Packet Filter) expression used to read TCP FIN-ACK packets.
    """
    description: str = "Filter to read TCP FIN-ACK packets"
    filter_expression: str = "tcp[13] & 0x11 == 0x11"  # BPF expression for TCP FIN-ACK packets"
