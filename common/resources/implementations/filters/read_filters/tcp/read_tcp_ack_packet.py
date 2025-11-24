from dataclasses import dataclass

@dataclass
class ReadTCPAckPacketFilter:
    """
    Filter to read TCP ACK packets from network traffic.

    This filter captures TCP packets with the ACK flag set, which are used to acknowledge
    the receipt of data in a TCP connection. It is useful for monitoring ongoing connections
    and analyzing network behavior.

    Attributes:
        description (str): A brief description of the filter.
        filter_expression (str): The BPF (Berkeley Packet Filter) expression used to read TCP ACK packets.
    """
    description: str = "Filter to read TCP ACK packets"
    filter_expression: str = "tcp[13] & 0x10 != 0"  # BPF expression for TCP ACK packets"