from dataclasses import dataclass

@dataclass
class CaptureTCPRstPacketFilter:
    """
    Filter to capture TCP RST packets from network traffic.

    This filter captures TCP packets with the RST flag set, which are used to abruptly
    terminate a TCP connection. It is useful for monitoring connection resets and
    analyzing network behavior.

    Attributes:
        description (str): A brief description of the filter.
        filter_expression (str): The BPF (Berkeley Packet Filter) expression used to capture TCP RST packets.
    """
    description: str = "Filter to capture TCP RST packets"
    filter_expression: str = "tcp[13] & 0x04 != 0"  # BPF expression for TCP RST packets"
