from dataclasses import dataclass

@dataclass
class ReadTCPSynPacketFilter:
    """
    Filter to read TCP SYN packets from network traffic.

    This filter captures TCP packets with the SYN flag set, which are used to initiate
    a TCP connection. It is useful for monitoring connection attempts and analyzing
    network behavior.

    Attributes:
        description (str): A brief description of the filter.
        filter_expression (str): The BPF (Berkeley Packet Filter) expression used to read TCP SYN packets.
    """
    description:str = "Filter to read TCP SYN packets"
    filter_expression: str = "tcp[13] & 0x02 != 0 and tcp[13] & 0x10 == 0"  # BPF expression for TCP SYN packets"