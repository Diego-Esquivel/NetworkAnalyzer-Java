package common.resources.implementations.filters.read_filters.tcp;

/**
 * Filter to read TCP SYN-ACK packets from network traffic.
 *
 * This filter captures TCP packets with both the SYN and ACK flags set, which are used
 * to acknowledge a TCP connection initiation. It is useful for monitoring connection
 * establishments and analyzing network behavior.
 *
 * Attributes:
 *   description: A brief description of the filter.
 *   filterExpression: The BPF (Berkeley Packet Filter) expression used to read TCP SYN-ACK packets.
 */
public class ReadTCPSynAckPacketFilter {
    private final String description = "Filter to read TCP SYN-ACK packets";
    private final String filterExpression = "tcp[13] & 0x12 == 0x12"; // BPF expression for TCP SYN-ACK packets

    public String getDescription() {
        return description;
    }

    public String getFilterExpression() {
        return filterExpression;
    }
}