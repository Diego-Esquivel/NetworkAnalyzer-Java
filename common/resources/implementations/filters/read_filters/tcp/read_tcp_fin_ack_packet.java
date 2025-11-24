package common.resources.implementations.filters.read_filters.tcp;

/**
 * Filter to read TCP FIN-ACK packets from network traffic.
 *
 * This filter captures TCP packets with both the FIN and ACK flags set, which are used
 * to gracefully terminate a TCP connection. It is useful for monitoring connection
 * teardowns and analyzing network behavior.
 *
 * Attributes:
 *   description: A brief description of the filter.
 *   filterExpression: The BPF (Berkeley Packet Filter) expression used to read TCP FIN-ACK packets.
 */
public class ReadTCPFinAckPacketFilter {
    private final String description = "Filter to read TCP FIN-ACK packets";
    private final String filterExpression = "tcp[13] & 0x11 == 0x11"; // BPF expression for TCP FIN-ACK packets

    public String getDescription() {
        return description;
    }

    public String getFilterExpression() {
        return filterExpression;
    }
}