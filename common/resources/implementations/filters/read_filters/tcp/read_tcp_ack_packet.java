package common.resources.implementations.filters.read_filters.tcp;

/**
 * Filter to read TCP ACK packets from network traffic.
 *
 * This filter captures TCP packets with the ACK flag set, which are used to acknowledge
 * the receipt of data in a TCP connection. It is useful for monitoring ongoing connections
 * and analyzing network behavior.
 *
 * Attributes:
 *   description: A brief description of the filter.
 *   filterExpression: The BPF (Berkeley Packet Filter) expression used to read TCP ACK packets.
 */
public class ReadTCPAckPacketFilter {
    private final String description = "Filter to read TCP ACK packets";
    private final String filterExpression = "tcp[13] & 0x10 != 0"; // BPF expression for TCP ACK packets

    public String getDescription() {
        return description;
    }

    public String getFilterExpression() {
        return filterExpression;
    }
}