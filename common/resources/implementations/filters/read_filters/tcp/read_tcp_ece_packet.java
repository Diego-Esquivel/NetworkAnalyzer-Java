package common.resources.implementations.filters.read_filters.tcp;

/**
 * Filter to read TCP ECE packets from network traffic.
 *
 * This filter captures TCP packets with the ECE (ECN-Echo) flag set, which are used
 * in Explicit Congestion Notification (ECN) to indicate network congestion without
 * dropping packets. It is useful for monitoring ECN behavior and analyzing network
 * performance.
 *
 * Attributes:
 *   description: A brief description of the filter.
 *   filterExpression: The BPF (Berkeley Packet Filter) expression used to read TCP ECE packets.
 */
public class ReadTCPEcePacketFilter {
    private final String description = "Filter to read TCP ECE packets";
    private final String filterExpression = "tcp[13] & 0x40 != 0"; // BPF expression for TCP ECE packets

    public String getDescription() {
        return description;
    }

    public String getFilterExpression() {
        return filterExpression;
    }
}