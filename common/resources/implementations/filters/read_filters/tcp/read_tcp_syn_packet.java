package common.resources.implementations.filters.read_filters.tcp;

/**
 * Filter to read TCP SYN packets from network traffic.
 *
 * This filter captures TCP packets with the SYN flag set, which are used to initiate
 * a TCP connection. It is useful for monitoring connection attempts and analyzing
 * network behavior.
 *
 * Attributes:
 *   description: A brief description of the filter.
 *   filterExpression: The BPF (Berkeley Packet Filter) expression used to read TCP SYN packets.
 */
public class ReadTCPSynPacketFilter {
    private final String description = "Filter to read TCP SYN packets";
    private final String filterExpression = "tcp[13] & 0x02 != 0 and tcp[13] & 0x10 == 0"; // BPF expression for TCP SYN packets

    public String getDescription() {
        return description;
    }

    public String getFilterExpression() {
        return filterExpression;
    }
}