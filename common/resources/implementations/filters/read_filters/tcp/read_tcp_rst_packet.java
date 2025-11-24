package common.resources.implementations.filters.read_filters.tcp;

/**
 * Filter to read TCP RST packets from network traffic.
 *
 * This filter captures TCP packets with the RST flag set, which are used to abruptly
 * terminate a TCP connection. It is useful for monitoring connection resets and
 * analyzing network behavior.
 *
 * Attributes:
 *   description: A brief description of the filter.
 *   filterExpression: The BPF (Berkeley Packet Filter) expression used to read TCP RST packets.
 */
public class ReadTCPRstPacketFilter {
    private final String description = "Filter to read TCP RST packets";
    private final String filterExpression = "tcp[13] & 0x04 != 0"; // BPF expression for TCP RST packets"

    public String getDescription() {
        return description;
    }

    public String getFilterExpression() {
        return filterExpression;
    }
}