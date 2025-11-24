package common.resources.implementations.filters.capture_filters.tcp;

/**
 * Filter to capture TCP CWR packets from network traffic.
 *
 * This filter captures TCP packets with the CWR (Congestion Window Reduced) flag set,
 * which indicates that the sender has reduced its congestion window. It is useful for
 * monitoring network congestion and performance.
 *
 * Attributes:
 *    description (str): A brief description of the filter.
 *    filter_expression (str): The BPF (Berkeley Packet Filter) expression used to capture TCP CWR packets.
 */
public class CaptureTCPCwrPacketFilter {
    private final String description = "Filter to capture TCP CWR packets";
    private final String filterExpression = "tcp[13] & 0x80 != 0";  // BPF expression for TCP CWR packets

    public String getDescription() {
        return description;
    }

    public String getFilterExpression() {
        return filterExpression;
    }
}
