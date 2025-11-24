package common.resources.implementations.filters.capture_filters.tcp;

/**
 * Filter to capture TCP PSH packets from network traffic.
 *
 * This filter captures TCP packets with the PSH (Push) flag set, which indicates that
 * the data should be pushed to the receiving application immediately. It is useful for
 * monitoring data transmission and analyzing network behavior.
 *
 * Attributes:
 *    description (str): A brief description of the filter.
 *    filter_expression (str): The BPF (Berkeley Packet Filter) expression used to capture TCP PSH packets.
 */
public class CaptureTCPPshPacketFilter {
    private final String description = "Filter to capture TCP PSH packets";
    private final String filterExpression = "tcp[13] & 0x08 != 0";  // BPF expression for TCP PSH packets

    public String getDescription() {
        return description;
    }

    public String getFilterExpression() {
        return filterExpression;
    }
}
