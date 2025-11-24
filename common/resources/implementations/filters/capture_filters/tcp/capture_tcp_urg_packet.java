package common.resources.implementations.filters.capture_filters.tcp;

/**
 * Filter to capture TCP URG packets from network traffic.
 *
 * This filter captures TCP packets with the URG flag set, which indicate that the
 * urgent pointer field is significant. It is useful for monitoring urgent data
 * transmission and analyzing network behavior.
 *
 * Attributes:
 *    description (str): A brief description of the filter.
 *    filter_expression (str): The BPF (Berkeley Packet Filter) expression used to capture TCP URG packets.
 */
public class CaptureTCPUrgPacketFilter {
    private final String description = "Filter to capture TCP URG packets";
    private final String filterExpression = "tcp[13] & 0x20 != 0";  // BPF expression for TCP URG packets"

    public String getDescription() {
        return description;
    }

    public String getFilterExpression() {
        return filterExpression;
    }
}
