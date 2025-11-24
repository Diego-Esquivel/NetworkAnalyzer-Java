package common.resources.implementations.filters.capture_filters.tcp;

/**
 * Filter to capture TCP SYN-ACK packets from network traffic.
 *
 * This filter captures TCP packets with both the SYN and ACK flags set, which are used
 * to acknowledge a TCP connection initiation. It is useful for monitoring connection
 * establishments and analyzing network behavior.
 *
 * Attributes:
 *    description (str): A brief description of the filter.
 *    filter_expression (str): The BPF (Berkeley Packet Filter) expression used to capture TCP SYN-ACK packets.
 */
public class CaptureTCPSynAckPacketFilter {
    private final String description = "Filter to capture TCP SYN-ACK packets";
    private final String filterExpression = "tcp[13] & 0x12 == 0x12";  // BPF expression for TCP SYN-ACK packets

    public String getDescription() {
        return description;
    }

    public String getFilterExpression() {
        return filterExpression;
    }
}
