package com.filters.read_filters.tcp;
import com.filters.read_filters.tcp.ReadFilter;

/**
 * Filter to read TCP URG packets from network traffic.
 *
 * This filter captures TCP packets with the URG flag set, which indicate that the
 * urgent pointer field is significant. It is useful for monitoring urgent data
 * transmission and analyzing network behavior.
 *
 * Attributes:
 *   description: A brief description of the filter.
 *   filterExpression: The BPF (Berkeley Packet Filter) expression used to read TCP URG packets.
 */
public class ReadTCPUrgPacketFilter extends ReadFilter {
    public ReadTCPUrgPacketFilter() {
        super();
        description = "Filter to read TCP URG packets";
        filterExpression = "tcp[13] & 0x20 != 0"; // BPF expression for TCP URG packets
    }
}