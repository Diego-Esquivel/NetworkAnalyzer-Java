package com.filters.read_filters.tcp;
import com.filters.read_filters.tcp.ReadFilter;

/**
 * Filter to read TCP PSH packets from network traffic.
 *
 * This filter captures TCP packets with the PSH flag set, which indicates that the
 * data should be pushed to the receiving application immediately. It is useful for
 * monitoring data transmission and analyzing network behavior.
 *
 * Attributes:
 *   description: A brief description of the filter.
 *   filterExpression: The BPF (Berkeley Packet Filter) expression used to read TCP PSH packets.
 */
public class ReadTCPPshPacketFilter extends ReadFilter {
    protected static String description = "Filter to read TCP PSH packets";
    protected static String filterExpression = "tcp[13] & 0x08 != 0"; // BPF expression for TCP PSH packets
    
    public static String getDescription() {
        return description;
    }
    
    public static String getFilterExpression() {
        return filterExpression;
    }
}