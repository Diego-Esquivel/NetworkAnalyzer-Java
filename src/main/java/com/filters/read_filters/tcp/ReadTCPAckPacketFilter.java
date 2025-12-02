package com.filters.read_filters.tcp;
import com.filters.read_filters.tcp.ReadFilter;

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
public class ReadTCPAckPacketFilter extends ReadFilter {
    protected static String description = "Filter to read TCP ACK packets";
    protected static String filterExpression = "tcp[13] & 0x10 != 0"; // BPF expression for TCP ACK packets

    public static String getDescription() {
        return description;
    }
    
    public static String getFilterExpression() {
        return filterExpression;
    }
    public static void main(String[] args) {
        System.out.println("Description: " + ReadTCPAckPacketFilter.getDescription());
        System.out.println("Filter Expression: " + ReadTCPAckPacketFilter.getFilterExpression());
    }
}