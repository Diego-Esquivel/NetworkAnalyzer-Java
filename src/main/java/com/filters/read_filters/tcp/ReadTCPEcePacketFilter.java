package com.filters.read_filters.tcp;
import com.filters.read_filters.tcp.ReadFilter;

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
public class ReadTCPEcePacketFilter extends ReadFilter {
    public ReadTCPEcePacketFilter() {
        super();
        description = "Filter to read TCP ECE packets";
        filterExpression = "tcp[13] & 0x40 != 0"; // BPF expression for TCP ECE packets
    }
}