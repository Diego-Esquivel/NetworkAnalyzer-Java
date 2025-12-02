package com.filters.read_filters.tcp;
import com.filters.read_filters.tcp.ReadFilter;

/**
 * Filter to read TCP FIN packets from network traffic.
 *
 * This filter captures TCP packets with the FIN flag set, which are used to gracefully
 * terminate a TCP connection. It is useful for monitoring connection teardowns and
 * analyzing network behavior.
 *
 * Attributes:
 *   description: A brief description of the filter.
 *   filterExpression: The BPF (Berkeley Packet Filter) expression used to read TCP FIN packets.
 */
public class ReadTCPFinPacketFilter extends ReadFilter {
    public ReadTCPFinPacketFilter() {
        super();
        description = "Filter to read TCP FIN packets";
        filterExpression = "tcp[13] & 0x01 != 0"; // BPF expression for TCP FIN packets
    }
}