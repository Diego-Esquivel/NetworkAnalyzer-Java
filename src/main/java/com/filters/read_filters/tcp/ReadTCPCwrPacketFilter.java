package com.filters.read_filters.tcp;
import com.filters.read_filters.tcp.ReadFilter;

/**
 * Filter to read TCP CWR packets from network traffic.
 *
 * This filter captures TCP packets with the CWR (Congestion Window Reduced) flag set,
 * which indicates that the sender has reduced its congestion window. It is useful for
 * monitoring congestion control mechanisms in TCP connections and analyzing network behavior.
 *
 * Attributes:
 *   description: A brief description of the filter.
 *   filterExpression: The BPF (Berkeley Packet Filter) expression used to read TCP CWR packets.
 */
public class ReadTCPCwrPacketFilter extends ReadFilter {
    public ReadTCPCwrPacketFilter() {
        super();
        description = "Filter to read TCP CWR packets";
        filterExpression = "tcp[13] & 0x80 != 0"; // BPF expression for TCP CWR packets
    }
}