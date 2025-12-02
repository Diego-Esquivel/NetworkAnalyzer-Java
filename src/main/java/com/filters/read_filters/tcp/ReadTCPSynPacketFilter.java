package com.filters.read_filters.tcp;
import com.filters.read_filters.tcp.ReadFilter;

/**
 * Filter to read TCP SYN packets from network traffic.
 *
 * This filter captures TCP packets with the SYN flag set, which are used to initiate
 * a TCP connection. It is useful for monitoring connection attempts and analyzing
 * network behavior.
 *
 * Attributes:
 *   description: A brief description of the filter.
 *   filterExpression: The BPF (Berkeley Packet Filter) expression used to read TCP SYN packets.
 */
public class ReadTCPSynPacketFilter extends ReadFilter {
    public ReadTCPSynPacketFilter() {
        super();
        description = "Filter to read TCP SYN packets";
        filterExpression = "tcp[13] & 0x02 != 0 and tcp[13] & 0x10 == 0"; // BPF expression for TCP SYN packets
    }
}