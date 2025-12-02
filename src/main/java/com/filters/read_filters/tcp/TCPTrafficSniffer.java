package com.filters.read_filters.tcp;

/**
 * Tool to read TCP ACK packets from network traffic.
 *
 * This filter captures TCP packets with the depending on the arguments passed in. The args
 * are 1-to-1 with the types of capture filters supported.
 * This spawns a dumpcap process using the args like this:
 *  - dumpcap -i <interfaceName>  -f <capture filter> -w <output_file_name_prefix> -b duration:<NUM> -b packets:<NUM>
 * 
 * It is useful for monitoring ongoing connections
 * and analyzing network behavior.
 *
 * Attributes:
 *   description: A brief comprehensive list of the filters the sniffer is configured to capture.
 *   filterExpression: The BPF (Berkeley Packet Filter) expression used to read the configured TCP packets.
 */
public class TCPTrafficSniffer {
    private static String description = "Tool for capturing TCP-based network traffic";
    private static String[] readFiltersExpression = {
        ReadTCPAckPacketFilter.getFilterExpression(),
        ReadTCPCwrPacketFilter.getFilterExpression(),
        ReadTCPEcePacketFilter.getFilterExpression(),
        ReadTCPFinAckPacketFilter.getFilterExpression(),
        ReadTCPFinPacketFilter.getFilterExpression(),
        ReadTCPPshPacketFilter.getFilterExpression(),
        ReadTCPRstPacketFilter.getFilterExpression(),
        ReadTCPSynAckPacketFilter.getFilterExpression(),
        ReadTCPSynPacketFilter.getFilterExpression(),
        ReadTCPUrgPacketFilter.getFilterExpression()
    };
    private static String[] readFiltersDescriptions = {
        ReadTCPAckPacketFilter.getDescription(),
        ReadTCPCwrPacketFilter.getDescription(),
        ReadTCPEcePacketFilter.getDescription(),
        ReadTCPFinAckPacketFilter.getDescription(),
        ReadTCPFinPacketFilter.getDescription(),
        ReadTCPPshPacketFilter.getDescription(),
        ReadTCPRstPacketFilter.getDescription(),
        ReadTCPSynAckPacketFilter.getDescription(),
        ReadTCPSynPacketFilter.getDescription(),
        ReadTCPUrgPacketFilter.getDescription()
    };
    private static String interfaceName = "Wi-Fi";
    private static String filterExpression = "tcp"; // BPF expression for all TCP packets
    private static String filePatternWhereDataIsSaved = "C:\\Users\\mpidi\\Desktop\\MU\\tcp_capture_file.pcap";
    private static String dumpcapExpression = "start /B /D \"C:\\Program Files\\Wireshark\" dumpcap -i " + interfaceName + " -f \"" + filterExpression + "\" -w " + filePatternWhereDataIsSaved + " -b duration:10 -b files:10";

    public static String getDescription() {
        return description;
    }

    public static String getFilterExpression() {
        return filterExpression;
    }

    public static String getNetworkInterface() {
        return interfaceName;
    }

    public static String getFilePatterWhereDataIsSaved() {
        return filePatternWhereDataIsSaved;
    }

    public static String getDumpcapExpression() {
        return dumpcapExpression;
    }

    public static void startTrafficCapture() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/C", dumpcapExpression});
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void stopTrafficCapture() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"cmd.exe", "/C", "taskkill /F /IM dumpcap.exe"});
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        System.out.println("Description: " + TCPTrafficSniffer.getDescription());
        System.out.println("Filter Expression: " + TCPTrafficSniffer.getFilterExpression());
        System.out.println("Dumpcap Expression: " + TCPTrafficSniffer.getDumpcapExpression());
        // Start capturing TCP traffic
        TCPTrafficSniffer.startTrafficCapture();
        // sleep for a while to capture some packets
        try {
            Thread.sleep(80000); // Capture for 80 seconds
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        // Stop capturing TCP traffic
        TCPTrafficSniffer.stopTrafficCapture();
    }
}