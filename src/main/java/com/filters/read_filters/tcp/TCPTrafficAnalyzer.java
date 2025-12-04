package com.filters.read_filters.tcp;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;

public class TCPTrafficAnalyzer {
    protected final static String description = "Analyzer for TCP traffic patterns and anomalies";
    public static String[] readFiltersExpression = {
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
    private static String[] readPacketsByIPAddress = {"(ip.src==" , "" , " && ip.dst==", "", ") || (ip.src==", "", " && ip.dst==" , "", ")"};
    private final static int indexOfIPSrcInFilter_1 = 1;
    private final static int indexOfIPDstInFilter_1 = 3;
    private final static int indexOfIPSrcInFilter_2 = 7;
    private final static int indexOfIPDstInFilter_2 = 5;
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
    public static int[] flagBuffer = new int[10];
    private static String readFilterString = "";
    public static String filePatternWhereDataIsSaved = "C:\\Users\\mpidi\\Desktop\\MU\\tcp_capture_file";
    public static String clientHostIPAddress = "127.0.0.1";
    protected static String[] IPAddressesClientHostTalksWith = new String[50];
    private static String prepareFileForProcessingExpression = "type " + filePatternWhereDataIsSaved + "* > all_pcap.pcap";
    private static String tsharkExpression = "start /B /D \"C:\\Program Files\\Wireshark\" tshark -r \"C:\\Users\\mpidi\\Desktop\\MU\\FA2025\\COSC6280\\Semester Long Project\\NetworkAnalyzer-Java\\all_pcap.pcap\" -Y " + readFilterString + " > " + filePatternWhereDataIsSaved + "_analyzed.txt";
    public static String getDescription() {
        return description;
    }

    public static String getFilterExpression() {
        return readFilterString;
    }

    public static void setFilterExpression(int index) {
        String filterExpression = readFiltersExpression[index];
        readFilterString = filterExpression;
    }

    public static String getFilePatternWhereDataIsSaved() {
        return filePatternWhereDataIsSaved;
    }

    public static void setFilePatternWhereDataIsSaved(String filePatternWhereDataIsSaved) {
        TCPTrafficAnalyzer.filePatternWhereDataIsSaved = filePatternWhereDataIsSaved;
    }

    public static String getClientHostIPAddress() {
        return clientHostIPAddress;
    }

    public static void setClientHostIPAddress(String clientHostIPAddress) {
        TCPTrafficAnalyzer.clientHostIPAddress = clientHostIPAddress;
    }

    public static String getTsharkExpression() {
        return tsharkExpression;
    }

    public static void setTsharkExpression(String tsharkExpression) {
        TCPTrafficAnalyzer.tsharkExpression = tsharkExpression;
    }

    private static void resetTsharkExpression() {
        tsharkExpression = "start /B /D \"C:\\Program Files\\Wireshark\" tshark -r \"C:\\Users\\mpidi\\Desktop\\MU\\FA2025\\COSC6280\\Semester Long Project\\NetworkAnalyzer-Java\\all_pcap.pcap\" -Y \"" + readFilterString + "\" > " + filePatternWhereDataIsSaved + "_analyzed.txt";
    }

    public static String[] getReadFiltersDescriptions() {
        return readFiltersDescriptions;
    }

    public static String[] getIPAddressesClientHostTalksWith() {
        return IPAddressesClientHostTalksWith;
    }

    public static void setIPAddressesClientHostTalksWith(String[] IPAddressesClientHostTalksWith) {
        TCPTrafficAnalyzer.IPAddressesClientHostTalksWith = IPAddressesClientHostTalksWith;
    }

    public static int[] getFlagBuffer() {
        return flagBuffer;
    }

    public static void setFlagBuffer(int[] flagBuffer) {
        TCPTrafficAnalyzer.flagBuffer = flagBuffer;
    }

    public static String[] getReadFiltersExpression() {
        return readFiltersExpression;
    }

    public static void setReadFiltersExpression(String[] readFiltersExpression) {
        TCPTrafficAnalyzer.readFiltersExpression = readFiltersExpression;
    }

    public static String[] getListOfPacketsBetweenClientAndAHost(String hostIPAddress) {
        // Build the filter expression in the array
        readPacketsByIPAddress[indexOfIPSrcInFilter_1] = clientHostIPAddress;
        readPacketsByIPAddress[indexOfIPDstInFilter_1] = hostIPAddress;
        readPacketsByIPAddress[indexOfIPSrcInFilter_2] = hostIPAddress;
        readPacketsByIPAddress[indexOfIPDstInFilter_2] = clientHostIPAddress;
        // Concatenate the array elements to form the final filter string
        readFilterString = String.join("", readPacketsByIPAddress);
        executeTSharkExpression();
        String[] listOfPacketsBetweenClientAndAHostFilter = readTSharkAnalyzedOutput();
        return listOfPacketsBetweenClientAndAHostFilter;
    }

    public static String[] getAllSYNPackets() {
        setFilterExpression(8); // Index 8 corresponds to SYN packets
        executeTSharkExpression();
        String[] listOfSYNPackets = readTSharkAnalyzedOutput();
        return listOfSYNPackets;
    }

    public static String[] getAllSYNACKPackets() {
        setFilterExpression(7); // Index 7 corresponds to SYN-ACK packets
        executeTSharkExpression();
        String[] listOfSYNACKPackets = readTSharkAnalyzedOutput();
        return listOfSYNACKPackets;
    }
    
    public static String[] getAllACKPackets() {
        setFilterExpression(0); // Index 0 corresponds to ACK packets
        executeTSharkExpression();
        String[] listOfACKPackets = readTSharkAnalyzedOutput();
        return listOfACKPackets;
    }

    public static String[] getAllSYNACKResponsePackets() {
        // Get all ACK packets
        String[] allACKPackets = getAllACKPackets();
        // Move all SYN-ACK packets into another list
        ArrayList<String> synAckPackets = new ArrayList<String>();
        for (String ackPacket : allACKPackets) {
            if (ackPacket.contains("Flags [S.]") && ackPacket.contains("tcp.len==0")) {
                synAckPackets.add(ackPacket);
            }
        }
        // Make an array list for ACK only packets
        ArrayList<String> ackOnlyPackets = new ArrayList<String>();
        for (String ackPacket : allACKPackets) {
            if (ackPacket.contains("Flags [.]") && ackPacket.contains("tcp.len==0")) {
                ackOnlyPackets.add(ackPacket);
            }
        }
        // Compare the ACK # of ACK only packets with the sequence # of SYN-ACK packets. If the ACK # is equal to a SYN-ACK sequence #, then it's a response to that SYN-ACK & save it to another list
        ArrayList<String> synAckResponsePackets = new ArrayList<String>();
        for (String synAckPacket : synAckPackets) {
            String[] synAckParts = synAckPacket.split(" ");
            String synAckSeqNum = "";
            String synAckSrcIP = "";
            String synAckDstIP = "";
            for (int i = 0; i < synAckParts.length; i++) {
                if (synAckParts[i].startsWith("seq=")) {
                    synAckSeqNum = synAckParts[i].substring(4);
                }
                if (synAckParts[i].startsWith("IP")) {
                    synAckSrcIP = synAckParts[i + 1].split("\\.")[0];
                    synAckDstIP = synAckParts[i + 3].split("\\.")[0];
                }
            }
            for (String ackPacket : ackOnlyPackets) {
                String[] ackParts = ackPacket.split(" ");
                String ackNum = "";
                String ackSrcIP = "";
                String ackDstIP = "";
                for (int j = 0; j < ackParts.length; j++) {
                    if (ackParts[j].startsWith("ack=")) {
                        ackNum = ackParts[j].substring(4);
                    }
                    if (ackParts[j].startsWith("IP")) {
                        ackSrcIP = ackParts[j + 1].split("\\.")[0];
                        ackDstIP = ackParts[j + 3].split("\\.")[0];
                    }
                }
                if (ackNum.equals(synAckSeqNum) && ackSrcIP.equals(synAckDstIP) && ackDstIP.equals(synAckSrcIP)) {
                    synAckResponsePackets.add(ackPacket);
                }
            }
        }
        return synAckResponsePackets.toArray(new String[]{});
    }

    public static String[] getAllFINPackets() {
        setFilterExpression(4); // Index 4 corresponds to FIN packets
        executeTSharkExpression();
        String[] listOfFINPackets = readTSharkAnalyzedOutput();
        return listOfFINPackets;
    }

    public static String[] getAllFINResponsePackets() {
        // Get all ACK packets
        String[] allACKPackets = getAllACKPackets();
        // Move all FIN packets into another list
        ArrayList<String> finPackets = new ArrayList<String>();
        for (String ackPacket : allACKPackets) {
            if (ackPacket.contains("Flags [F.]") && ackPacket.contains("tcp.len==0")) {
                finPackets.add(ackPacket);
            }
        }
        // Make an array list for ACK only packets
        ArrayList<String> ackOnlyPackets = new ArrayList<String>();
        for (String ackPacket : allACKPackets) {
            if (ackPacket.contains("Flags [.]") && ackPacket.contains("tcp.len==0")) {
                ackOnlyPackets.add(ackPacket);
            }
        }
        // Compare the ACK # of ACK only packets with the sequence # of FIN packets. If the ACK # is equal to a FIN sequence #, then it's a response to that FIN & save it to another list
        ArrayList<String> finResponsePackets = new ArrayList<String>();
        for (String finPacket : finPackets) {
            String[] finParts = finPacket.split(" ");
            String finSeqNum = "";
            String finSrcIP = "";
            String finDstIP = "";
            for (int i = 0; i < finParts.length; i++) {
                if (finParts[i].startsWith("seq=")) {
                    finSeqNum = finParts[i].substring(4);
                }
                if (finParts[i].startsWith("IP")) {
                    finSrcIP = finParts[i + 1].split("\\.")[0];
                    finDstIP = finParts[i + 3].split("\\.")[0];
                }
            }
            for (String ackPacket : ackOnlyPackets) {
                String[] ackParts = ackPacket.split(" ");
                String ackNum = "";
                String ackSrcIP = "";
                String ackDstIP = "";
                for (int j = 0; j < ackParts.length; j++) {
                    if (ackParts[j].startsWith("ack=")) {
                        ackNum = ackParts[j].substring(4);
                    }
                    if (ackParts[j].startsWith("IP")) {
                        ackSrcIP = ackParts[j + 1].split("\\.")[0];
                        ackDstIP = ackParts[j + 3].split("\\.")[0];
                    }
                }
                if (ackNum.equals(finSeqNum) && ackSrcIP.equals(finDstIP) && ackDstIP.equals(finSrcIP)) {
                    finResponsePackets.add(ackPacket);
                }
            }
        }
        return finResponsePackets.toArray(new String[]{});
    }

    public static String[] getAllServerFINPackets() {
        setFilterExpression(4); // Index 4 corresponds to FIN packets
        executeTSharkExpression();
        String[] listOfFINPackets = readTSharkAnalyzedOutput();
        // Filter only server FIN packets (assuming server IP is different from client IP)
        ArrayList<String> serverFINPackets = new ArrayList<String>();
        for (String finPacket : listOfFINPackets) {
            if (!finPacket.contains(clientHostIPAddress)) {
                serverFINPackets.add(finPacket);
            }
        }
        return serverFINPackets.toArray(new String[]{});
    }


    public static String[] getAllFINACKPackets() {
        setFilterExpression(3); // Index 3 corresponds to FIN-ACK packets
        executeTSharkExpression();
        String[] listOfFINACKPackets = readTSharkAnalyzedOutput();
        return listOfFINACKPackets;
    }

    public static String[] getAllClientFINACKResponsePackets() {
        // Get all ACK packets
        String[] allACKPackets = getAllACKPackets();
        // Move all FIN-ACK packets into another list
        ArrayList<String> finAckPackets = new ArrayList<String>();
        for (String ackPacket : allACKPackets) {
            if (ackPacket.contains("Flags [F.]") && ackPacket.contains("tcp.len==0")) {
                finAckPackets.add(ackPacket);
            }
        }
        // Make an array list for ACK only packets
        ArrayList<String> ackOnlyPackets = new ArrayList<String>();
        for (String ackPacket : allACKPackets) {
            if (ackPacket.contains("Flags [.]") && ackPacket.contains("tcp.len==0")) {
                ackOnlyPackets.add(ackPacket);
            }
        }
        // Compare the ACK # of ACK only packets with the sequence # of FIN-ACK packets. If the ACK # is equal to a FIN-ACK sequence #, then it's a response to that FIN-ACK & save it to another list
        ArrayList<String> finAckResponsePackets = new ArrayList<String>();
        for (String finAckPacket : finAckPackets) {
            String[] finAckParts = finAckPacket.split(" ");
            String finAckSeqNum = "";
            String finAckSrcIP = "";
            String finAckDstIP = "";
            for (int i = 0; i < finAckParts.length; i++) {
                if (finAckParts[i].startsWith("seq=")) {
                    finAckSeqNum = finAckParts[i].substring(4);
                }
                if (finAckParts[i].startsWith("IP")) {
                    finAckSrcIP = finAckParts[i + 1].split("\\.")[0];
                    finAckDstIP = finAckParts[i + 3].split("\\.")[0];
                }
            }
            for (String ackPacket : ackOnlyPackets) {
                String[] ackParts = ackPacket.split(" ");
                String ackNum = "";
                String ackSrcIP = "";
                String ackDstIP = "";
                for (int j = 0; j < ackParts.length; j++) {
                    if (ackParts[j].startsWith("ack=")) {
                        ackNum = ackParts[j].substring(4);
                    }
                    if (ackParts[j].startsWith("IP")) {
                        ackSrcIP = ackParts[j + 1].split("\\.")[0];
                        ackDstIP = ackParts[j + 3].split("\\.")[0];
                    }
                }
                if (ackNum.equals(finAckSeqNum) && ackSrcIP.equals(finAckDstIP) && ackDstIP.equals(finAckSrcIP)) {
                    finAckResponsePackets.add(ackPacket);
                }
            }
        }
        return finAckResponsePackets.toArray(new String[]{});
    }

    public static String[] getSYNPacketsWithClientServerIPAddresses() {
        // Build the filter expression in the array
        readPacketsByIPAddress[indexOfIPSrcInFilter_1] = clientHostIPAddress;
        readPacketsByIPAddress[indexOfIPDstInFilter_1] = IPAddressesClientHostTalksWith[0];
        readPacketsByIPAddress[indexOfIPSrcInFilter_2] = IPAddressesClientHostTalksWith[0];
        readPacketsByIPAddress[indexOfIPDstInFilter_2] = clientHostIPAddress;
        // Concatenate the array elements to form the final filter string
        readFilterString = String.join("", readPacketsByIPAddress);
        // Append the SYN packet filter
        readFilterString = "(" + readFilterString + ") && tcp.flags.syn==1 && tcp.flags.ack==0";
        executeTSharkExpression();
        String[] listOfSYNPackets = readTSharkAnalyzedOutput();
        return listOfSYNPackets;
    }

    public static String[] getMSSFromPackets() {
        setFilterExpression(8); // Index 8 corresponds to SYN packets
        // Append the MSS option filter
        readFilterString = readFilterString + " && tcp.options.mss";
        executeTSharkExpression();
        String[] listOfMSSPackets = readTSharkAnalyzedOutput();
        return listOfMSSPackets;
    }

    public static String[] getMTUFromPackets() {
        setFilterExpression(8); // Index 8 corresponds to SYN packets
        // Append the MTU option filter
        readFilterString = readFilterString + " && ip.len";
        executeTSharkExpression();
        String[] listOfMTUPackets = readTSharkAnalyzedOutput();
        return listOfMTUPackets;
    }

    public static String[] getAllPortsUsedByHosts() {
        setFilterExpression(0); // Index 0 corresponds to ACK packets
        // Append the port extraction filter
        readFilterString = readFilterString + " && (tcp.srcport || tcp.dstport)";
        executeTSharkExpression();
        String[] listOfPortsUsedByHosts = readTSharkAnalyzedOutput();
        return listOfPortsUsedByHosts;
    }
    
    private static void executeTSharkExpression() {
        // Execute the tshark command using the constructed filter expression
        resetTsharkExpression();
        // First, consolidate all pcap files into one
        moveAllPCAPFilesTo1File();
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"cmd", "/C", tsharkExpression});
            process.waitFor();
            try {
                Thread.sleep(500); // Wait for 0.5 seconds to ensure TShark has finished writing the output file
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String[] readTSharkAnalyzedOutput() {
        // Read the analyzed output file generated by TShark
        // Create a list to store the strings
        ArrayList<String> output = new ArrayList<String>();
        try (BufferedReader br = new BufferedReader(new FileReader(filePatternWhereDataIsSaved + "_analyzed.txt"))) {
            String line;
            while ((line = br.readLine()) != null) {
                output.add(line);
            }
            br.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return output.toArray(new String[]{});
    }

    private static void moveAllPCAPFilesTo1File() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"cmd", "/C", prepareFileForProcessingExpression});
            process.waitFor();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        // Example usage
        String[] synPackets = TCPTrafficAnalyzer.getAllSYNPackets();

        System.out.println("SYN Packets:");
        for (String packet : synPackets) {
            System.out.println(packet);
        }
    }
}
