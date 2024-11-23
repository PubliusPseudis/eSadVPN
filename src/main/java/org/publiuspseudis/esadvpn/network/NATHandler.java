/*
 * Copyright (C) 2024 Publius Pseudis
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.publiuspseudis.esadvpn.network;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code NATHandler} class manages Network Address Translation (NAT) for VPN traffic within the VPN framework.
 * It handles the translation of internal (private) IP addresses and ports to external (public) ones,
 * facilitating seamless communication between VPN peers and external networks.
 * </p>
 *
 * <p>
 * This class maintains NAT mapping tables for both TCP and UDP protocols, ensuring that incoming and outgoing
 * packets are correctly translated and routed. It also manages dynamic port allocation, connection tracking
 * for TCP sessions, and cleanup of expired NAT mappings to optimize resource usage.
 * </p>
 *
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Managing NAT mappings for TCP and UDP protocols.</li>
 *   <li>Allocating dynamic ports within a specified range.</li>
 *   <li>Tracking active TCP connections.</li>
 *   <li>Handling packet translation for both outgoing and incoming packets.</li>
 *   <li>Cleaning up expired NAT mappings based on predefined timeouts.</li>
 *   <li>Providing NAT statistics for monitoring purposes.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Initialize NATHandler
 * NATHandler natHandler = new NATHandler();
 * 
 * // Process an outgoing TCP packet
 * byte[] outgoingPacket = {/* TCP packet data *};
 * String srcSubnet = "192.168.1.";
 * byte[] translatedOutgoingPacket = natHandler.processOutgoingPacket(outgoingPacket, srcSubnet);
 * 
 * // Process an incoming UDP packet
 * byte[] incomingPacket = {/* UDP packet data *};
 * byte[] translatedIncomingPacket = natHandler.processIncomingPacket(incomingPacket);
 * 
 * // Periodically clean up expired mappings
 * natHandler.cleanupExpiredMappings();
 * 
 * // Retrieve NAT statistics
 * Map<String, Object> stats = natHandler.getStats();
 * System.out.println("NAT Statistics: " + stats);
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>  
 * The {@code NATHandler} class is designed to be thread-safe, utilizing concurrent data structures like
 * {@code ConcurrentHashMap} and atomic variables to manage NAT mappings and port allocations. This ensures
 * safe concurrent access in multi-threaded environments.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>SLF4J Logging Framework for logging events and debugging.</li>
 * </ul>
 * 
 * @author
 * Publius Pseudis
 * 
 * @version 1.0
 * @since 2024-01-01
 */
public class NATHandler {
    /**
     * Logger instance for logging information, warnings, and errors.
     */
    private static final Logger log = LoggerFactory.getLogger(NATHandler.class);
    
    /**
     * Mapping of external (public) ports to their corresponding NAT mappings.
     * Utilizes {@code ConcurrentHashMap} for thread-safe operations.
     */
    private final Map<Integer, NATMapping> portMappings = new ConcurrentHashMap<>();
    
    /**
     * Mapping of connection keys to their assigned external ports.
     * Utilizes {@code ConcurrentHashMap} for thread-safe operations.
     */
    private final Map<String, Integer> addressMappings = new ConcurrentHashMap<>();
    
    /**
     * Atomic integer to keep track of the next available dynamic port for NAT mapping.
     */
    private final AtomicInteger nextPort = new AtomicInteger(10000);
    
    /**
     * Timeout duration for UDP NAT mappings in milliseconds.
     * {@code 2} minutes by default.
     */
    private static final long UDP_TIMEOUT = TimeUnit.MINUTES.toMillis(2);
    
    /**
     * Timeout duration for TCP NAT mappings in milliseconds.
     * {@code 15} minutes by default.
     */
    private static final long TCP_TIMEOUT = TimeUnit.MINUTES.toMillis(15);
    
    /**
     * Minimum dynamic port number for NAT mappings.
     */
    private static final int MIN_DYNAMIC_PORT = 10000;
    
    /**
     * Maximum dynamic port number for NAT mappings.
     */
    private static final int MAX_DYNAMIC_PORT = 60000;
    
    /**
     * <p>
     * The {@code NATMapping} class represents a single NAT mapping entry.
     * It stores information about the original and translated IP addresses and ports,
     * the protocol used, timestamps for creation and last usage, and connection state
     * for TCP protocols.
     * </p>
     */
    public static class NATMapping {
        /**
         * Original source IP address before NAT translation.
         */
        public final String originalSrcIP;
        
        /**
         * Original source port before NAT translation.
         */
        public final int originalSrcPort;
        
        /**
         * Original destination IP address before NAT translation.
         */
        public final String originalDstIP;
        
        /**
         * Original destination port before NAT translation.
         */
        public final int originalDstPort;
        
        /**
         * Protocol number (6 for TCP, 17 for UDP).
         */
        public final int protocol;          // 6 for TCP, 17 for UDP
        
        /**
         * Timestamp indicating when the NAT mapping was created.
         */
        public final long creationTime;
        
        /**
         * Timestamp indicating the last time the NAT mapping was used.
         */
        public long lastUsed;
        
        /**
         * Flag indicating whether a TCP connection has been established.
         */
        public boolean tcpEstablished;     // For TCP connection tracking
        
        /**
         * Constructs a new {@code NATMapping} instance with the specified parameters.
         *
         * @param srcIP     The original source IP address.
         * @param srcPort   The original source port.
         * @param dstIP     The original destination IP address.
         * @param dstPort   The original destination port.
         * @param protocol  The protocol number (6 for TCP, 17 for UDP).
         */
        public NATMapping(String srcIP, int srcPort, String dstIP, int dstPort, int protocol) {
            this.originalSrcIP = srcIP;
            this.originalSrcPort = srcPort;
            this.originalDstIP = dstIP;
            this.originalDstPort = dstPort;
            this.protocol = protocol;
            this.creationTime = System.currentTimeMillis();
            this.lastUsed = this.creationTime;
            this.tcpEstablished = false;
        }
    }
    
    /**
     * Processes an outgoing packet for NAT translation.
     *
     * <p>
     * This method translates the source IP address and port of outgoing packets from the
     * internal subnet to externally visible ones. It handles both TCP and UDP protocols,
     * ensuring that the necessary NAT mappings are created or reused. For TCP packets, it
     * also tracks the connection state based on TCP flags.
     * </p>
     *
     * @param packet    The raw outgoing packet data as a byte array.
     * @param srcSubnet The source subnet (e.g., "192.168.1.") to identify internal packets.
     * @return The translated packet as a byte array, or the original packet if no translation is performed.
     */
    public byte[] processOutgoingPacket(byte[] packet, String srcSubnet) {
        if (packet.length < 20) return packet; // Too small for IP header
        
        int protocol = packet[9] & 0xFF;
        if (protocol != 6 && protocol != 17) { // Not TCP/UDP
            return packet;
        }
        
        String srcIP = extractIP(packet, 12);
        String dstIP = extractIP(packet, 16);
        int srcPort = extractPort(packet, 20);
        int dstPort = extractPort(packet, 22);
        
        // Skip if source is not from our managed subnet
        if (!srcIP.startsWith(srcSubnet)) {
            return packet;
        }
        
        // Create or get NAT mapping
        String connectionKey = String.format("%s:%d-%s:%d/%d", 
            srcIP, srcPort, dstIP, dstPort, protocol);
        
        int mappedPort = addressMappings.computeIfAbsent(connectionKey, k -> {
            int port = createPortMapping(srcIP, srcPort, dstIP, dstPort, protocol);
            log.debug("Created new NAT mapping: {} -> :{}", connectionKey, port);
            return port;
        });
        
        // Update last used timestamp
        NATMapping mapping = portMappings.get(mappedPort);
        if (mapping != null) {
            mapping.lastUsed = System.currentTimeMillis();
            
            // Track TCP connection state
            if (protocol == 6) { // TCP
                int tcpFlags = packet[33] & 0xFF;
                boolean isSYN = (tcpFlags & 0x02) != 0;
                boolean isFIN = (tcpFlags & 0x01) != 0;
                boolean isRST = (tcpFlags & 0x04) != 0;
                
                if (isSYN && !mapping.tcpEstablished) {
                    mapping.tcpEstablished = true;
                } else if ((isFIN || isRST) && mapping.tcpEstablished) {
                    mapping.tcpEstablished = false;
                }
            }
        }
        
        // Create modified packet with NAT translation
        byte[] modifiedPacket = packet.clone();
        
        // Update source port
        modifiedPacket[20] = (byte) ((mappedPort >> 8) & 0xFF);
        modifiedPacket[21] = (byte) (mappedPort & 0xFF);
        
        // Recalculate checksums
        updateChecksums(modifiedPacket);
        
        return modifiedPacket;
    }
    
    /**
     * Processes an incoming packet for NAT translation.
     *
     * <p>
     * This method translates the destination IP address and port of incoming packets from
     * externally visible ones back to their original internal addresses and ports. It handles
     * both TCP and UDP protocols, ensuring that the NAT mappings are correctly applied.
     * For TCP packets, it also updates the connection state based on TCP flags.
     * </p>
     *
     * @param packet The raw incoming packet data as a byte array.
     * @return The translated packet as a byte array, or {@code null} if no valid NAT mapping is found.
     */
    public byte[] processIncomingPacket(byte[] packet) {
        if (packet.length < 20) return null;
        
        int protocol = packet[9] & 0xFF;
        if (protocol != 6 && protocol != 17) {
            return packet;
        }
        
        int dstPort = extractPort(packet, 22);
        NATMapping mapping = portMappings.get(dstPort);
        
        if (mapping == null) {
            return null; // No NAT mapping found
        }
        
        // Update last used timestamp
        mapping.lastUsed = System.currentTimeMillis();
        
        // Create modified packet with original addresses
        byte[] modifiedPacket = packet.clone();
        
        // Restore original destination IP and port
        writeIP(modifiedPacket, 16, mapping.originalSrcIP);
        writePort(modifiedPacket, 22, mapping.originalSrcPort);
        
        // Handle TCP connection tracking
        if (protocol == 6) {
            int tcpFlags = packet[33] & 0xFF;
            boolean isFIN = (tcpFlags & 0x01) != 0;
            boolean isRST = (tcpFlags & 0x04) != 0;
            
            if ((isFIN || isRST) && mapping.tcpEstablished) {
                mapping.tcpEstablished = false;
            }
        }
        
        // Recalculate checksums
        updateChecksums(modifiedPacket);
        
        return modifiedPacket;
    }
    
    /**
     * Creates a new NAT mapping for a given connection.
     *
     * <p>
     * This method attempts to reuse an existing NAT mapping if one exists for the specified
     * connection. If no such mapping exists, it allocates a new external port and creates a
     * new {@code NATMapping} entry.
     * </p>
     *
     * @param srcIP     The original source IP address.
     * @param srcPort   The original source port.
     * @param dstIP     The original destination IP address.
     * @param dstPort   The original destination port.
     * @param protocol  The protocol number (6 for TCP, 17 for UDP).
     * @return The allocated external port number for NAT mapping.
     */
    private int createPortMapping(String srcIP, int srcPort, String dstIP, int dstPort, int protocol) {
        // Try to reuse existing mapping if possible
        for (Map.Entry<Integer, NATMapping> entry : portMappings.entrySet()) {
            NATMapping mapping = entry.getValue();
            if (mapping.originalSrcIP.equals(srcIP) && 
                mapping.originalSrcPort == srcPort &&
                mapping.originalDstIP.equals(dstIP) &&
                mapping.originalDstPort == dstPort &&
                mapping.protocol == protocol) {
                return entry.getKey();
            }
        }
        
        // Create new mapping
        int mappedPort = allocatePort();
        portMappings.put(mappedPort, new NATMapping(srcIP, srcPort, dstIP, dstPort, protocol));
        return mappedPort;
    }
    
    /**
     * Allocates a new external port for NAT mapping within the dynamic port range.
     *
     * <p>
     * This method increments the {@code nextPort} atomic integer to obtain the next available
     * port. If the port exceeds the maximum dynamic port, it wraps around to the minimum dynamic port.
     * It ensures that the allocated port is not already in use within the {@code portMappings}.
     * </p>
     *
     * @return An available external port number for NAT mapping.
     */
    private int allocatePort() {
        while (true) {
            int port = nextPort.incrementAndGet();
            if (port > MAX_DYNAMIC_PORT) {
                nextPort.set(MIN_DYNAMIC_PORT);
                port = nextPort.incrementAndGet();
            }
            if (!portMappings.containsKey(port)) {
                return port;
            }
        }
    }
    
    /**
     * Cleans up expired NAT mappings based on predefined timeout durations.
     *
     * <p>
     * This method iterates through the existing NAT mappings and removes those that have
     * not been used within their respective timeout periods. For UDP mappings, the timeout
     * is {@code UDP_TIMEOUT}, and for TCP mappings, it is {@code TCP_TIMEOUT}. Additionally,
     * TCP mappings with established connections are not expired.
     * </p>
     */
    public void cleanupExpiredMappings() {
        long now = System.currentTimeMillis();
        
        portMappings.entrySet().removeIf(entry -> {
            NATMapping mapping = entry.getValue();
            long timeout = mapping.protocol == 17 ? UDP_TIMEOUT : TCP_TIMEOUT;
            
            boolean expired = now - mapping.lastUsed > timeout;
            
            // For TCP, also check connection state
            if (mapping.protocol == 6 && mapping.tcpEstablished) {
                expired = false; // Don't expire established TCP connections
            }
            
            if (expired) {
                String key = String.format("%s:%d-%s:%d/%d",
                    mapping.originalSrcIP, mapping.originalSrcPort,
                    mapping.originalDstIP, mapping.originalDstPort,
                    mapping.protocol);
                addressMappings.remove(key);
                
                log.debug("Removed expired NAT mapping: {} -> :{}", 
                    key, entry.getKey());
            }
            
            return expired;
        });
    }
    
    /**
     * Extracts an IP address from the packet data starting at the specified offset.
     *
     * @param packet The raw packet data as a byte array.
     * @param offset The byte offset where the IP address starts.
     * @return A {@code String} representing the extracted IP address in dotted-decimal notation.
     */
    private String extractIP(byte[] packet, int offset) {
        return String.format("%d.%d.%d.%d",
            packet[offset] & 0xFF,
            packet[offset + 1] & 0xFF,
            packet[offset + 2] & 0xFF,
            packet[offset + 3] & 0xFF);
    }
    
    /**
     * Extracts a port number from the packet data starting at the specified offset.
     *
     * @param packet The raw packet data as a byte array.
     * @param offset The byte offset where the port number starts.
     * @return An integer representing the extracted port number.
     */
    private int extractPort(byte[] packet, int offset) {
        return ((packet[offset] & 0xFF) << 8) | (packet[offset + 1] & 0xFF);
    }
    
    /**
     * Writes an IP address into the packet data at the specified offset.
     *
     * @param packet The raw packet data as a byte array.
     * @param offset The byte offset where the IP address should be written.
     * @param ip     The IP address as a {@code String} in dotted-decimal notation.
     */
    private void writeIP(byte[] packet, int offset, String ip) {
        String[] parts = ip.split("\\.");
        for (int i = 0; i < 4; i++) {
            packet[offset + i] = (byte) Integer.parseInt(parts[i]);
        }
    }
    
    /**
     * Writes a port number into the packet data at the specified offset.
     *
     * @param packet The raw packet data as a byte array.
     * @param offset The byte offset where the port number should be written.
     * @param port   The port number to write.
     */
    private void writePort(byte[] packet, int offset, int port) {
        packet[offset] = (byte) ((port >> 8) & 0xFF);
        packet[offset + 1] = (byte) (port & 0xFF);
    }
    
    /**
     * Updates the checksums of the modified packet to ensure data integrity.
     *
     * <p>
     * This method recalculates the IP header checksum after any modifications to the packet.
     * It sets the checksum field to zero, calculates the new checksum by summing all 16-bit words,
     * adding any carry-over bits, and then taking the one's complement of the sum. The calculated
     * checksum is then written back into the packet.
     * </p>
     *
     * @param packet The modified packet data as a byte array.
     */
    private void updateChecksums(byte[] packet) {
        // Clear existing checksums
        packet[10] = packet[11] = 0; // IP header checksum
        
        // Calculate IP header checksum
        int ipLength = (packet[0] & 0x0F) * 4;
        int sum = 0;
        
        for (int i = 0; i < ipLength; i += 2) {
            sum += ((packet[i] & 0xFF) << 8) | (packet[i + 1] & 0xFF);
        }
        
        // Add carry bits
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        
        int ipChecksum = ~sum & 0xFFFF;
        packet[10] = (byte) ((ipChecksum >> 8) & 0xFF);
        packet[11] = (byte) (ipChecksum & 0xFF);
        
        // Let the kernel handle TCP/UDP checksums as they require pseudo-header
        // Most modern NICs also support checksum offloading
    }
    
    /**
     * Retrieves the current NAT statistics, including total mappings,
     * active TCP and UDP connections, and port usage statistics.
     *
     * @return A {@code Map<String, Object>} containing various NAT statistics.
     */
    public Map<String, Object> getStats() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalMappings", portMappings.size());
        
        // Count active TCP/UDP connections
        long tcpCount = portMappings.values().stream()
            .filter(m -> m.protocol == 6).count();
        long udpCount = portMappings.values().stream()
            .filter(m -> m.protocol == 17).count();
            
        stats.put("activeTCP", tcpCount);
        stats.put("activeUDP", udpCount);
        
        // Get port usage statistics
        stats.put("nextAvailablePort", nextPort.get());
        stats.put("portPoolSize", MAX_DYNAMIC_PORT - MIN_DYNAMIC_PORT);
        stats.put("portPoolUsage", 
            String.format("%.2f%%", 
                (double)portMappings.size() / (MAX_DYNAMIC_PORT - MIN_DYNAMIC_PORT) * 100));
                
        return stats;
    }

    
    /**
     * Constructs a new {@code NATHandler} instance.
     *
     * <p>
     * Initializes the NAT handler, setting up necessary configurations and resources
     * required for managing NAT operations within the P2P VPN network.
     * </p>
     */
    public NATHandler() {}
}
