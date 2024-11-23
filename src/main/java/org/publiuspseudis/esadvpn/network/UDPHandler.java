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

import org.publiuspseudis.esadvpn.network.IPPacket;
import org.publiuspseudis.esadvpn.core.NetworkStack;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code UDPHandler} class manages the processing of UDP packets within the peer-to-peer (P2P) VPN network.
 * It operates in user space, handling the parsing, verification, and routing of UDP packets based on port bindings.
 * This class ensures that incoming UDP packets are correctly dispatched to the appropriate handlers and facilitates
 * the sending of UDP packets to designated destinations through the network stack.
 * </p>
 * 
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Binding UDP ports to specific packet handlers, enabling customized processing of UDP traffic.</li>
 *   <li>Parsing and validating UDP packet headers, including source and destination ports, packet length, and checksum.</li>
 *   <li>Verifying the integrity of UDP packets using checksums to ensure data integrity.</li>
 *   <li>Routing incoming UDP packets to the appropriate handlers based on destination ports.</li>
 *   <li>Facilitating the sending of UDP packets to target IP addresses and ports through the network stack.</li>
 *   <li>Managing port bindings and ensuring thread-safe access to shared resources.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Initialize NetworkStack instance
 * NetworkStack networkStack = new NetworkStack();
 * 
 * // Initialize UDPHandler with the network stack
 * UDPHandler udpHandler = new UDPHandler(networkStack);
 * 
 * // Define a packet handler for a specific UDP port
 * UDPHandler.PacketHandler handler = (payload, sourceIP, sourcePort) -> {
 *     // Process the received UDP payload
 *     String message = new String(payload.array(), StandardCharsets.UTF_8);
 *     System.out.println("Received UDP message from " + sourceIP + ":" + sourcePort + " - " + message);
 * };
 * 
 * // Bind the handler to UDP port 8080
 * boolean success = udpHandler.bind(8080, handler);
 * if (success) {
 *     System.out.println("Successfully bound UDP handler to port 8080.");
 * } else {
 *     System.out.println("Failed to bind UDP handler to port 8080.");
 * }
 * 
 * // Sending a UDP packet
 * String message = "Hello, UDP!";
 * ByteBuffer payload = ByteBuffer.wrap(message.getBytes(StandardCharsets.UTF_8));
 * int sourcePort = 8080;
 * int destIP = InetAddress.getByName("192.168.1.100").hashCode(); // Example destination IP
 * int destPort = 9090;
 * udpHandler.sendPacket(sourcePort, destIP, destPort, payload);
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>
 * </p>
 * <p>
 * The {@code UDPHandler} class is designed to be thread-safe. It utilizes concurrent data structures such as
 * {@link ConcurrentHashMap} to manage port bindings, ensuring safe access and modification in multi-threaded
 * environments. Additionally, the class handles synchronization implicitly through the use of thread-safe
 * collections, allowing multiple threads to interact with the handler without risking data inconsistencies.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>{@link NetworkStack}: Facilitates the sending of IP packets, serving as the underlying network interface.</li>
 *   <li>SLF4J Logging Framework: Used for logging informational, debug, and error messages.</li>
 * </ul>
 * 
 * @author
 * Publius Pseudis
 */
public class UDPHandler {
    /**
     * Logger instance for logging informational, debug, and error messages.
     */
    private static final Logger log = LoggerFactory.getLogger(UDPHandler.class);
    
    // UDP header offsets
    /**
     * Offset for the source port field in the UDP header.
     */
    private static final int SRC_PORT_OFFSET = 0;
    
    /**
     * Offset for the destination port field in the UDP header.
     */
    private static final int DST_PORT_OFFSET = 2;
    
    /**
     * Offset for the length field in the UDP header.
     */
    private static final int LENGTH_OFFSET = 4;
    
    /**
     * Offset for the checksum field in the UDP header.
     */
    private static final int CHECKSUM_OFFSET = 6;
    
    /**
     * Total size of the UDP header in bytes.
     */
    private static final int UDP_HEADER_SIZE = 8;
    
    /**
     * Reference to the {@link NetworkStack} instance used for sending UDP packets.
     */
    private final NetworkStack networkStack;
    
    /**
     * A thread-safe map that maintains bindings between UDP ports and their corresponding handlers.
     * The key is the UDP port number, and the value is the associated {@link PortBinding}.
     */
    private final Map<Integer, PortBinding> portBindings;
    
    /**
     * Constructs a new {@code UDPHandler} with the specified network stack.
     *
     * @param networkStack The {@link NetworkStack} instance used for sending UDP packets.
     */
    public UDPHandler(NetworkStack networkStack) {
        this.networkStack = networkStack;
        this.portBindings = new ConcurrentHashMap<>();
    }
    
    /**
     * Represents a binding between a UDP port and its associated packet handler.
     */
    private static class PortBinding {
        /**
         * The UDP port number to which this binding applies.
         */
        final int port;
        
        /**
         * The handler responsible for processing incoming UDP packets on the bound port.
         */
        final PacketHandler handler;
        
        /**
         * Constructs a new {@code PortBinding} with the specified port and handler.
         *
         * @param port    The UDP port number.
         * @param handler The {@link PacketHandler} responsible for processing packets on this port.
         */
        PortBinding(int port, PacketHandler handler) {
            this.port = port;
            this.handler = handler;
        }
    }
    
    /**
     * <p>
     * The {@code PacketHandler} interface defines the contract for handling incoming UDP packets.
     * Implementations of this interface process the payload of UDP packets received on bound ports.
     * </p>
     * 
     * <p>
     * <strong>Example Implementation:</strong>
     * </p>
     * <pre>{@code
     * UDPHandler.PacketHandler handler = (payload, sourceIP, sourcePort) -> {
     *     // Convert payload to string and print
     *     String message = new String(payload.array(), StandardCharsets.UTF_8);
     *     System.out.println("Received from " + sourceIP + ":" + sourcePort + " - " + message);
     * };
     * }</pre>
     */
    public interface PacketHandler {
        /**
         * Handles an incoming UDP packet's payload.
         *
         * @param payload     A {@code ByteBuffer} containing the UDP packet's payload data.
         * @param sourceIP    An {@code int} representing the source IP address of the packet.
         * @param sourcePort  An {@code int} representing the source port number of the packet.
         */
        void handlePacket(ByteBuffer payload, int sourceIP, int sourcePort);
    }
    
    /**
     * Binds a {@link PacketHandler} to a specific UDP port. Once bound, incoming UDP packets on the
     * specified port will be dispatched to the provided handler.
     *
     * @param port     The UDP port number to bind the handler to. Must be in the range 0-65535.
     * @param handler  The {@link PacketHandler} instance responsible for processing packets on this port.
     * @return {@code true} if the binding was successful; {@code false} if the port is already bound.
     * @throws IllegalArgumentException If the specified port number is outside the valid range (0-65535).
     */
    public boolean bind(int port, PacketHandler handler) {
        if (port < 0 || port > 65535) {
            throw new IllegalArgumentException("Invalid port: " + port);
        }
        
        if (portBindings.containsKey(port)) {
            log.warn("Attempted to bind to already bound port {}", port);
            return false;
        }
        
        portBindings.put(port, new PortBinding(port, handler));
        log.debug("Bound UDP handler to port {}", port);
        return true;
    }
    
    /**
     * Unbinds a {@link PacketHandler} from a specific UDP port. After unbinding, incoming UDP packets
     * on the specified port will no longer be dispatched to the handler.
     *
     * @param port The UDP port number to unbind the handler from.
     */
    public void unbind(int port) {
        if (portBindings.remove(port) != null) {
            log.debug("Unbound UDP handler from port {}", port);
        } else {
            log.warn("Attempted to unbind from non-bound port {}", port);
        }
    }
    
    /**
     * Handles an incoming UDP packet by parsing its header, validating its integrity, and dispatching
     * it to the appropriate {@link PacketHandler} based on the destination port.
     *
     * @param ipPacket The {@link IPPacket} representing the received UDP packet.
     */
    public void handlePacket(IPPacket ipPacket) {
        ByteBuffer udpData = ipPacket.getPayload();
        if (udpData.remaining() < UDP_HEADER_SIZE) {
            log.warn("UDP packet too small from {}", IPPacket.formatIP(ipPacket.getSourceIP()));
            return;
        }
        
        // Parse UDP header
        int sourcePort = udpData.getShort(SRC_PORT_OFFSET) & 0xFFFF;
        int destPort = udpData.getShort(DST_PORT_OFFSET) & 0xFFFF;
        int length = udpData.getShort(LENGTH_OFFSET) & 0xFFFF;
        
        // Basic validation
        if (length != udpData.remaining()) {
            log.warn("Invalid UDP length from {}:{}", 
                IPPacket.formatIP(ipPacket.getSourceIP()), sourcePort);
            return;
        }
        
        // Verify checksum if present
        int checksum = udpData.getShort(CHECKSUM_OFFSET) & 0xFFFF;
        if (checksum != 0 && !verifyChecksum(ipPacket)) {
            log.warn("Invalid UDP checksum from {}:{}", 
                IPPacket.formatIP(ipPacket.getSourceIP()), sourcePort);
            return;
        }
        
        // Find port binding
        PortBinding binding = portBindings.get(destPort);
        if (binding != null) {
            // Extract payload
            ByteBuffer payload = udpData.duplicate();
            payload.position(UDP_HEADER_SIZE);
            payload = payload.slice();
            
            // Handle packet
            binding.handler.handlePacket(payload, ipPacket.getSourceIP(), sourcePort);
        } else {
            log.debug("No handler for UDP port {} from {}:{}", 
                destPort, IPPacket.formatIP(ipPacket.getSourceIP()), sourcePort);
        }
    }
    
    /**
     * Sends a UDP packet to a specified destination IP and port. This method constructs the UDP header,
     * appends the payload, and dispatches the packet through the network stack.
     *
     * @param sourcePort The source UDP port number from which the packet is sent.
     * @param destIP     An {@code int} representing the destination IP address.
     * @param destPort   The destination UDP port number to which the packet is sent.
     * @param payload    A {@code ByteBuffer} containing the payload data to be sent.
     */
    public void sendPacket(int sourcePort, int destIP, int destPort, ByteBuffer payload) {
        // Create UDP header
        ByteBuffer udpPacket = ByteBuffer.allocate(UDP_HEADER_SIZE + payload.remaining());
        
        // Source port
        udpPacket.putShort((short) sourcePort);
        
        // Destination port
        udpPacket.putShort((short) destPort);
        
        // Length
        udpPacket.putShort((short) (UDP_HEADER_SIZE + payload.remaining()));
        
        // Checksum (initially 0; checksum calculation can be added if needed)
        udpPacket.putShort((short) 0);
        
        // Payload
        udpPacket.put(payload.duplicate());
        udpPacket.flip();
        
        // Create IP packet and send through network stack
        networkStack.sendPacket(IPPacket.PROTO_UDP, destIP, udpPacket);
        log.debug("Sent UDP packet from port {} to {}:{} with {} bytes of payload", 
            sourcePort, IPPacket.formatIP(destIP), destPort, payload.remaining());
    }
    
    /**
     * Verifies the integrity of a received UDP packet by recalculating its checksum and comparing it
     * to the checksum provided in the packet header.
     *
     * @param packet The {@link IPPacket} representing the received UDP packet.
     * @return {@code true} if the checksum is valid or not present; {@code false} otherwise.
     */
    private boolean verifyChecksum(IPPacket packet) {
        // UDP checksum includes pseudo-header
        ByteBuffer udpData = packet.getPayload();
        int originalChecksum = udpData.getShort(CHECKSUM_OFFSET) & 0xFFFF;
        
        // If checksum is 0, it wasn't calculated (optional in IPv4)
        if (originalChecksum == 0) {
            return true;
        }
        
        // Calculate checksum including pseudo-header
        ByteBuffer extended = ByteBuffer.allocate(udpData.remaining() + 12);
        
        // Pseudo-header
        extended.putInt(packet.getSourceIP());
        extended.putInt(packet.getDestinationIP());
        extended.put((byte) 0);
        extended.put((byte) packet.getProtocol());
        extended.putShort((short) udpData.remaining());
        
        // UDP data with checksum field set to 0
        udpData = udpData.duplicate();
        udpData.putShort(CHECKSUM_OFFSET, (short) 0);
        extended.put(udpData);
        extended.flip();
        
        // Calculate checksum
        int sum = 0;
        while (extended.hasRemaining()) {
            if (extended.remaining() >= 2) {
                sum += extended.getShort() & 0xFFFF;
            } else {
                sum += (extended.get() & 0xFF) << 8;
            }
        }
        
        // Add carry bits
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        
        return (short) ~sum == originalChecksum;
    }
}
