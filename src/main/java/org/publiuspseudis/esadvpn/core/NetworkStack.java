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
package org.publiuspseudis.esadvpn.core;

import org.publiuspseudis.esadvpn.core.VirtualInterface;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.publiuspseudis.esadvpn.network.IPPacket;
import org.publiuspseudis.esadvpn.routing.SwarmRouter;
import org.publiuspseudis.esadvpn.network.UDPHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code NetworkStack} class coordinates the userspace network stack components within the VPN framework.
 * It manages the flow of network packets between the virtual network interface and the underlying network protocols,
 * handling tasks such as packet processing, NAT translation, routing, and protocol-specific operations.
 * </p>
 *
 * <p>
 * This class integrates various components like {@link VirtualInterface}, {@link UDPHandler}, and {@link SwarmRouter}
 * to facilitate seamless communication within the VPN. It employs multi-threading to handle inbound and outbound
 * packet processing concurrently, ensuring efficient network traffic management.
 * </p>
 *
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Reading packets from the virtual network interface.</li>
 *   <li>Handling inbound and outbound network traffic.</li>
 *   <li>Managing NAT translations for VPN traffic.</li>
 *   <li>Processing protocol-specific packets such as UDP and ICMP.</li>
 *   <li>Routing packets using the {@link SwarmRouter} component.</li>
 *   <li>Sending and receiving ping (ICMP) responses.</li>
 *   <li>Providing NAT and routing statistics.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Initialize SwarmRouter (assuming it's properly defined)
 * SwarmRouter router = new SwarmRouter();
 * 
 * // Initialize NetworkStack with address and router
 * NetworkStack networkStack = new NetworkStack("10.0.0.1", router);
 * 
 * // Sending a UDP packet
 * ByteBuffer payload = ByteBuffer.wrap("Hello, World!".getBytes());
 * networkStack.sendPacket(IPPacket.PROTO_UDP, InetAddress.getByName("8.8.8.8").hashCode(), payload);
 * 
 * // Injecting a received packet into the network stack
 * ByteBuffer receivedPacket = ByteBuffer.wrap(receivedData);
 * networkStack.injectPacket(receivedPacket);
 * 
 * // Closing the network stack when done
 * networkStack.close();
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>  
 * The {@code NetworkStack} class is designed to be thread-safe, utilizing concurrent data structures and
 * synchronized operations where necessary. It employs an {@code ExecutorService} to manage separate threads
 * for inbound and outbound packet processing, ensuring that network operations do not block each other.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>{@link VirtualInterface}: Manages the virtual network interface for reading and writing packets.</li>
 *   <li>{@link UDPHandler}: Handles UDP-specific packet processing and communication.</li>
 *   <li>{@link SwarmRouter}: Manages routing of packets within the VPN network.</li>
 *   <li>SLF4J Logging Framework: Utilized for logging events and debugging.</li>
 * </ul>
 * 
 * @author
 * Publius Pseudis
 * 
 * @version 1.0
 * @since 2024-01-01
 */
public class NetworkStack implements AutoCloseable {
    /**
     * Logger instance for logging information, warnings, and errors.
     */
    private static final Logger log = LoggerFactory.getLogger(NetworkStack.class);
    
    /**
     * The virtual network interface used for reading and writing packets.
     */
    private final VirtualInterface virtualInterface;
    
    /**
     * The UDP handler responsible for processing UDP packets.
     */
    private final UDPHandler udpHandler;
    
    /**
     * Executor service managing the threads for inbound and outbound packet processing.
     */
    private final ExecutorService executor;
    
    /**
     * The router responsible for determining the next hop for packet routing.
     */
    private final SwarmRouter router;
    
    /**
     * The address associated with this network stack instance.
     */
    private final String address;  
    
    /**
     * Flag indicating whether the network stack is currently running.
     */
    private volatile boolean running;
    
    /**
     * Constructs a new {@code NetworkStack} instance with the specified address and router.
     *
     * <p>
     * Initializes the virtual network interface, UDP handler, and router. It also sets up
     * an executor service with a fixed thread pool to handle inbound and outbound packet
     * processing concurrently. The network stack starts in the running state, and the
     * provided address is stored for reference.
     * </p>
     *
     * @param address The IP address associated with this network stack instance.
     * @param router  The {@link SwarmRouter} instance used for routing packets.
     */
    public NetworkStack(String address, SwarmRouter router) {
        this.virtualInterface = new VirtualInterface(address, 1500);
        this.udpHandler = new UDPHandler(this);
        this.router = router;
        this.executor = Executors.newFixedThreadPool(2);
        this.running = true;
        this.address = address;
        // Start packet processors
        executor.submit(this::processInbound);
        executor.submit(this::processOutbound);
    }
    
    /**
     * Retrieves the address associated with this network stack instance.
     *
     * @return A {@code String} representing the IP address.
     */
    public String getAddress() {
        return address;
    }
    
    /**
     * Processes inbound packets from the virtual network interface.
     *
     * <p>
     * This method continuously reads packets from the virtual interface and delegates
     * them to the {@link #handlePacket(ByteBuffer)} method for further processing.
     * It runs on a separate thread managed by the executor service.
     * </p>
     */
    private void processInbound() {
        while (running) {
            try {
                ByteBuffer packet = virtualInterface.read();
                if (packet != null) {
                    handlePacket(packet);
                }
            } catch (Exception e) {
                log.error("Error processing inbound packet: {}", e.getMessage());
            }
        }
    }
    
    /**
     * Processes outbound packets by retrieving them from the router and writing
     * them to the virtual network interface.
     *
     * <p>
     * This method continuously fetches packets from the {@link SwarmRouter}'s queue and
     * writes them to the virtual interface for transmission. It runs on a separate thread
     * managed by the executor service.
     * </p>
     */
    private void processOutbound() {
        while (running) {
            try {
                // Get next packet from router
                ByteBuffer packet = router.getNextPacket();
                if (packet != null) {
                    virtualInterface.write(packet);
                }
            } catch (Exception e) {
                log.error("Error processing outbound packet: {}", e.getMessage());
            }
        }
    }
    
    /**
     * Handles an incoming IP packet by verifying its checksum, determining its protocol,
     * and processing it accordingly.
     *
     * <p>
     * Depending on the protocol of the IP packet (e.g., UDP, ICMP), this method delegates
     * the packet to the appropriate handler. If the network stack is acting as an exit node,
     * it handles internet-bound traffic; otherwise, it routes VPN-bound traffic using the
     * {@link SwarmRouter}.
     * </p>
     *
     * @param buffer The {@link ByteBuffer} containing the raw IP packet data.
     */
    private void handlePacket(ByteBuffer buffer) {
        try {
            IPPacket packet = new IPPacket(buffer);
            
            // Verify IP header
            if (!packet.verifyChecksum()) {
                log.warn("Invalid IP checksum from {}", 
                    IPPacket.formatIP(packet.getSourceIP()));
                return;
            }
            
            // Handle based on protocol
            switch (packet.getProtocol()) {
                case IPPacket.PROTO_UDP -> udpHandler.handlePacket(packet);
                    
                case IPPacket.PROTO_ICMP -> handleICMP(packet);
                    
                default -> log.debug("Unsupported protocol: {}", packet.getProtocol());
            }
            
            // If we're the exit node (10.0.0.1) and this is internet-bound traffic
            String destAddr = IPPacket.formatIP(packet.getDestinationIP());
            if (address.equals("10.0.0.1") && !destAddr.startsWith("10.")) {
                // This is internet-bound traffic and we're the exit node
                handleOutboundTraffic(packet);
            } else {
                // Get next hop from router for VPN traffic
                String nextHop = router.getNextHop(destAddr);
                if (nextHop != null) {
                    router.routePacket(packet.getPacket(), nextHop);
                } else {
                    log.debug("No route to {}", destAddr);
                }
            }
            
        } catch (Exception e) {
            log.error("Error handling packet: {}", e.getMessage());
        }
    }

    /**
     * Handles outbound internet-bound traffic by sending UDP packets to external destinations.
     *
     * <p>
     * This method is invoked when the network stack is acting as an exit node and needs to forward
     * VPN traffic to the internet. It extracts the source and destination ports from the payload,
     * sends the data using a {@link DatagramSocket}, waits for a response, and then routes the response
     * back through the VPN.
     * </p>
     *
     * @param packet The {@link IPPacket} representing the outbound internet-bound traffic.
     */
    private void handleOutboundTraffic(IPPacket packet) {
        if (packet.getProtocol() != IPPacket.PROTO_UDP) {
            log.debug("Only UDP is currently supported for internet traffic");
            return;
        }

        try {
            ByteBuffer payload = packet.getPayload();
            String destAddr = IPPacket.formatIP(packet.getDestinationIP());
            log.info("Handling outbound traffic to {}", destAddr);
            
            // Get socket info from payload
            int originalSrcPort = payload.getShort(0) & 0xFFFF;
            int destPort = payload.getShort(2) & 0xFFFF;
            
            // Get actual data
            payload.position(4);
            ByteBuffer data = payload.slice();
            
            try ( // Create new socket for internet traffic
                    DatagramSocket internetSocket = new DatagramSocket()) {
                // Send the data
                byte[] sendData = new byte[data.remaining()];
                data.get(sendData);
                DatagramPacket sendPacket = new DatagramPacket(
                    sendData, 
                    sendData.length, 
                    InetAddress.getByName(destAddr), 
                    destPort
                );
                internetSocket.send(sendPacket);
                
                // Wait for response
                byte[] receiveData = new byte[65536];
                DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
                internetSocket.setSoTimeout(5000);  // 5 second timeout
                internetSocket.receive(receivePacket);
                
                // Create response packet
                ByteBuffer responseBuffer = ByteBuffer.allocate(receivePacket.getLength() + 4);
                responseBuffer.putShort((short)originalSrcPort); // Original source port
                responseBuffer.putShort((short)destPort);       // Original dest port
                responseBuffer.put(receiveData, 0, receivePacket.getLength());
                responseBuffer.flip();
                
                // Send response back through VPN
                String sourceAddr = IPPacket.formatIP(packet.getSourceIP());
                String nextHop = router.getNextHop(sourceAddr);
                if (nextHop != null) {
                    byte[] sourceIP = new byte[4];
                    payload.getInt(0); // Original source IP
                    
                    IPPacket response = IPPacket.create(
                        IPPacket.PROTO_UDP,
                        parseIP(destAddr),     // Response source (internet server)
                        parseIP(sourceAddr),   // Response destination (original client)
                        responseBuffer
                    );
                    
                    router.routePacket(response.getPacket(), nextHop);
                }
                
            }
            
        } catch (IOException e) {
            log.error("Error handling outbound traffic: {}", e.getMessage());
        }
    }
    
    /**
     * Handles ICMP messages such as ping (echo requests).
     *
     * <p>
     * This method processes incoming ICMP packets. If an ICMP echo request (ping) is detected,
     * it generates and sends an appropriate echo reply.
     * </p>
     *
     * @param packet The {@link IPPacket} representing the incoming ICMP message.
     */
    private void handleICMP(IPPacket packet) {
        ByteBuffer icmp = packet.getPayload();
        if (icmp.remaining() < 8) return;
        
        // Check if it's an echo request (ping)
        int type = icmp.get(0) & 0xFF;
        if (type == 8) {  // Echo request
            sendPingReply(packet);
        }
    }

    /**
     * Sends an ICMP echo reply in response to an echo request (ping).
     *
     * <p>
     * This method constructs an ICMP echo reply by modifying the type field of the received
     * echo request, recalculates the checksum, and routes the reply back to the original sender
     * through the VPN.
     * </p>
     *
     * @param request The {@link IPPacket} representing the incoming ICMP echo request.
     */
    private void sendPingReply(IPPacket request) {
        ByteBuffer icmp = request.getPayload();
        ByteBuffer reply = ByteBuffer.allocate(icmp.remaining());
        
        // Copy original ping data
        reply.put(icmp.duplicate());
        reply.flip();
        
        // Change ICMP type to reply (0)
        reply.put(0, (byte) 0);
        
        // Clear and recalculate ICMP checksum
        reply.putShort(2, (short) 0);
        int checksum = calculateICMPChecksum(reply);
        reply.putShort(2, (short) checksum);
        
        // Send reply
        String destAddr = IPPacket.formatIP(request.getSourceIP());
        String nextHop = router.getNextHop(destAddr);
        if (nextHop != null) {
            router.routePacket(reply, nextHop);
        }
    }
    
    /**
     * Calculates the ICMP checksum for the given data.
     *
     * <p>
     * The checksum is calculated by summing all 16-bit words in the ICMP message, adding any
     * carry-over bits, and then taking the one's complement of the total sum.
     * </p>
     *
     * @param data The {@link ByteBuffer} containing the ICMP message data.
     * @return The calculated checksum as an integer.
     */
    private int calculateICMPChecksum(ByteBuffer data) {
        int sum = 0;
        int position = data.position();
        data.position(0);
        
        while (data.hasRemaining()) {
            if (data.remaining() >= 2) {
                sum += data.getShort() & 0xFFFF;
            } else {
                sum += (data.get() & 0xFF) << 8;
            }
        }
        
        data.position(position);
        
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        
        return ~sum & 0xFFFF;
    }
    
    /**
     * Sends an IP packet with the specified protocol, destination IP, and payload.
     *
     * <p>
     * This method constructs an {@link IPPacket} with the given parameters and routes it using the
     * {@link SwarmRouter}. If the network stack is acting as an exit node, it handles the packet as
     * outbound internet-bound traffic.
     * </p>
     *
     * @param protocol The protocol number (e.g., {@link IPPacket#PROTO_TCP}, {@link IPPacket#PROTO_UDP}).
     * @param destIP   The destination IP address as an integer.
     * @param payload  The payload data as a {@link ByteBuffer}.
     */
    public void sendPacket(int protocol, int destIP, ByteBuffer payload) {
        try {
            // Parse destination address
            String destAddr = IPPacket.formatIP(destIP);
            
            // Check if we're the exit node (10.0.0.1)
            if (address.equals("10.0.0.1")) {
                // We're the exit node, handle internet traffic
                handleOutboundTraffic(protocol, destAddr, destIP, payload);
                return;
            }
            
            // Get next hop from router
            String nextHop = router.getNextHop(destAddr);
            if (nextHop == null) {
                log.debug("No route to {}", destAddr);
                return;
            }
            
            // Create IP packet
            byte[] sourceIP = parseIP(address);
            byte[] destIPBytes = parseIP(destAddr);
            
            IPPacket packet = IPPacket.create(protocol, sourceIP, destIPBytes, payload);
            
            // Send to router
            router.routePacket(packet.getPacket(), nextHop);
            
        } catch (Exception e) {
            log.error("Error sending packet: {}", e.getMessage());
        }
    }
    
    /**
     * Parses an IP address string into a byte array.
     *
     * <p>
     * Converts a dotted-decimal IP address string (e.g., "192.168.1.1") into a byte array
     * suitable for use in network packets.
     * </p>
     *
     * @param address The IP address as a {@code String}.
     * @return A byte array representing the IP address.
     */
    private byte[] parseIP(String address) {
        String[] parts = address.split("\\.");
        byte[] bytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            bytes[i] = (byte) Integer.parseInt(parts[i]);
        }
        return bytes;
    }
    
    /**
     * Retrieves the UDP handler associated with this network stack.
     *
     * @return The {@link UDPHandler} instance.
     */
    public UDPHandler getUDPHandler() {
        return udpHandler;
    }
    
    /**
     * Closes the network stack, terminating all ongoing processes and releasing resources.
     *
     * <p>
     * This method stops the inbound and outbound packet processing threads, closes the virtual
     * network interface, and shuts down the executor service. It ensures that all resources are
     * properly released to prevent resource leaks.
     * </p>
     */
    @Override
    public void close() {
        running = false;
        try {
            virtualInterface.close();
        } catch (Exception e) {
            log.error("Error closing virtual interface: {}", e.getMessage());
        }
        executor.shutdownNow();
    }
    
    /**
     * Processes an incoming packet by delegating it to the {@link #handlePacket(ByteBuffer)} method.
     *
     * <p>
     * This method can be used to inject packets directly into the network stack for processing,
     * bypassing the virtual network interface. It ensures that only valid packets with remaining
     * data are processed.
     * </p>
     *
     * @param packet The {@link ByteBuffer} containing the raw packet data.
     */
    public void processIncoming(ByteBuffer packet) {
        if (packet == null || !packet.hasRemaining()) {
            return;
        }
        try {
            handlePacket(packet);
        } catch (Exception e) {
            log.error("Error processing incoming packet: {}", e.getMessage());
        }
    }

    /**
     * Injects a packet into the virtual network interface for transmission.
     *
     * <p>
     * This method allows external components to send packets through the virtual network interface.
     * It ensures that the network stack is running and that the packet contains data before writing.
     * </p>
     *
     * @param packet The {@link ByteBuffer} containing the raw packet data to be injected.
     */
    public void injectPacket(ByteBuffer packet) {
        if (!running || packet == null || !packet.hasRemaining()) {
            return;
        }
        virtualInterface.write(packet);
    }
    
    /**
     * Handles outbound internet-bound traffic by sending UDP packets to external destinations.
     *
     * <p>
     * This method is invoked when the network stack is acting as an exit node and needs to forward
     * VPN traffic to the internet. It extracts the source and destination ports from the payload,
     * sends the data using a {@link UDPHandler}, and handles the response.
     * </p>
     *
     * @param protocol   The protocol number (e.g., {@link IPPacket#PROTO_UDP}).
     * @param destAddr   The destination address as a {@code String} in dotted-decimal notation.
     * @param destIP     The destination IP address as an integer.
     * @param payload    The payload data as a {@link ByteBuffer}.
     */
    private void handleOutboundTraffic(int protocol, String destAddr, int destIP, ByteBuffer payload) {
        if (protocol != IPPacket.PROTO_UDP) {
            log.debug("Only UDP is currently supported for internet traffic");
            return;
        }

        try {
            log.info("Handling outbound traffic to {}", destAddr);
            
            // Extract ports and data
            short sourcePort = payload.getShort(0);
            short destPort = payload.getShort(2);
            payload.position(4);  // Move position past the ports
            ByteBuffer data = payload.slice();  // Create slice from current position
            
            // Let UDPHandler deal with the actual UDP communication
            udpHandler.sendPacket(
                sourcePort & 0xFFFF,
                destIP,
                destPort & 0xFFFF,
                data
            );
        } catch (Exception e) {
            log.error("Error handling outbound traffic: {}", e.getMessage());
        }
    }
}
