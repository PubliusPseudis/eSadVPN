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

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
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
    private static final int DEFAULT_RATE_LIMIT = 1000; // packets per second

    /**
     * A map of IP addresses to their corresponding rate limiters.
     * Used to prevent abuse by limiting the rate of packet handling
     * for each source IP.
     */
    private final Map<String, RateLimiter> rateLimiters = new ConcurrentHashMap<>();

    private static final int MAX_PACKET_SIZE = 65536;
    private static final int DEFAULT_BUFFER_SIZE = 1500;  // Standard MTU
    private static final int MAX_BUFFERS = 8192;         // Much larger pool

    /**
     * Access control list for managing outbound connections.
     * Ensures that outgoing traffic complies with configured rules
     * such as port restrictions and per-host connection limits.
     */
    private final OutboundACL outboundACL = new OutboundACL();

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
     * Handler for processing ICMP (Internet Control Message Protocol) packets,
     * including echo requests and replies (commonly used in "ping").
     */
    private final ICMPHandler icmpHandler = new ICMPHandler();
    
    /**
     * Pool of reusable {@link ByteBuffer} instances to optimize memory usage and reduce
     * garbage collection overhead.
     */
    private final BufferPool bufferPool;
    
    private static final int MIN_PACKET_SIZE = 20;    // Minimum valid IP header
    
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
        this.bufferPool = new BufferPool(MAX_BUFFERS, DEFAULT_BUFFER_SIZE);
        this.executor = Executors.newFixedThreadPool(2);
        this.running = true;
        this.address = address;
        // Start packet processors
        executor.submit(this::processInbound);
        executor.submit(this::processOutbound);
    }
    
    /**
     * Retrieves the {@link RateLimiter} instance associated with a given IP address,
     * creating a new one if it does not already exist.
     *
     * @param address The IP address as a {@code String}.
     * @return The {@link RateLimiter} instance for the specified IP.
     */
    private RateLimiter getRateLimiter(String address) {
        return rateLimiters.computeIfAbsent(address, 
            addr -> new RateLimiter(DEFAULT_RATE_LIMIT));
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
        int emptyCount = 0;
        while (running) {
            ByteBuffer buffer = null;
            try {
                buffer = virtualInterface.read();
                if (buffer != null) {
                    ByteBuffer workBuffer = bufferPool.acquire();
                    workBuffer.put(buffer);
                    workBuffer.flip();
                    handlePacket(workBuffer);
                    emptyCount = 0;
                } else {
                    emptyCount++;
                    // Exponential backoff with max delay of 100ms
                    long sleepTime = Math.min(1L * emptyCount, 100L);
                    Thread.sleep(sleepTime);
                }
            } catch (InterruptedException e) {
                log.warn("Buffer acquisition interrupted");
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("Error processing inbound packet: {}", e.getMessage());
            } finally {
                if (buffer != null) {
                    bufferPool.release(buffer);
                }
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
        int emptyCount = 0;
        while (running) {
            ByteBuffer buffer = null;
            try {
                // Get next packet from router with timeout
                ByteBuffer packet = router.getNextPacket();
                if (packet != null) {
                    buffer = bufferPool.acquire();
                    buffer.put(packet);
                    buffer.flip();
                    virtualInterface.write(buffer);
                    emptyCount = 0;
                } else {
                    emptyCount++;
                    // Exponential backoff with max delay of 100ms
                    long sleepTime = Math.min(1L * emptyCount, 100L);
                    Thread.sleep(sleepTime);
                }
            } catch (InterruptedException e) {
                log.warn("Buffer acquisition interrupted");
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("Error processing outbound packet: {}", e.getMessage());
            } finally {
                if (buffer != null) {
                    bufferPool.release(buffer);
                }
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
        ByteBuffer workBuffer = null;
        try {
            // Basic sanity checks
            if (buffer == null || !buffer.hasRemaining()) {
                return;
            }

            // Size validation for IPv4
            int packetSize = buffer.remaining();
            if (packetSize < MIN_PACKET_SIZE || packetSize > MAX_PACKET_SIZE) {
                log.warn("Invalid packet size: {}", packetSize);
                return;
            }

            // Make safe copy using buffer pool
            workBuffer = bufferPool.acquire();
            workBuffer.put(buffer.duplicate());
            workBuffer.flip();

            IPPacket packet = new IPPacket(workBuffer);

            
            // Verify IP header
            if (!packet.verifyChecksum()) {
                log.warn("Invalid IP checksum from {}", 
                    IPPacket.formatIP(packet.getSourceIP()));
                return;
            }

            // Apply rate limiting per source IP
            String sourceAddr = IPPacket.formatIP(packet.getSourceIP());
            RateLimiter limiter = getRateLimiter(sourceAddr);
            
            if (!limiter.tryAcquire()) {
                log.warn("Rate limit exceeded for {}", sourceAddr);
                return;
            }

            // Handle based on protocol
            switch (packet.getProtocol()) {
                case IPPacket.PROTO_UDP -> {
                    ByteBuffer payload = packet.getPayload();
                    if (payload == null || payload.remaining() < 8) {
                        log.warn("Invalid UDP packet from {}", sourceAddr);
                        return;
                    }
                    udpHandler.handlePacket(packet);
                }
                    
                case IPPacket.PROTO_ICMP -> {
                    ByteBuffer icmp = packet.getPayload();
                    if (icmp == null || icmp.remaining() < 8) {
                        log.warn("Invalid ICMP packet from {}", sourceAddr);
                        return;
                    }
                    handleICMP(packet);
                }
                    
                default -> {
                    if (log.isDebugEnabled()) {
                        log.debug("Unsupported protocol: {} from {}", 
                            packet.getProtocol(), sourceAddr);
                    }
                }
            }

            // Clean up old rate limiters periodically
            if (Math.random() < 0.001) { // 0.1% chance per packet
                cleanupRateLimiters();
            }

        } catch (InterruptedException e) {
            log.warn("Buffer acquisition interrupted");
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.error("Error handling packet: {}", e.getMessage());
        } finally {
            if (workBuffer != null) {
                bufferPool.release(workBuffer);
            }
        }
    }
 
    /**
    * Cleans up rate limiters for IP addresses that have not sent traffic
    * in a predefined interval (5 minutes by default). Helps to conserve
    * memory by removing unused rate limiter entries.
    */
    private void cleanupRateLimiters() {
        // Remove rate limiters for addresses we haven't seen in a while
        long now = System.currentTimeMillis();
        rateLimiters.entrySet().removeIf(entry -> 
            now - entry.getValue().getLastUsedTime() > TimeUnit.MINUTES.toMillis(5));
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

        ByteBuffer buffer = null;
        DatagramSocket internetSocket = null;
        String destAddr = null;

        try {
            ByteBuffer payload = packet.getPayload();
            destAddr = IPPacket.formatIP(packet.getDestinationIP());

            // Get socket info from payload
            int originalSrcPort = payload.getShort(0) & 0xFFFF;
            int destPort = payload.getShort(2) & 0xFFFF;

            // Check ACL before creating socket
            if (!outboundACL.isAllowed(destAddr, destPort)) {
                log.warn("Outbound connection to {}:{} blocked by ACL", destAddr, destPort);
                return;
            }

            // Get actual data with position handling
            payload.position(4);
            ByteBuffer data = payload.slice();

            // Create controlled socket
            internetSocket = createManagedSocket();

            // Send the data
            byte[] sendData = new byte[data.remaining()];
            data.get(sendData);

            // Validate destination address
            InetAddress inetAddr = InetAddress.getByName(destAddr);
            if (inetAddr.isLoopbackAddress() || inetAddr.isLinkLocalAddress() || 
                inetAddr.isSiteLocalAddress() || inetAddr.isMulticastAddress()) {
                log.warn("Rejected connection attempt to restricted address: {}", destAddr);
                return;
            }

            DatagramPacket sendPacket = new DatagramPacket(
                sendData, 
                sendData.length, 
                inetAddr, 
                destPort
            );
            internetSocket.send(sendPacket);

            // Wait for response with timeout
            byte[] receiveData = new byte[MAX_PACKET_SIZE];
            DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            internetSocket.setSoTimeout(5000);  // 5 second timeout
            internetSocket.receive(receivePacket);

            // Process response
            ByteBuffer responseBuffer = bufferPool.acquire();
            try {
                responseBuffer.putShort((short)originalSrcPort);
                responseBuffer.putShort((short)destPort);
                responseBuffer.put(receiveData, 0, receivePacket.getLength());
                responseBuffer.flip();

                // Route response
                String sourceAddr = IPPacket.formatIP(packet.getSourceIP());
                String nextHop = router.getNextHop(sourceAddr);
                if (nextHop != null) {
                    IPPacket response = IPPacket.create(
                        IPPacket.PROTO_UDP,
                        parseIP(destAddr),
                        parseIP(sourceAddr),
                        responseBuffer
                    );
                    router.routePacket(response.getPacket(), nextHop);
                }
            } finally {
                bufferPool.release(responseBuffer);
            }

        } catch (IOException | InterruptedException e) {
            log.error("Error handling outbound traffic to {}: {}", destAddr, e.getMessage());
        } finally {
            if (internetSocket != null) {
                internetSocket.close();
                if (destAddr != null) {
                    outboundACL.releaseSocket(destAddr);
                }
            }
        }
    }
    
    /**
     * Creates a managed {@link DatagramSocket} with specific configurations to enhance security and performance.
     *
     * <p>
     * The socket is configured to allow address reuse, set with a timeout, and assigned appropriate
     * buffer sizes to handle standard network traffic efficiently.
     * </p>
     *
     * @return A configured {@link DatagramSocket} instance.
     * @throws SocketException If the socket could not be opened, or the socket could not bind to the specified local port.
     */
    private DatagramSocket createManagedSocket() throws SocketException {
        DatagramSocket socket = new DatagramSocket();
        socket.setReuseAddress(true);
        socket.setSoTimeout(5000);  // 5 second timeout

        // Set socket options for security
        socket.setTrafficClass(0x04);  // IPTOS_RELIABILITY

        // Set reasonable send/receive buffer sizes
        socket.setSendBufferSize(DEFAULT_BUFFER_SIZE);
        socket.setReceiveBufferSize(DEFAULT_BUFFER_SIZE);

        return socket;
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
        icmpHandler.handleICMP(packet, router);
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
        rateLimiters.clear();
        try {
            // Let current operations finish
            try (virtualInterface) {
                // Let current operations finish
                Thread.sleep(100);
                // Log final stats
                log.info("Buffer pool stats at shutdown: {}", bufferPool.getStats());
            }
        } catch (Exception e) {
            log.error("Error closing network stack: {}", e.getMessage());
        } finally {
            executor.shutdownNow();
        }
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
        ByteBuffer buffer = null;
        try {
            buffer = bufferPool.acquire();
            buffer.put(packet.duplicate());
            buffer.flip();
            handlePacket(buffer);
        } catch (InterruptedException e) {
            log.warn("Buffer acquisition interrupted");
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.error("Error processing incoming packet: {}", e.getMessage());
        } finally {
            if (buffer != null) {
                bufferPool.release(buffer);
            }
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
        ByteBuffer buffer = null;
        try {
            buffer = bufferPool.acquire();
            buffer.put(packet.duplicate());
            buffer.flip();
            virtualInterface.write(buffer);
        } catch (InterruptedException e) {
            log.warn("Buffer acquisition interrupted");
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.error("Error injecting packet: {}", e.getMessage());
        } finally {
            if (buffer != null) {
                bufferPool.release(buffer);
            }
        }
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

        ByteBuffer buffer = null;
        try {
            // Copy payload to working buffer
            buffer = bufferPool.acquire();
            buffer.put(payload.duplicate());
            buffer.flip();

            log.info("Handling outbound traffic to {}", destAddr);

            // Extract ports and data
            short sourcePort = buffer.getShort(0);
            short destPort = buffer.getShort(2);
            buffer.position(4);  // Move position past the ports
            ByteBuffer data = buffer.slice();  // Create slice from current position

            // Let UDPHandler deal with the actual UDP communication
            udpHandler.sendPacket(
                sourcePort & 0xFFFF,
                destIP,
                destPort & 0xFFFF,
                data
            );
        } catch (InterruptedException e) {
            log.warn("Buffer acquisition interrupted");
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            log.error("Error handling outbound traffic: {}", e.getMessage());
        } finally {
            if (buffer != null) {
                bufferPool.release(buffer);
            }
        }
    }
    
    /**
     * Thread-safe pool of reusable {@link ByteBuffer} instances.
     * Implements backpressure to ensure that memory usage remains
     * within predefined limits while providing performance benefits
     * by reducing garbage collection overhead.
     *
     * <p>Maintains a pool of pre-allocated buffers and dynamically
     * grows/shrinks based on demand, up to a configurable maximum size.</p>
     *
     * <p><strong>Usage:</strong></p>
     * <pre>{@code
     * BufferPool pool = new BufferPool(100, 1500);
     * ByteBuffer buffer = pool.acquire();
     * try {
     *     // Use buffer
     * } finally {
     *     pool.release(buffer);
     * }
     * }</pre>
     */
    private static final class BufferPool {
           private final Queue<ByteBuffer> availableBuffers;
           private final Set<ByteBuffer> inUseBuffers;
           private final int maxBuffers;
           private final int bufferSize;
           private final AtomicInteger totalCreated = new AtomicInteger(0);
           private final AtomicInteger waitingThreads = new AtomicInteger(0);

           private static final long BUFFER_WAIT_TIMEOUT = TimeUnit.SECONDS.toNanos(5);

           /**
            * Constructs a new {@code BufferPool} with specified maximum buffers and buffer size.
            *
            * @param maxBuffers The maximum number of buffers that can be created.
            * @param bufferSize The size of each buffer in bytes.
            */
           public BufferPool(int maxBuffers, int bufferSize) {
               this.maxBuffers = maxBuffers;
               this.bufferSize = bufferSize;
               this.availableBuffers = new ConcurrentLinkedQueue<>();
               this.inUseBuffers = ConcurrentHashMap.newKeySet();

               // Pre-allocate initial buffers
               for (int i = 0; i < maxBuffers / 4; i++) {
                   availableBuffers.offer(ByteBuffer.allocateDirect(bufferSize));
                   totalCreated.incrementAndGet();
               }
           }

           /**
            * Acquires a {@link ByteBuffer} from the pool. If no buffers are available and the pool
            * has not reached its maximum size, a new buffer is created. Otherwise, the method waits
            * until a buffer becomes available or a timeout occurs.
            *
            * @return A {@link ByteBuffer} instance ready for use.
            * @throws InterruptedException If the thread is interrupted while waiting for a buffer.
            */
           public ByteBuffer acquire() throws InterruptedException {
               waitingThreads.incrementAndGet();
               try {
                   long deadline = System.nanoTime() + BUFFER_WAIT_TIMEOUT;

                   while (true) {
                       // Try to get an available buffer
                       ByteBuffer buffer = availableBuffers.poll();
                       if (buffer != null) {
                           inUseBuffers.add(buffer);
                           buffer.clear();
                           return buffer;
                       }

                       // If we can create a new buffer, do so
                       if (totalCreated.get() < maxBuffers) {
                           if (totalCreated.incrementAndGet() <= maxBuffers) {
                               buffer = ByteBuffer.allocateDirect(bufferSize);
                               inUseBuffers.add(buffer);
                               return buffer;
                           }
                           totalCreated.decrementAndGet();
                       }

                       // Wait for a buffer to become available
                       long timeLeft = deadline - System.nanoTime();
                       if (timeLeft <= 0) {
                           throw new InterruptedException("Buffer acquisition timeout");
                       }
                       // Exponential backoff
                       Thread.sleep(Math.min(100, Math.max(1, 1000_000 - timeLeft/1000_000)));
                   }
               } finally {
                   waitingThreads.decrementAndGet();
               }
           }

           /**
            * Releases a {@link ByteBuffer} back to the pool, making it available for reuse.
            *
            * @param buffer The {@link ByteBuffer} to be released.
            */
           public void release(ByteBuffer buffer) {
               if (buffer != null && inUseBuffers.remove(buffer)) {
                   buffer.clear();
                   availableBuffers.offer(buffer);
               }
           }

           /**
            * Cleans up excess buffers that are not frequently used.
            *
            * <p>
            * This method reduces the number of available buffers to a quarter of the maximum
            * size, ensuring that memory usage remains optimal.
            * </p>
            */
           public void cleanup() {
               // Only clean up if no threads are waiting
               if (waitingThreads.get() == 0) {
                   int excess = availableBuffers.size() - (maxBuffers / 4);
                   if (excess > 0) {
                       for (int i = 0; i < excess; i++) {
                           ByteBuffer buffer = availableBuffers.poll();
                           if (buffer == null) break;
                           totalCreated.decrementAndGet();
                       }
                   }
               }
           }

           /**
            * Retrieves statistics about the current state of the buffer pool.
            *
            * @return A {@link Map} containing statistics such as total buffers, available buffers,
            *         in-use buffers, and waiting threads.
            */
           public Map<String, Number> getStats() {
               Map<String, Number> stats = new HashMap<>();
               stats.put("totalBuffers", totalCreated.get());
               stats.put("availableBuffers", availableBuffers.size());
               stats.put("inUseBuffers", inUseBuffers.size());
               stats.put("waitingThreads", waitingThreads.get());
               return stats;
           }
       }
    
    /**
    * Outbound access control list for managing external connections.
    *
    * <p>Provides granular control over outbound traffic by enforcing
    * per-host and global socket limits, as well as port-based filtering.</p>
    *
    * <p><strong>Key Features:</strong></p>
    * <ul>
    *   <li>Restricts the number of concurrent connections per destination.</li>
    *   <li>Imposes a global limit on total open sockets to prevent resource exhaustion.</li>
    *   <li>Blocks connections to disallowed ports or addresses.</li>
    * </ul>
    */
    private static class OutboundACL {
        private static final int MAX_SOCKETS_PER_HOST = 8;
        private static final int MAX_TOTAL_SOCKETS = 256;
        private static final long SOCKET_CLEANUP_INTERVAL = TimeUnit.MINUTES.toMillis(1);

        // Default allowed ports - can be made configurable
        private static final Set<Integer> DEFAULT_ALLOWED_PORTS = Set.of(
            53,    // DNS
            80,    // HTTP
            443,   // HTTPS
            3478,  // STUN
            5349   // STUN/TLS
        );

        private final Set<Integer> allowedPorts;
        private final Map<String, AtomicInteger> socketCountsByHost;
        private final AtomicInteger totalSockets;
        private volatile long lastCleanup;
        private final Object cleanupLock = new Object();

        /**
         * Constructs a new {@code OutboundACL} instance with default allowed ports and initializes
         * internal tracking structures for socket management.
         */
        public OutboundACL() {
            this.allowedPorts = ConcurrentHashMap.newKeySet();
            this.allowedPorts.addAll(DEFAULT_ALLOWED_PORTS);
            this.socketCountsByHost = new ConcurrentHashMap<>();
            this.totalSockets = new AtomicInteger(0);
            this.lastCleanup = System.currentTimeMillis();
        }

        /**
         * Determines whether an outbound connection to a specified address and port is allowed
         * based on current ACL rules.
         *
         * <p>
         * The method checks if the destination port is allowed, ensures that the global socket
         * limit has not been exceeded, and verifies that the per-host socket limit is not breached.
         * If all checks pass, the method increments the relevant counters and permits the connection.
         * </p>
         *
         * @param destAddr The destination address as a {@code String}.
         * @param destPort The destination port as an {@code int}.
         * @return {@code true} if the connection is allowed; {@code false} otherwise.
         */
        public boolean isAllowed(String destAddr, int destPort) {
            // Check if port is allowed
            if (!allowedPorts.contains(destPort)) {
                return false;
            }

            // Check total socket limit
            if (totalSockets.get() >= MAX_TOTAL_SOCKETS) {
                cleanup(); // Try cleanup before rejecting
                if (totalSockets.get() >= MAX_TOTAL_SOCKETS) {
                    return false;
                }
            }

            // Check per-host socket limit
            AtomicInteger hostCount = socketCountsByHost.computeIfAbsent(destAddr, 
                k -> new AtomicInteger(0));

            if (hostCount.get() >= MAX_SOCKETS_PER_HOST) {
                cleanup(); // Try cleanup before rejecting
                if (hostCount.get() >= MAX_SOCKETS_PER_HOST) {
                    return false;
                }
            }

            // Track socket allocation
            hostCount.incrementAndGet();
            totalSockets.incrementAndGet();
            return true;
        }

        /**
         * Releases a previously allowed outbound connection, decrementing the relevant
         * socket counters for the specified destination address.
         *
         * @param destAddr The destination address as a {@code String}.
         */
        public void releaseSocket(String destAddr) {
            AtomicInteger hostCount = socketCountsByHost.get(destAddr);
            if (hostCount != null) {
                hostCount.decrementAndGet();
            }
            totalSockets.decrementAndGet();
        }

        /**
         * Cleans up outdated socket counts by removing entries for hosts that no longer have active connections.
         *
         * <p>
         * This method is invoked periodically to ensure that the internal tracking structures do not
         * retain stale information, thereby conserving memory and maintaining accurate connection counts.
         * </p>
         */
        private void cleanup() {
            long now = System.currentTimeMillis();
            if (now - lastCleanup < SOCKET_CLEANUP_INTERVAL) {
                return;
            }

            synchronized (cleanupLock) {
                if (now - lastCleanup < SOCKET_CLEANUP_INTERVAL) {
                    return;
                }

                socketCountsByHost.entrySet().removeIf(entry -> 
                    entry.getValue().get() <= 0);

                lastCleanup = now;
            }
        }
    }
    
    /**
    * Handles ICMP packet processing, including echo requests (ping).
    *
    * <p>Provides rate limiting to prevent abuse and mitigates replay/spoofing
    * attacks by tracking recent requests.</p>
    *
    * <p><strong>Responsibilities:</strong></p>
    * <ul>
    *   <li>Processes ICMP echo requests and generates appropriate replies.</li>
    *   <li>Implements rate limiting for incoming ICMP packets on a per-IP basis.</li>
    *   <li>Maintains a cache of recent requests to detect duplicates or replays.</li>
    * </ul>
    */
    private static class ICMPHandler {
        private static final int ICMP_ECHO_REQUEST = 8;
        private static final int ICMP_ECHO_REPLY = 0;

        // Rate limiting for ICMP
        private static final int ICMP_RATE_LIMIT = 100;  // packets per second
        private final Map<String, RateLimiter> icmpLimiters = new ConcurrentHashMap<>();

        // Track ICMP echo requests to prevent spoofing/replay
        private static final int MAX_TRACKED_REQUESTS = 1000;
        private final Map<ICMPIdentifier, Long> recentRequests = new ConcurrentHashMap<>();
        private volatile long lastCleanup = System.currentTimeMillis();
        private static final long CLEANUP_INTERVAL = TimeUnit.MINUTES.toMillis(1);

        /**
         * Inner class representing a unique identifier for ICMP echo requests.
         * Combines the source IP address, identifier, and sequence number.
         */
        private static class ICMPIdentifier {
            final String sourceIP;
            final int id;
            final int sequence;

            /**
             * Constructs a new {@code ICMPIdentifier} with the specified source IP, identifier, and sequence number.
             *
             * @param sourceIP The source IP address as a {@code String}.
             * @param id       The ICMP identifier.
             * @param sequence The ICMP sequence number.
             */
            ICMPIdentifier(String sourceIP, int id, int sequence) {
                this.sourceIP = sourceIP;
                this.id = id;
                this.sequence = sequence;
            }

            @Override
            public boolean equals(Object o) {
                if (this == o) return true;
                if (!(o instanceof ICMPIdentifier)) return false;
                ICMPIdentifier that = (ICMPIdentifier) o;
                return id == that.id && 
                       sequence == that.sequence && 
                       sourceIP.equals(that.sourceIP);
            }

            @Override
            public int hashCode() {
                return Objects.hash(sourceIP, id, sequence);
            }
        }

        /**
         * Handles an incoming ICMP packet by determining its type and processing it accordingly.
         *
         * <p>
         * For ICMP echo requests (type 8), this method generates and routes an echo reply.
         * It also implements rate limiting and request tracking to prevent abuse.
         * </p>
         *
         * @param packet The {@link IPPacket} representing the incoming ICMP message.
         * @param router The {@link SwarmRouter} used for routing the ICMP reply.
         */
        void handleICMP(IPPacket packet, SwarmRouter router) {
            ByteBuffer icmp = packet.getPayload();
            if (icmp == null || icmp.remaining() < 8) {
                return;
            }

            String sourceIP = IPPacket.formatIP(packet.getSourceIP());

            // Apply rate limiting
            RateLimiter limiter = icmpLimiters.computeIfAbsent(sourceIP,
                addr -> new RateLimiter(ICMP_RATE_LIMIT));

            if (!limiter.tryAcquire()) {
                log.warn("ICMP rate limit exceeded for {}", sourceIP);
                return;
            }

            // Clean up old tracked requests
            cleanupTracking();

            int type = icmp.get(0) & 0xFF;
            int code = icmp.get(1) & 0xFF;

            switch (type) {
                case ICMP_ECHO_REQUEST -> handleEchoRequest(packet, icmp, router);
                // Add other ICMP types as needed
                default -> log.debug("Unsupported ICMP type: {}", type);
            }
        }

        /**
         * Handles an ICMP echo request by generating and routing an echo reply.
         *
         * <p>
         * This method extracts the ICMP identifier and sequence number from the request,
         * checks for duplicate or replayed requests, and constructs an appropriate echo reply
         * if the request is valid and not a duplicate.
         * </p>
         *
         * @param packet   The {@link IPPacket} representing the incoming ICMP echo request.
         * @param icmp     The {@link ByteBuffer} containing the ICMP payload.
         * @param router   The {@link SwarmRouter} used for routing the ICMP reply.
         */
        private void handleEchoRequest(IPPacket packet, ByteBuffer icmp, SwarmRouter router) {
            // Extract ICMP header fields
            int id = icmp.getShort(4) & 0xFFFF;
            int sequence = icmp.getShort(6) & 0xFFFF;
            String sourceIP = IPPacket.formatIP(packet.getSourceIP());

            // Create identifier for this request
            ICMPIdentifier identifier = new ICMPIdentifier(sourceIP, id, sequence);

            // Check if we've seen this request recently
            Long lastSeen = recentRequests.get(identifier);
            if (lastSeen != null && 
                System.currentTimeMillis() - lastSeen < TimeUnit.SECONDS.toMillis(60)) {
                log.warn("Duplicate ICMP request from {} (ID: {}, Seq: {})", 
                    sourceIP, id, sequence);
                return;
            }

            // Track this request
            if (recentRequests.size() < MAX_TRACKED_REQUESTS) {
                recentRequests.put(identifier, System.currentTimeMillis());
            }

            // Create reply
            ByteBuffer reply = ByteBuffer.allocate(icmp.remaining());
            reply.put(icmp.duplicate());
            reply.flip();

            // Modify header for reply
            reply.put(0, (byte)ICMP_ECHO_REPLY);  // Change type to reply
            reply.put(1, (byte)0);                // Code 0
            reply.putShort(2, (short)0);          // Clear checksum

            // Calculate new checksum
            int checksum = calculateICMPChecksum(reply);
            reply.putShort(2, (short)checksum);

            // Send reply
            String destAddr = IPPacket.formatIP(packet.getSourceIP());
            String nextHop = router.getNextHop(destAddr);
            if (nextHop != null) {
                router.routePacket(reply, nextHop);
            }
        }

        /**
         * Cleans up tracked ICMP echo requests and rate limiters by removing entries that are older than the defined interval.
         *
         * <p>
         * This method helps in preventing the internal tracking structures from growing indefinitely,
         * thereby conserving memory and maintaining accurate tracking of recent requests.
         * </p>
         */
        private void cleanupTracking() {
            long now = System.currentTimeMillis();
            if (now - lastCleanup > CLEANUP_INTERVAL) {
                synchronized (this) {
                    if (now - lastCleanup > CLEANUP_INTERVAL) {
                        recentRequests.entrySet().removeIf(entry ->
                            now - entry.getValue() > TimeUnit.MINUTES.toMillis(5));
                        icmpLimiters.entrySet().removeIf(entry ->
                            now - entry.getValue().getLastUsedTime() > TimeUnit.MINUTES.toMillis(5));
                        lastCleanup = now;
                    }
                }
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
        private static int calculateICMPChecksum(ByteBuffer data) {
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
    }

}
