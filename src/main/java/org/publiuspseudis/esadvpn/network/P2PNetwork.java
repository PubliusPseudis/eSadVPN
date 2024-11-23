package org.publiuspseudis.esadvpn.network;

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

import org.publiuspseudis.esadvpn.protocol.GossipMessage;
import org.publiuspseudis.esadvpn.crypto.ProofOfWork;
import org.publiuspseudis.esadvpn.core.NetworkStack;
import org.publiuspseudis.esadvpn.core.VPNConnection;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.publiuspseudis.esadvpn.routing.RouteInfo;
import org.publiuspseudis.esadvpn.routing.SwarmRouter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code P2PNetwork} class represents a peer-to-peer (P2P) network node within the VPN framework.
 * It handles the establishment and management of connections with peers, routing of network packets,
 * NAT (Network Address Translation) handling, proof-of-work verification, and periodic maintenance tasks
 * such as gossiping and proof updates. This class integrates various components like {@link NetworkStack},
 * {@link SwarmRouter}, {@link NATHandler}, and utilizes multithreading to ensure efficient and concurrent
 * operations.
 * </p>
 *
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Establishing and managing peer connections.</li>
 *   <li>Routing network packets between peers using pheromone-based routing metrics.</li>
 *   <li>Handling NAT translations for incoming and outgoing packets.</li>
 *   <li>Maintaining network health by ensuring a minimum number of active peers.</li>
 *   <li>Periodic tasks including gossiping, proof-of-work updates, keepalive messages, and logging statistics.</li>
 *   <li>Providing diagnostics and network state export/import functionalities.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Initialize P2PNetwork as an initiator node
 * int port = 8080;
 * boolean isInitiator = true;
 * P2PNetwork p2pNetwork = new P2PNetwork(port, isInitiator);
 * 
 * // Start the network node
 * p2pNetwork.start();
 * 
 * // Connect to a peer
 * p2pNetwork.connectToPeer("192.168.1.100", 8081);
 * 
 * // Retrieve network statistics
 * Map<String, Object> stats = p2pNetwork.getNetworkStats();
 * System.out.println("Network Stats: " + stats);
 * 
 * // Run diagnostics
 * String diagnostics = p2pNetwork.runDiagnostics();
 * System.out.println(diagnostics);
 * 
 * // Close the network node when done
 * p2pNetwork.close();
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>  
 * The {@code P2PNetwork} class is designed to be thread-safe, utilizing concurrent data structures like
 * {@link ConcurrentHashMap} and synchronized operations where necessary. It employs an {@code ExecutorService}
 * and a {@code ScheduledExecutorService} to manage asynchronous tasks, ensuring that network operations
 * do not block each other and are handled efficiently.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>{@link NetworkStack}: Manages the virtual network interface and packet processing.</li>
 *   <li>{@link SwarmRouter}: Handles routing decisions based on pheromone metrics.</li>
 *   <li>{@link NATHandler}: Manages NAT translations for network packets.</li>
 *   <li>{@link ProofOfWork}: Handles proof-of-work generation and verification.</li>
 *   <li>{@link GossipMessage}: Manages gossip protocol messages for peer discovery and routing information sharing.</li>
 *   <li>SLF4J Logging Framework: Utilized for logging events and debugging.</li>
 * </ul>
 * 
 * @author
 * Publius Pseudis
 * 
 * @version 1.0
 * @since 2024-01-01
 */
public final class P2PNetwork implements GossipMessage.GossipHandler, AutoCloseable {
    /**
     * Logger instance for logging information, warnings, and errors.
     */
    private static final Logger log = LoggerFactory.getLogger(P2PNetwork.class);
    
    // Network components
    /**
     * The {@link NetworkStack} instance managing the virtual network interface and packet processing.
     */
    private final NetworkStack networkStack;
    
    /**
     * The {@link SwarmRouter} instance responsible for determining the next hop for routing packets.
     */
    private final SwarmRouter router;
    
    /**
     * The {@link ServerSocket} used for listening to incoming peer connection requests.
     */
    private final ServerSocket serverSocket;
    
    /**
     * A thread-safe map storing active peers identified by their node IDs.
     */
    private final Map<ByteBuffer, Peer> peers;
    
    /**
     * The {@link NATHandler} instance managing NAT translations for network packets.
     */
    private final NATHandler natHandler;
    
    // Identity and security
    /**
     * The unique node ID generated for this P2P network node.
     */
    private final byte[] nodeId;
    
    /**
     * The IP address associated with this network node.
     */
    private final String ipAddress;
    
    /**
     * The {@link ProofOfWork} instance managing proof-of-work generation and verification.
     */
    private final ProofOfWork pow;
    
    /**
     * The port number on which this network node listens for peer connections.
     */
    private final int port;
    
    // Configuration constants
    /**
     * The maximum number of peers this node can connect to simultaneously.
     */
    private static final int MAX_PEERS = 10;
    
    /**
     * The minimum number of peers required to maintain network health.
     */
    private static final int MIN_PEERS = 3;
    
    /**
     * The socket timeout duration in milliseconds for peer connections.
     */
    private static final int SOCKET_TIMEOUT = 30000;
    
    /**
     * The number of connection retry attempts when attempting to connect to a peer.
     */
    private static final int CONNECTION_RETRY_COUNT = 3;
    
    // Threading and scheduling
    /**
     * The {@link ScheduledExecutorService} for scheduling periodic maintenance tasks.
     */
    private final ScheduledExecutorService scheduler;
    
    /**
     * The {@link ExecutorService} for handling asynchronous tasks such as peer connections and packet routing.
     */
    private final ExecutorService executor;
    
    /**
     * A flag indicating whether the network node is currently running.
     */
    private volatile boolean running;
    
    // Statistics and metrics
    /**
     * A thread-safe map tracking the number of bytes sent to each peer.
     */
    private final Map<String, Long> bytesSent;
    
    /**
     * A thread-safe map tracking the number of bytes received from each peer.
     */
    private final Map<String, Long> bytesReceived;
    
    /**
     * The timestamp marking when the network node was started.
     */
    private final long startTime;
    
    /**
     * A flag indicating whether this node is the initiator of the network.
     */
    private final boolean isInitiator;


    /**
     * An interface for handling new peer connections.
     */
    public interface ConnectionHandler {
        /**
         * Callback method invoked when a new connection is established with a peer.
         *
         * @param address The IP address of the connected peer.
         * @param port    The port number of the connected peer.
         * @param conn    The {@link VPNConnection} instance representing the connection.
         */
        void onNewConnection(String address, int port, VPNConnection conn);
    }

    /**
     * The handler for managing new connections.
     */
    private ConnectionHandler connectionHandler;

    /**
     * Sets the {@link ConnectionHandler} for handling new peer connections.
     *
     * @param handler The {@link ConnectionHandler} implementation to be set.
     */
    public void setConnectionHandler(ConnectionHandler handler) {
        this.connectionHandler = handler;
    }

    /**
     * Creates a new P2P VPN network node.
     *
     * @param port        The port number on which this node will listen for peer connections.
     * @param isInitiator A flag indicating whether this node is initiating a new network.
     * @throws IOException If there is an error during network setup, such as binding to the specified port.
     */
    public P2PNetwork(int port, boolean isInitiator) throws IOException {
        this.port = port;
        this.nodeId = generateNodeId();
        this.ipAddress = isInitiator ? "10.0.0.1" : "10.0.1.1";
        this.peers = new ConcurrentHashMap<>();
        this.bytesSent = new ConcurrentHashMap<>();
        this.bytesReceived = new ConcurrentHashMap<>();
        this.isInitiator = isInitiator;
        // Initialize core components
        this.router = new SwarmRouter();
        this.networkStack = new NetworkStack(ipAddress, router);
        this.natHandler = new NATHandler();
        this.pow = new ProofOfWork(nodeId);
        
        // Create server socket for peer connections
        this.serverSocket = new ServerSocket();
        this.serverSocket.setReuseAddress(true);
        this.serverSocket.bind(new InetSocketAddress(port));
        
        // Initialize thread pools
        this.scheduler = Executors.newScheduledThreadPool(4);
        this.executor = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            return t;
        });
        
        // Set up periodic tasks
        scheduler.scheduleAtFixedRate(this::gossip, 30, 30, TimeUnit.SECONDS);
        scheduler.scheduleAtFixedRate(this::updateProofOfWork, 20, 20, TimeUnit.HOURS);
        scheduler.scheduleAtFixedRate(this::sendKeepalive, 5, 5, TimeUnit.SECONDS);
        scheduler.scheduleAtFixedRate(router::evaporatePheromones, 10, 10, TimeUnit.SECONDS);
        scheduler.scheduleAtFixedRate(router::cleanupRoutes, 1, 1, TimeUnit.MINUTES);
        scheduler.scheduleAtFixedRate(natHandler::cleanupExpiredMappings, 1, 1, TimeUnit.MINUTES);
        scheduler.scheduleAtFixedRate(this::checkPeerCount, 1, 1, TimeUnit.MINUTES);
        scheduler.scheduleAtFixedRate(this::logStats, 5, 5, TimeUnit.MINUTES);
        
        // Set up UDP handlers
        setupUDPHandlers();
        
        this.running = true;
        this.startTime = System.currentTimeMillis();
        
        log.info("P2P Network node started on port {} with IP {}", port, ipAddress);
        log.info("Node ID: {}", ByteBuffer.wrap(nodeId).toString());
        setConnectionHandler((address, remotePort, conn) -> {
            try {
                handleNewPeerConnection(address, remotePort, conn);
            } catch (Exception e) {
                log.error("Failed to handle new peer: {}", e.getMessage());
            }
        });
    }
    
    /**
     * Generates a unique node ID using a secure random number generator.
     *
     * @return A byte array representing the unique node ID.
     */
    private byte[] generateNodeId() {
        byte[] id = new byte[32];
        new SecureRandom().nextBytes(id);
        return id;
    }

    
    /**
     * Sets up UDP handlers for managing VPN traffic. This is only configured if the node is an initiator.
     */
    private void setupUDPHandlers() {
        // Handle VPN traffic - only bind if we're an initiator
        if (isInitiator) {
            getUDPHandler().bind(port, (payload, sourceIP, sourcePort) -> {
                try {
                    // Extract original ports from payload
                    short origSrcPort = payload.getShort();
                    short origDstPort = payload.getShort();

                    // Extract actual data
                    byte[] data = new byte[payload.remaining()];
                    payload.get(data);

                    String sourcePeer = IPPacket.formatIP(sourceIP);
                    updatePeerStats(sourcePeer, data.length, true);

                    // Process through NAT
                    byte[] processedPacket = natHandler.processIncomingPacket(data);
                    if (processedPacket != null) {
                        processIncomingPacket(ByteBuffer.wrap(processedPacket), sourcePeer);

                        // Send response data back through UDP tunnel
                        ByteBuffer response = ByteBuffer.allocate(processedPacket.length + 4);
                        response.putShort(origDstPort);  // Swap ports for response
                        response.putShort(origSrcPort);
                        response.put(processedPacket);
                        response.flip();

                        getUDPHandler().sendPacket(sourcePort, sourceIP, origSrcPort, response);
                    }

                } catch (Exception e) {
                    log.error("Error handling VPN packet: {}", e.getMessage());
                }
            });
        }
    }

    
    /**
     * Updates the statistics for data sent or received from a peer.
     *
     * @param peerId     The identifier of the peer.
     * @param bytes      The number of bytes sent or received.
     * @param isReceived A flag indicating whether the bytes were received (true) or sent (false).
     */
    private void updatePeerStats(String peerId, int bytes, boolean isReceived) {
        Map<String, Long> stats = isReceived ? bytesReceived : bytesSent;
        stats.compute(peerId, (k, v) -> (v == null ? 0L : v) + bytes);
    }



    /**
     * Starts the network node by solving the initial proof of work, setting up UDP listeners if initiator,
     * and beginning to accept peer connections and route packets.
     *
     * @throws IOException  If there is an error during startup, such as failing to bind the UDP port.
     * @throws Exception    If the proof of work cannot be solved.
     */
    public void start() throws IOException, Exception {
        // Solve initial proof of work
        if (!pow.solve()) {
            throw new RuntimeException("Failed to generate initial proof of work");
        }
    
        // Create initial UDP listener
        if (isInitiator) {
            log.info("Starting UDP listener on port {}", port);
            try (DatagramSocket testSocket = new DatagramSocket(null)) {
                testSocket.setReuseAddress(true);
                testSocket.bind(new InetSocketAddress("0.0.0.0", port));
                testSocket.close();
                log.info("UDP port {} is available", port);
            } catch (IOException e) {
                log.error("UDP port {} is not available: {}", port, e.getMessage());
                throw e;
            }
            VPNConnection serverConn = new VPNConnection(null, port, true);
            serverConn.setGossipHandler(this);
        }
    
        // Start accepting connections
        executor.submit(this::acceptConnections);
        
        // Start packet routing
        executor.submit(this::routePackets);
        
        log.info("Network node fully started and ready for connections");
    }


     /**
     * Continuously accepts incoming peer connections and handles them.
     */
    private void acceptConnections() {
        while (running && !Thread.currentThread().isInterrupted()) {
            try {
                Socket socket = serverSocket.accept();
                socket.setSoTimeout(SOCKET_TIMEOUT);
                
                // Check peer limit
                if (peers.size() >= MAX_PEERS) {
                    log.warn("Rejecting connection from {}: peer limit reached", 
                        socket.getInetAddress());
                    socket.close();
                    continue;
                }
                
                executor.submit(() -> handleNewPeer(socket));
                
            } catch (IOException e) {
                if (running) {
                    log.error("Error accepting connection: {}", e.getMessage());
                }
            }
        }
    }
    
    /**
     * The main loop for routing packets. Continuously retrieves packets from the router and routes them.
     */
    private void routePackets() {
        while (running && !Thread.currentThread().isInterrupted()) {
            try {
                ByteBuffer packet = router.getNextPacket();
                if (packet != null) {
                    routePacket(packet);
                } else {
                    // No packets to route, short sleep
                    Thread.sleep(10);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("Error routing packet: {}", e.getMessage());
            }
        }
    }
    
    /**
     * Routes a single packet by determining its destination and forwarding it through the appropriate peer.
     *
     * @param packet The {@link ByteBuffer} containing the raw IP packet data.
     */
    private void routePacket(ByteBuffer packet) {
        try {
            IPPacket ipPacket = new IPPacket(packet);
            String destIP = IPPacket.formatIP(ipPacket.getDestinationIP());
            
            // Get next hop
            String nextHop = router.getNextHop(destIP);
            if (nextHop == null) {
                log.debug("No route to {}, dropping packet", destIP);
                return;
            }
            
            // Get peer for next hop
            Peer peer = findPeerById(nextHop);
            if (peer == null) {
                log.debug("Peer {} not found for route to {}", nextHop, destIP);
                return;
            }
            
            // Apply NAT and send
            byte[] nattedPacket = natHandler.processOutgoingPacket(packet.array(), 
                getLocalSubnet());
            if (nattedPacket != null) {
                peer.getConnection().sendPacket(nattedPacket);
                updatePeerStats(nextHop, nattedPacket.length, false);
                
                // Update route metrics
                updateRouteMetrics(nextHop, ipPacket, nattedPacket.length);
            }
            
        } catch (IOException e) {
            log.error("Error processing outbound packet: {}", e.getMessage());
        }
    }


    /**
     * Processes an incoming packet by determining its destination and forwarding or handling it accordingly.
     *
     * @param packet      The {@link ByteBuffer} containing the raw IP packet data.
     * @param sourcePeer  The identifier of the source peer from which the packet was received.
     */
    private void processIncomingPacket(ByteBuffer packet, String sourcePeer) {
        try {
            IPPacket ipPacket = new IPPacket(packet);
            String destIP = IPPacket.formatIP(ipPacket.getDestinationIP());
            
            // Update routing information
            updateRouteMetrics(sourcePeer, ipPacket, packet.remaining());
            
            // Check if packet is for us
            if (isForLocalNetwork(destIP)) {
                networkStack.injectPacket(packet);
                return;
            }
            
            // Forward packet
            String nextHop = router.getNextHop(destIP);
            if (nextHop != null && !nextHop.equals(sourcePeer)) {
                router.routePacket(packet, nextHop);
            } else {
                log.debug("No route to {} from {}", destIP, sourcePeer);
            }
            
        } catch (Exception e) {
            log.error("Error processing inbound packet: {}", e.getMessage());
        }
    }
    
    /**
     * Updates routing metrics based on the transmission of a packet.
     *
     * @param peerId     The identifier of the peer through which the packet was sent or received.
     * @param packet     The {@link IPPacket} representing the packet.
     * @param packetSize The size of the packet in bytes.
     */
    private void updateRouteMetrics(String peerId, IPPacket packet, int packetSize) {
        Peer peer = findPeerById(peerId);
        if (peer != null) {
            String destIP = IPPacket.formatIP(packet.getDestinationIP());
            
            // Calculate metrics
            double latency = peer.getLatency();
            long bandwidth = calculateBandwidth(peer, packetSize);
            
            // Update router
            router.updateMetrics(destIP, peerId, latency, bandwidth);
        }
    }
    
    /**
     * Calculates the estimated bandwidth based on recent packet history.
     *
     * @param peer         The {@link Peer} for which bandwidth is being calculated.
     * @param newPacketSize The size of the new packet in bytes.
     * @return The estimated bandwidth in bytes per second.
     */
    private long calculateBandwidth(Peer peer, int newPacketSize) {
        long totalBytes = bytesSent.getOrDefault(Arrays.toString(peer.getNodeId()), 0L) +
                           bytesReceived.getOrDefault(Arrays.toString(peer.getNodeId()), 0L) +
                           newPacketSize;
                         
        long duration = System.currentTimeMillis() - peer.getLastProofTimestamp();
        if (duration == 0) return 0;
        
        return (totalBytes * 1000) / duration; // bytes per second
    }


    /**
     * Finds a peer by its identifier.
     *
     * @param peerId The identifier of the peer.
     * @return The {@link Peer} instance if found; otherwise, {@code null}.
     */
    private Peer findPeerById(String peerId) {
        for (Peer peer : peers.values()) {
            if (ByteBuffer.wrap(peer.getNodeId()).toString().equals(peerId)) {
                return peer;
            }
        }
        return null;
    }
    
    /**
     * Retrieves the local subnet based on the node's IP address.
     *
     * @return A {@link String} representing the local subnet.
     */
    private String getLocalSubnet() {
        return ipAddress.substring(0, ipAddress.lastIndexOf('.'));
    }
    
    /**
     * Determines whether an IP address belongs to the local network.
     *
     * @param ipAddress The IP address to check.
     * @return {@code true} if the IP address is within the local subnet; {@code false} otherwise.
     */
    private boolean isForLocalNetwork(String ipAddress) {
        String ourSubnet = this.ipAddress.startsWith("10.0.0") ? "10.0.0" : "10.0.1";
        return ipAddress.startsWith(ourSubnet);
    }

    
    /**
     * Performs a handshake with a connected peer by exchanging peer information and proofs of work.
     *
     * @param conn The {@link VPNConnection} instance representing the connection to the peer.
     * @throws IOException If the handshake fails due to I/O errors.
     */
    private void performHandshake(VPNConnection conn) throws IOException {
        try {
            // Wait for peer info first
            log.info("Receiving peer info...");
            byte[] peerNodeId = conn.receivePeerInfo();
            log.info("Received peer ID, length: {}", peerNodeId.length);
            
            // Then receive proof of work
            byte[] proofData = conn.receiveProof();
            long peerTimestamp = ByteBuffer.wrap(proofData, proofData.length - 8, 8).getLong();
            
            // Send our info back
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeInt(nodeId.length);
            dos.write(nodeId);
            conn.sendMessage(VPNConnection.MSG_TYPE_PEER_INFO, baos.toByteArray());
            
            // Send our proof
            byte[] proof = pow.getCurrentProof();
            long timestamp = pow.getTimestamp();
            conn.sendProof(proof, timestamp);
        } catch (IOException e) {
            throw new IOException("Handshake failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Handles a new peer connection by performing handshake, verifying proof of work, and initializing peer details.
     *
     * @param address The IP address of the new peer.
     * @param port    The port number of the new peer.
     * @param conn    The {@link VPNConnection} instance representing the connection to the peer.
     * @throws Exception If there is an error during the handling of the new peer connection.
     */
    private void handleNewPeerConnection(String address, int port, VPNConnection conn) throws Exception {
        // Wait for peer info and proof
        log.info("Receiving peer info from {}:{}", address, port);
        byte[] peerNodeId = conn.receivePeerInfo();
        log.info("Received peer ID, length: {}", peerNodeId.length);
        
        ByteBuffer peerId = ByteBuffer.wrap(peerNodeId);
        if (peers.containsKey(peerId)) {
            try (conn) {
                log.warn("Duplicate peer connection, closing");
            }
            return;
        }
        
        // Get and verify proof of work
        byte[] proofData = conn.receiveProof();
        long peerTimestamp = ByteBuffer.wrap(proofData, proofData.length - 8, 8).getLong();
        
        if (!pow.verify(Arrays.copyOf(proofData, proofData.length - 8), peerTimestamp)) {
            try (conn) {
                log.warn("Invalid proof of work from peer");
            }
            return;
        }
        
        // Create peer
        Peer peer = new Peer(address, port, peerNodeId);
        peer.setProofOfWork(Arrays.copyOf(proofData, proofData.length - 8));
        peer.setLastProofTimestamp(peerTimestamp);
        peer.setConnection(conn);
        
        peers.put(peerId, peer);
        log.info("Added peer to network: {}:{}", address, port);
        
        sendInitialRoutes(peer);
        executor.submit(() -> handlePeerTraffic(peer));
        // Send acknowledgment
        conn.sendMessage(VPNConnection.MSG_TYPE_PEER_INFO, new byte[]{1});  // Simple ack
        
        log.info("New peer connection established: {}:{}", address, port);
    }


      /**
     * Handles the setup of a new peer connection by initializing a {@link VPNConnection} and assigning handlers.
     *
     * @param socket The {@link Socket} representing the new peer connection.
     */
    private void handleNewPeer(Socket socket) {
        try {
            log.info("Setting up new peer connection from: {}", socket.getInetAddress());
            
            // Create VPN connection with handler
            VPNConnection conn = new VPNConnection(null, port, true); 
            conn.setGossipHandler(this);
            conn.setConnectionHandler(connectionHandler);  // Add this line
            
            log.info("UDP listener established on port {}", port);
            
        } catch (Exception e) {
            log.error("Failed to setup peer connection: {}", e.getMessage());
            try {
                socket.close();
            } catch (IOException ignored) {}
        }
    }
    
    /**
     * Retrieves the {@link UDPHandler} instance from the {@link NetworkStack}.
     *
     * @return The {@link UDPHandler} associated with this network node.
     */
    public UDPHandler getUDPHandler() {
        return networkStack.getUDPHandler();
    }

    /**
     * Initiates a connection to a new peer given its address and port.
     *
     * @param address The IP address of the peer to connect to.
     * @param port    The port number of the peer to connect to.
     * @throws IOException If the connection attempt fails after the maximum number of retries.
     */
    public void connectToPeer(String address, int port) throws IOException {
        String peerAddr = address + ":" + port;
        log.info("Connecting to peer {}:{}", address, port);
    
        // Check if already connected
        for (Peer peer : peers.values()) {
            if ((peer.getAddress() + ":" + peer.getPort()).equals(peerAddr)) {
                log.info("Already connected to peer {}", peerAddr);
                return;
            }
        }
    
        IOException lastException = null;
        int initialTimeout = 1000; // Start with 1 second timeout
        int maxAttempts = 5;
    
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                int currentTimeout = initialTimeout * (int) Math.pow(2, attempt - 1); // Exponential backoff
                log.info("Connecting to peer {}:{} (attempt {}/{}) with timeout {}ms",
                        address, port, attempt, maxAttempts, currentTimeout);
    
                // Create connection
                VPNConnection conn = new VPNConnection(address, port);
                conn.setTimeout(currentTimeout); 
                conn.setGossipHandler(this);
    
                // Exchange keys and establish secure channel 
                log.debug("Exchanging peer info and proofs with {}:{}", address, port);
    
                // Send peer info 
                ByteBuffer info = ByteBuffer.allocate(32);
                info.putInt(4);  // Version
                info.putLong(System.currentTimeMillis());
                info.flip();
                conn.sendMessage(VPNConnection.MSG_TYPE_PEER_INFO, info.array());
    
                // Send proof
                ByteBuffer proof = ByteBuffer.allocate(40);
                proof.putInt(1);  // Version
                proof.putLong(System.currentTimeMillis());
                proof.flip();
                conn.sendMessage(VPNConnection.MSG_TYPE_PROOF, proof.array());
    
                // Create and add peer
                Peer peer = new Peer(address, port, nodeId);
                peer.setProofOfWork(pow.getCurrentProof());
                peer.setLastProofTimestamp(pow.getTimestamp());
                peer.setConnection(conn);
    
                peers.put(ByteBuffer.wrap(nodeId), peer);
                
                log.info("Successfully connected to peer {}:{}", address, port);
                return;
    
            } catch (SocketTimeoutException e) {
                log.warn("Connection attempt {} timed out", attempt);
                lastException = e;
    
            } catch (IOException e) {
                log.error("Failed to connect to peer {}:{}: {}", address, port, e.getMessage());
                lastException = e;
    
            } catch (Exception e) {
                log.error("Unexpected error while connecting to peer {}:{}: {}", address, port, e.getMessage());
                throw new IOException(e);
            }
    
            // Wait before the next attempt
            try {
                Thread.sleep(initialTimeout * (int) Math.pow(2, attempt - 1));
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new IOException("Connection interrupted during backoff", ie);
            }
        }
    
        throw new IOException("Failed to connect after " + maxAttempts + " attempts", lastException);
    }


    /**
     * Handles the traffic from a connected peer by continuously receiving packets and processing them.
     *
     * @param peer The {@link Peer} instance representing the connected peer.
     */
    private void handlePeerTraffic(Peer peer) {
        try {
            VPNConnection conn = peer.getConnection();
            while (running && !Thread.currentThread().isInterrupted()) {
                try {
                    long hPt_startTime = System.nanoTime();
                    byte[] packet = conn.receivePacket();
                    
                    if (packet != null) {
                        updatePeerStats(Arrays.toString(peer.getNodeId()), packet.length, true);
                        double latency = (System.nanoTime() - hPt_startTime) / 1_000_000.0;
                        peer.updateLatency(latency);
                        processIncomingPacket(ByteBuffer.wrap(packet), 
                            Arrays.toString(peer.getNodeId()));
                    }
                    
                } catch (SocketTimeoutException e) {
                    // This is normal, continue
    
                } catch (IOException e) {
                    if ("Connection closed by peer".equals(e.getMessage())) {
                        log.info("Peer {} disconnected gracefully", peer.getAddress());
                    } else {
                        log.error("Error reading from peer {}: {}", 
                            peer.getAddress(), e.getMessage());
                    }
                    break;
                }
            }
        } finally {
            removePeer(peer);
        }
    }
    
    /**
     * Sends the initial routing information to a newly connected peer.
     *
     * @param peer The {@link Peer} instance representing the new peer.
     * @throws IOException If there is an error while sending routing information.
     */
    private void sendInitialRoutes(Peer peer) throws IOException {
        // Always add a direct route to this peer
        String peerSubnet = peer.getAddress().substring(0, peer.getAddress().lastIndexOf('.')) + ".0";
        String peerId = Arrays.toString(peer.getNodeId());
        
        // Add direct route to peer's subnet
        router.updateRoute(peerSubnet, peerId, 1);
        
        // If this is the initiator (10.0.0.1), add route to self for default gateway
        if (isInitiator) {
            router.updateRoute("10.0.0.1", peerId, 1);
            
            // Add high pheromone level for direct connection
            String routeKey = "10.0.0.1-" + peerId;
            router.updateMetrics("10.0.0.1", peerId, 0.1, 1000000); // Low latency, high bandwidth
        } else {
            // If we're not the initiator, add route to initiator through this peer if it's 10.0.0.x
            if (peer.getAddress().startsWith("10.0.0")) {
                router.updateRoute("10.0.0.1", peerId, 1);
                router.updateMetrics("10.0.0.1", peerId, 0.1, 1000000);
            }
        }
        
        // Share current routes
        Map<String, RouteInfo> currentRoutes = new HashMap<>();
        for (Map.Entry<String, Map<String, RouteInfo>> entry : router.getRoutes().entrySet()) {
            String destination = entry.getKey();
            Map<String, RouteInfo> routes = entry.getValue();
            
            for (Map.Entry<String, RouteInfo> routeEntry : routes.entrySet()) {
                String nextHop = routeEntry.getKey();
                RouteInfo route = routeEntry.getValue();
                
                // Only share routes we're actually using
                if (route.getScore() > 0) {
                    currentRoutes.put(destination + "-" + nextHop, route);
                }
            }
        }
        
        GossipMessage gossip = new GossipMessage(
            nodeId,
            pow.getCurrentProof(),
            pow.getTimestamp(),
            new ArrayList<>(peers.values()),
            currentRoutes
        );
        
        peer.getConnection().sendGossip(gossip);
        peer.updateLastGossip();
        log.debug("Sent initial routes to peer: {}", peer.getAddress());
    }


    /**
     * Removes a peer from the network by updating the peers map, router, and cleaning up resources.
     *
     * @param peer The {@link Peer} instance to be removed.
     */
    private void removePeer(Peer peer) {
        log.info("Removing peer: {}", peer.getAddress());
        
        ByteBuffer peerId = ByteBuffer.wrap(peer.getNodeId());
        peers.remove(peerId);
        router.removePeer(Arrays.toString(peer.getNodeId()));
        
        try {
            peer.getConnection().close();
        } catch (IOException e) {
            log.debug("Error closing peer connection: {}", e.getMessage());
        }
        
        // Clean up statistics
        bytesSent.remove(Arrays.toString(peer.getNodeId()));
        bytesReceived.remove(Arrays.toString(peer.getNodeId()));
        
        // Check if we need to find more peers
        checkPeerCount();
    }
    
    /**
     * Ensures that the network maintains at least the minimum required number of peers.
     * If the current peer count is below the minimum, it initiates a search for new peers.
     */
    private void checkPeerCount() {
        if (peers.size() < MIN_PEERS) {
            log.info("Peer count ({}) below minimum ({}), seeking new peers", 
                peers.size(), MIN_PEERS);
            seekNewPeers();
        }
    }
    
    /**
     * Seeks new peers by requesting peer lists from existing connections through gossip messages.
     */
    private void seekNewPeers() {
        // Get list of known peers from existing connections
        Set<String> knownPeers = new HashSet<>();
        for (Peer peer : peers.values()) {
            knownPeers.add(peer.getAddress() + ":" + peer.getPort());
        }
        
        // Ask existing peers for their peer lists
        for (Peer peer : peers.values()) {
            try {
                GossipMessage gossip = new GossipMessage(
                    nodeId,
                    pow.getCurrentProof(),
                    pow.getTimestamp(),
                    new ArrayList<>(peers.values()),
                    new HashMap<>()
                );
                peer.getConnection().sendGossip(gossip);
            } catch (IOException e) {
                log.error("Failed to request peers from {}: {}", 
                    peer.getAddress(), e.getMessage());
            }
        }
    }

    /**
     * Periodically gossips to maintain network state by sharing routing information and known peers with a subset of connected peers.
     */
    private void gossip() {
        if (!running || peers.isEmpty()) return;
        
        // Select random subset of peers to gossip with
        List<Peer> activePeers = new ArrayList<>(peers.values());
        Collections.shuffle(activePeers);
        int gossipCount = Math.min(3, activePeers.size());
        
        // Prepare current routing information
        Map<String, RouteInfo> currentRoutes = new HashMap<>();
        for (Map.Entry<String, Map<String, RouteInfo>> entry : router.getRoutes().entrySet()) {
            String destination = entry.getKey();
            Map<String, RouteInfo> routes = entry.getValue();
            
            // Only share active routes
            routes.entrySet().stream()
                .filter(r -> r.getValue().getScore() > 0)
                .forEach(r -> currentRoutes.put(
                    destination + "-" + r.getKey(), r.getValue()));
        }
        
        // Add our direct routes
        for (Peer peer : peers.values()) {
            String peerSubnet = getSubnetForIP(peer.getAddress());
            RouteInfo directRoute = new RouteInfo(
                peerSubnet,             // destination
                Arrays.toString(peer.getNodeId()),  // nextHop
                1                       // hopCount
            );
            currentRoutes.put(peerSubnet + "-direct", directRoute);
        }

        // Send gossip to selected peers
        for (int i = 0; i < gossipCount; i++) {
            Peer peer = activePeers.get(i);
            try {
                GossipMessage gossip = new GossipMessage(
                    nodeId,
                    pow.getCurrentProof(),
                    pow.getTimestamp(),
                    new ArrayList<>(peers.values()),
                    currentRoutes
                );
                
                peer.getConnection().sendGossip(gossip);
                peer.updateLastGossip();
                
                log.debug("Sent gossip to peer: {}", peer.getAddress());
            } catch (IOException e) {
                log.error("Failed to gossip with peer {}: {}", 
                    peer.getAddress(), e.getMessage());
                removePeer(peer);
            }
        }
    }


     /**
     * Handles incoming gossip messages by validating them and updating network state accordingly.
     *
     * @param message     The {@link GossipMessage} received from a peer.
     * @param sourcePeer  The {@link Peer} instance representing the source of the gossip message.
     */
    private void handleGossipMessage(GossipMessage message, Peer sourcePeer) {
        if (!message.isValid()) {
            log.warn("Received invalid gossip message from peer: {}", 
                sourcePeer != null ? sourcePeer.getAddress() : "unknown");
            return;
        }
        
        if (sourcePeer != null) {  // Add null check here
            // Update peer's proof of work if newer
            if (message.getProofTimestamp() > sourcePeer.getLastProofTimestamp()) {
                sourcePeer.setProofOfWork(message.getProofOfWork());
                sourcePeer.setLastProofTimestamp(message.getProofTimestamp());
            }
        }

        // Process peer information
        for (GossipMessage.PeerInfo peerInfo : message.getKnownPeers()) {
            ByteBuffer peerId = ByteBuffer.wrap(peerInfo.nodeId());
            
            // Skip if this is us
            if (Arrays.equals(peerInfo.nodeId(), nodeId)) continue;
            
            // Update existing peer information
            Peer existingPeer = peers.get(peerId);
            if (existingPeer != null) {
                if (peerInfo.proofTimestamp() > existingPeer.getLastProofTimestamp()) {
                    existingPeer.setProofOfWork(peerInfo.proofOfWork());
                    existingPeer.setLastProofTimestamp(peerInfo.proofTimestamp());
                }
                continue;
            }

            // Connect to new peers if we have capacity
            if (peers.size() < MAX_PEERS) {
                executor.submit(() -> {
                    try {
                        connectToPeer(peerInfo.address(), peerInfo.port());
                    } catch (IOException e) {
                        log.debug("Failed to connect to discovered peer {}:{}: {}", 
                            peerInfo.address(), peerInfo.port(), e.getMessage());
                    }
                });
            }
        }

        // Process routing information
        for (Map.Entry<String, RouteInfo> entry : message.getRoutes().entrySet()) {
            String[] parts = entry.getKey().split("-");
            if (parts.length != 2) continue;
            
            String destination = parts[0];
            String nextHop = parts[1];
            RouteInfo newRoute = entry.getValue();
            
            // Skip routes through ourselves
            if (Arrays.equals(newRoute.getNextHop().getBytes(), nodeId)) continue;
            
            // Update routing table
            router.updateRoute(destination, nextHop, newRoute.getHopCount() + 1);
            
            // Update metrics if available
            if (newRoute.getLatency() > 0 || newRoute.getBandwidth() > 0) {
                router.updateMetrics(destination, nextHop, 
                    newRoute.getLatency(), newRoute.getBandwidth());
            }
        }
    }


    /**
     * Updates the proof of work by solving a new proof and broadcasting it to all connected peers.
     * This method is scheduled to run periodically.
     */
    private void updateProofOfWork() {
        executor.submit(() -> {
            if (pow.solve()) {
                byte[] newProof = pow.getCurrentProof();
                long newTimestamp = pow.getTimestamp();
                
                // Broadcast new proof to all peers
                for (Peer peer : peers.values()) {
                    try {
                        peer.getConnection().sendProof(newProof, newTimestamp);
                        log.debug("Sent new proof to peer: {}", peer.getAddress());
                    } catch (IOException e) {
                        log.error("Failed to send new proof to peer: {}", 
                            peer.getAddress(), e.getMessage());
                        removePeer(peer);
                    }
                }
                
                log.info("Successfully updated and broadcast new proof of work");
            } else {
                log.error("Failed to generate new proof of work");
            }
        });
    }
    
    /**
     * Sends keepalive messages to all connected peers to ensure active connections and detect stale peers.
     * This method is scheduled to run periodically.
     */
    private void sendKeepalive() {
        if (!running) return;
            
        // Send keepalive to each connected peer
        for (Peer peer : peers.values()) {
            try {
                if (peer.getConnection() != null && peer.getConnection().isRunning()) {
                    log.debug("Sending keepalive to peer: {}", peer.getAddress());
                    peer.getConnection().sendMessage(VPNConnection.MSG_TYPE_PING, new byte[]{});
                    peer.updateLastSeen();
                }
            } catch (IOException e) {
                log.error("Failed to send keepalive to peer {}: {}", peer.getAddress(), e.getMessage());
                removePeer(peer);
            }
        }
    }
    
    /**
     * Checks the health of all connected peers and removes any that are deemed stale.
     * This method is scheduled to run periodically.
     */
    private void checkPeerHealth() {
        if (!running || peers.isEmpty()) return;
            
        List<Peer> stalePeers = new ArrayList<>();
        
        for (Peer peer : peers.values()) {
            if (peer.isStale()) {
                log.warn("Peer {} is stale, marking for removal", peer.getAddress());
                stalePeers.add(peer);
            }
        }
        
        // Remove stale peers
        for (Peer peer : stalePeers) {
            removePeer(peer);
        }
        
        // Check if we need more peers
        if (peers.size() < MIN_PEERS) {
            log.info("Peer count ({}) below minimum ({}), seeking new peers", 
                peers.size(), MIN_PEERS);
            seekNewPeers();
        }
    }


    /**
     * Retrieves the subnet for a given IP address.
     *
     * @param ipAddress The IP address for which the subnet is to be determined.
     * @return A {@link String} representing the subnet in CIDR notation.
     */
    private String getSubnetForIP(String ipAddress) {
        return ipAddress.substring(0, ipAddress.lastIndexOf('.')) + ".0/24";
    }
    
    /**
     * Formats network statistics into a human-readable map.
     *
     * @return A {@link Map} containing various network statistics and metrics.
     */
    public Map<String, Object> getNetworkStats() {
        Map<String, Object> stats = new HashMap<>();
        
        // Basic network info
        stats.put("nodeId", ByteBuffer.wrap(nodeId).toString());
        stats.put("ipAddress", ipAddress);
        stats.put("port", port);
        stats.put("uptime", System.currentTimeMillis() - startTime);
        
        // Peer statistics
        stats.put("activePeers", peers.size());
        stats.put("maxPeers", MAX_PEERS);
        stats.put("minPeers", MIN_PEERS);
        
        // Traffic statistics
        long totalBytesSent = bytesSent.values().stream().mapToLong(Long::longValue).sum();
        long totalBytesReceived = bytesReceived.values().stream().mapToLong(Long::longValue).sum();
        stats.put("totalBytesSent", totalBytesSent);
        stats.put("totalBytesReceived", totalBytesReceived);
        
        // Calculate average metrics
        double avgLatency = peers.values().stream()
            .mapToDouble(Peer::getLatency)
            .filter(l -> l != Double.MAX_VALUE)
            .average()
            .orElse(0.0);
        
        double avgBandwidth = peers.values().stream()
            .mapToLong(Peer::getEstimatedBandwidth)
            .average()
            .orElse(0.0);
        
        stats.put("averageLatency", String.format("%.2fms", avgLatency));
        stats.put("averageBandwidth", String.format("%.2f KB/s", avgBandwidth / 1024));
        
        // Route statistics
        stats.put("activeRoutes", router.getRoutes().size());
        Map<String, Double> pheromoneStats = new HashMap<>();
        router.getRoutes().forEach((dest, routes) -> 
            routes.forEach((next, route) -> 
                pheromoneStats.put(dest + "-" + next, route.getScore())));
        stats.put("routeScores", pheromoneStats);
        
        // Proof of work info
        stats.put("lastProofUpdate", pow.getTimestamp());
        stats.put("proofAge", 
            TimeUnit.MILLISECONDS.toMinutes(System.currentTimeMillis() - pow.getTimestamp()));
            
        // NAT statistics
        stats.put("natStats", natHandler.getStats());
        
        return stats;
    }


    /**
     * Retrieves detailed information about all connected peers.
     *
     * @return A {@link List} of {@link Map} objects, each containing details of a peer.
     */
    public List<Map<String, Object>> getPeerDetails() {
        List<Map<String, Object>> peerList = new ArrayList<>();
        
        for (Peer peer : peers.values()) {
            Map<String, Object> details = new HashMap<>();
            details.put("address", peer.getAddress());
            details.put("port", peer.getPort());
            details.put("nodeId", ByteBuffer.wrap(peer.getNodeId()).toString());
            details.put("latency", peer.getLatency());
            details.put("bandwidth", peer.getEstimatedBandwidth());
            details.put("bytesSent", bytesSent.getOrDefault(Arrays.toString(peer.getNodeId()), 0L));
            details.put("bytesReceived", bytesReceived.getOrDefault(Arrays.toString(peer.getNodeId()), 0L));
            details.put("lastSeen", System.currentTimeMillis() - peer.getLastGossip());
            details.put("routeScore", router.getScore(Arrays.toString(peer.getNodeId())));
            peerList.add(details);
        }
        
        return peerList;
    }
    
    /**
     * Generates a string representation of the current routing table for visualization and diagnostics.
     *
     * @return A {@link String} detailing the current routing table.
     */
    public String dumpRoutingTable() {
        StringBuilder dump = new StringBuilder();
        dump.append("Current Routing Table:\n");
        
        router.getRoutes().forEach((destination, routes) -> {
            dump.append("\nDestination: ").append(destination).append("\n");
            routes.forEach((nextHop, route) -> {
                String peerAddress = "unknown";
                for (Peer peer : peers.values()) {
                    if (nextHop.equals(Arrays.toString(peer.getNodeId()))) {
                        peerAddress = peer.getAddress();
                        break;
                    }
                }
                
                dump.append(String.format("  via %s (peer: %s):\n", nextHop, peerAddress));
                dump.append(String.format("    hops: %d\n", route.getHopCount()));
                dump.append(String.format("    score: %.3f\n", route.getScore()));
                dump.append(String.format("    latency: %.2fms\n", route.getLatency()));
                dump.append(String.format("    bandwidth: %d B/s\n", route.getBandwidth()));
            });
        });
        
        return dump.toString();
    }


     /**
     * Logs periodic network statistics to aid in monitoring and diagnostics.
     * This method is scheduled to run at fixed intervals.
     */
    private void logStats() {
        if (!running) return;
        
        Map<String, Object> stats = getNetworkStats();
        log.info("Network Statistics:");
        log.info("  Peers: {}/{}", stats.get("activePeers"), stats.get("maxPeers"));
        log.info("  Traffic: {} sent, {} received", 
            formatBytes((Long)stats.get("totalBytesSent")),
            formatBytes((Long)stats.get("totalBytesReceived")));
        log.info("  Latency: {}, Bandwidth: {}", 
            stats.get("averageLatency"),
            stats.get("averageBandwidth"));
        log.info("  Routes: {}", stats.get("activeRoutes"));
        log.info("  Proof age: {} minutes", stats.get("proofAge"));
    }
    
    /**
     * Formats a byte count into a human-readable string with appropriate units.
     *
     * @param bytes The number of bytes.
     * @return A {@link String} representing the formatted byte count.
     */
    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        String pre = "KMGTPE".charAt(exp-1) + "";
        return String.format("%.1f %sB", bytes / Math.pow(1024, exp), pre);
    }
    
    /**
     * Retrieves a list of all active peers in a formatted string representation.
     *
     * @return A {@link List} of {@link String} objects, each representing an active peer.
     */
    public List<String> getPeerList() {
        List<String> peerList = new ArrayList<>();
        for (Peer peer : peers.values()) {
            peerList.add(String.format("%s:%d (%s)", 
                peer.getAddress(), 
                peer.getPort(),
                formatBytes(bytesSent.getOrDefault(Arrays.toString(peer.getNodeId()), 0L) +
                          bytesReceived.getOrDefault(Arrays.toString(peer.getNodeId()), 0L))));
        }
        return peerList;
    }


    /**
     * Determines whether the network is healthy based on various criteria such as running status,
     * peer count, proof of work freshness, active routes, and peer health metrics.
     *
     * @return {@code true} if the network is healthy; {@code false} otherwise.
     */
    public boolean isHealthy() {
        if (!running) return false;
        if (peers.size() < MIN_PEERS) return false;
        
        // Check if we have recent proof of work
        long proofAge = System.currentTimeMillis() - pow.getTimestamp();
        if (proofAge > TimeUnit.HOURS.toMillis(24)) return false;
        
        // Check if we have active routes
        if (router.getRoutes().isEmpty()) return false;
        
        // Check peer health
        long healthyPeers = peers.values().stream()
            .filter(p -> !p.isStale())
            .filter(p -> p.getLatency() < 1000)
            .count();
            
        return healthyPeers >= MIN_PEERS;
    }
    
    /**
     * Adds a callback function that receives network statistics at regular intervals.
     *
     * @param callback A {@link Consumer} that processes the network statistics map.
     */
    public void addStatsCallback(Consumer<Map<String, Object>> callback) {
        scheduler.scheduleAtFixedRate(() -> {
            try {
                callback.accept(getNetworkStats());
            } catch (Exception e) {
                log.error("Error in stats callback: {}", e.getMessage());
            }
        }, 1, 1, TimeUnit.MINUTES);
    }

    /**
     * Cleans up and shuts down the network node gracefully by notifying peers, shutting down thread pools,
     * and clearing all internal data structures.
     */
    @Override
    public void close() {
        if (!running) return;
        
        log.info("Shutting down P2P network...");
        running = false;
        
        try {
            // Notify peers of shutdown
            try (serverSocket) {
                // Notify peers of shutdown
                try (networkStack) {
                    // Notify peers of shutdown
                    for (Peer peer : peers.values()) {
                        try {
                            peer.getConnection().sendMessage(VPNConnection.MSG_TYPE_PING, new byte[]{0});
                        } catch (IOException ignored) {}
                    }
                }
                // Shutdown thread pools
                scheduler.shutdown();
                executor.shutdown();
            }
            
            // Wait for thread pools to terminate
            if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                scheduler.shutdownNow();
            }
            if (!executor.awaitTermination(5, TimeUnit.SECONDS)) {
                executor.shutdownNow();
            }
            
            // Clean up peers
            List<Peer> remainingPeers = new ArrayList<>(peers.values());
            for (Peer peer : remainingPeers) {
                removePeer(peer);
            }
            
            // Clear all collections
            peers.clear();
            bytesSent.clear();
            bytesReceived.clear();
            
            log.info("P2P network shutdown complete");
            
        } catch (IOException | InterruptedException e) {
            log.error("Error during shutdown: {}", e.getMessage());
            // Force shutdown of thread pools
            scheduler.shutdownNow();
            executor.shutdownNow();
        }
    }
    
    /**
     * Exports the current network state for persistence or transfer purposes.
     *
     * @return A {@link Map} representing the serialized state of the network.
     */
    public Map<String, Object> exportState() {
        Map<String, Object> state = new HashMap<>();
        
        // Basic info
        state.put("nodeId", nodeId);
        state.put("ipAddress", ipAddress);
        state.put("port", port);
        
        // Proof of work
        state.put("proofOfWork", pow.getCurrentProof());
        state.put("proofTimestamp", pow.getTimestamp());
        
        // Known peers
        List<Map<String, Object>> peerList = new ArrayList<>();
        for (Peer peer : peers.values()) {
            Map<String, Object> peerInfo = new HashMap<>();
            peerInfo.put("address", peer.getAddress());
            peerInfo.put("port", peer.getPort());
            peerInfo.put("nodeId", peer.getNodeId());
            peerInfo.put("proofOfWork", peer.getProofOfWork());
            peerInfo.put("proofTimestamp", peer.getLastProofTimestamp());
            peerList.add(peerInfo);
        }
        state.put("peers", peerList);
        
        // Routes
        state.put("routes", router.exportState());
        
        return state;
    }
    
    /**
     * Imports network state from a serialized map, allowing the network node to restore its previous state.
     *
     * @param state A {@link Map} containing the serialized network state.
     * @return A new {@link P2PNetwork} instance initialized with the imported state.
     * @throws IOException If there is an error during state import.
     */
    public static P2PNetwork importState(Map<String, Object> state) throws IOException {
        int port = (Integer) state.get("port");
        String ipAddress = (String) state.get("ipAddress");
        boolean isInitiator = ipAddress.equals("10.0.0.1");
        
        P2PNetwork network = new P2PNetwork(port, isInitiator);
        
        // Connect to known peers
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> peerList = (List<Map<String, Object>>) state.get("peers");
        for (Map<String, Object> peerInfo : peerList) {
            String address = (String) peerInfo.get("address");
            int peerPort = (Integer) peerInfo.get("port");
            try {
                network.connectToPeer(address, peerPort);
            } catch (IOException e) {
                log.warn("Failed to reconnect to peer {}:{}", address, peerPort);
            }
        }
        
        return network;
    }
    
    /**
     * Runs a comprehensive diagnostic report of the network node, including peer status, network metrics,
     * routing information, and security status.
     *
     * @return A {@link String} containing the diagnostic report.
     */
    public String runDiagnostics() {
        StringBuilder report = new StringBuilder();
        report.append("P2P Network Diagnostic Report\n");
        report.append("=============================\n\n");
        
        // Basic info
        report.append(String.format("Node ID: %s\n", ByteBuffer.wrap(nodeId).toString()));
        report.append(String.format("IP Address: %s\n", ipAddress));
        report.append(String.format("Port: %d\n", port));
        report.append(String.format("Running: %s\n", running));
        report.append(String.format("Uptime: %s\n", 
            formatDuration(System.currentTimeMillis() - startTime)));
        report.append("\n");
        
        // Peer status
        report.append("Peer Status:\n");
        for (Peer peer : peers.values()) {
            report.append(String.format("  %s:%d\n", peer.getAddress(), peer.getPort()));
            report.append(String.format("    Latency: %.2f ms\n", peer.getLatency()));
            report.append(String.format("    Bandwidth: %s/s\n", 
                formatBytes(peer.getEstimatedBandwidth())));
            report.append(String.format("    Last seen: %s ago\n",
                formatDuration(System.currentTimeMillis() - peer.getLastGossip())));
            report.append(String.format("    Traffic: %s sent, %s received\n",
                formatBytes(bytesSent.getOrDefault(Arrays.toString(peer.getNodeId()), 0L)),
                formatBytes(bytesReceived.getOrDefault(Arrays.toString(peer.getNodeId()), 0L))));
            report.append("\n");
        }
        
        // Network stack status
        report.append("Network Stack Status:\n");
        report.append(String.format("  Active routes: %d\n", router.getRoutes().size()));
        report.append(String.format("  NAT mappings: %d\n", natHandler.getStats().size()));
        report.append("\n");
        
        // Proof of work status
        report.append("Security Status:\n");
        report.append(String.format("  Proof of work age: %s\n",
            formatDuration(System.currentTimeMillis() - pow.getTimestamp())));
        report.append(String.format("  Peers requiring update: %d\n",
            peers.values().stream()
                .filter(p -> p.getLastProofTimestamp() < pow.getTimestamp())
                .count()));
        report.append("\n");
        
        // Health check
        report.append("Health Check:\n");
        report.append(String.format("  Overall status: %s\n", isHealthy() ? "HEALTHY" : "UNHEALTHY"));
        report.append(String.format("  Peer count: %d/%d\n", peers.size(), MAX_PEERS));
        report.append(String.format("  Thread pools: Scheduler=%s, Executor=%s\n",
            !scheduler.isShutdown(), !executor.isShutdown()));
        
        return report.toString();
    }
    
    /**
     * Formats a duration given in milliseconds into a human-readable string.
     *
     * @param millis The duration in milliseconds.
     * @return A {@link String} representing the formatted duration.
     */
    private String formatDuration(long millis) {
        long seconds = millis / 1000;
        long minutes = seconds / 60;
        long hours = minutes / 60;
        long days = hours / 24;
        
        if (days > 0) {
            return String.format("%dd %dh", days, hours % 24);
        } else if (hours > 0) {
            return String.format("%dh %dm", hours, minutes % 60);
        } else if (minutes > 0) {
            return String.format("%dm %ds", minutes, seconds % 60);
        } else {
            return String.format("%ds", seconds);
        }
    }


    /**
     * Tests the local network connectivity by attempting to bind to the node's port.
     *
     * @return {@code true} if the port is available and can be bound; {@code false} otherwise.
     */
    public boolean testConnectivity() {
        // Test if we can bind to our port
        try (ServerSocket testSocket = new ServerSocket()) {
            testSocket.setReuseAddress(true);
            testSocket.bind(new InetSocketAddress(port));
            return true;
        } catch (IOException e) {
            log.error("Port {} is not available: {}", port, e.getMessage());
            return false;
        }
    }
    
    /**
     * Provides a string representation of the network node's current status.
     *
     * @return A {@link String} summarizing the node's ID, address, port, number of peers, and routes.
     */
    @Override
    public String toString() {
        return String.format("P2PNetwork[id=%s, address=%s:%d, peers=%d, routes=%d]",
            ByteBuffer.wrap(nodeId).toString(),
            ipAddress,
            port,
            peers.size(),
            router.getRoutes().size());
    }

    
    /**
     * Handles incoming gossip messages by validating and processing them.
     *
     * @param message The {@link GossipMessage} received.
     */
    @Override
    public void handleGossip(GossipMessage message) {
        if (!message.isValid()) {
            log.warn("Received invalid gossip message");
            return;
        }
        handleGossipMessage(message, null); // Existing method
    }
    
    /**
     * Handles incoming proof of work messages by updating peers with newer proofs.
     *
     * @param proof     The proof of work data received.
     * @param timestamp The timestamp associated with the proof of work.
     */
    @Override 
    public void handleProof(byte[] proof, long timestamp) {
        // Move proof handling logic here from VPNConnection
        for (Peer peer : peers.values()) {
            if (timestamp > peer.getLastProofTimestamp()) {
                peer.setProofOfWork(proof);
                peer.setLastProofTimestamp(timestamp);
            }
        }
    }
    
    /**
     * Handles incoming peer information messages by updating the last seen timestamp for the peer.
     *
     * @param nodeId The node ID of the peer that sent the information.
     */
    @Override
    public void handlePeerInfo(byte[] nodeId) {
        // Find matching peer
        ByteBuffer peerId = ByteBuffer.wrap(nodeId);
        Peer peer = peers.get(peerId);
        if (peer != null) {
            peer.updateLastSeen();
        }
    }
}

