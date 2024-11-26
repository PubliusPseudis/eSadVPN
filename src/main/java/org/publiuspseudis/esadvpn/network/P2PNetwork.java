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
import java.net.SocketException;
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
import java.util.logging.Level;
import org.publiuspseudis.esadvpn.network.PeerDiscovery.ConnectionMode;
import org.publiuspseudis.esadvpn.proxy.SocksProxy;
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
     * The {@link PeerDiscovery} instance responsible for discovering and managing peers within the P2P network.
     *
     * <p>
     * This component handles the discovery of new peers through various mechanisms such as local network scanning
     * and bootstrap server queries. It maintains an updated list of available peers to facilitate connection establishment
     * and network expansion.
     * </p>
     */
    private final PeerDiscovery peerDiscovery;

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
    private final int THREAD_POOL_SIZE = Math.min(Runtime.getRuntime().availableProcessors(), 4);
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
      public P2PNetwork(int port, boolean isInitiator, String peerAddress) throws IOException {
        this.port = port;
        this.nodeId = generateNodeId();
        this.ipAddress = isInitiator ? "10.0.0.1" : "10.0.1.1";
        this.peers = new ConcurrentHashMap<>();
        this.bytesSent = new ConcurrentHashMap<>();
        this.bytesReceived = new ConcurrentHashMap<>();
        this.isInitiator = isInitiator;

        // Create executor services with custom thread factories
        this.executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE, r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            t.setPriority(Thread.MIN_PRIORITY); // Lower priority for background tasks
            return t;
        });

        this.scheduler = Executors.newScheduledThreadPool(2, r -> {
            Thread t = new Thread(r);
            t.setDaemon(true);
            t.setPriority(Thread.MIN_PRIORITY);
            t.setName("P2P-Scheduler-" + t.getId());
            return t;
        });

        // Initialize core components
        this.router = new SwarmRouter();
        this.networkStack = new NetworkStack(ipAddress, router);
        this.natHandler = new NATHandler();
        this.pow = new ProofOfWork(nodeId);
        
        // Create server socket for peer connections
        this.serverSocket = new ServerSocket();
        this.serverSocket.setReuseAddress(true);
        this.serverSocket.bind(new InetSocketAddress(port));
        
        // Set up periodic tasks with more reasonable intervals
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
        
        // Initialize peer discovery with appropriate mode and peer info
        ConnectionMode mode;
        String directPeer = null;
        if (isInitiator) {
            mode = PeerDiscovery.ConnectionMode.LOCAL_NETWORK;
        } else if (peerAddress != null) {
            mode = PeerDiscovery.ConnectionMode.DIRECT_PEER;
            directPeer = peerAddress;
        } else {
            mode = PeerDiscovery.ConnectionMode.LOCAL_NETWORK;
        }

        this.peerDiscovery = new PeerDiscovery(
            nodeId, 
            pow,
            mode,
            directPeer,
            "bootstrap1.example.com:51820",
            "bootstrap2.example.com:51820"
        );

        // Start bootstrap process if not initiator
        if (!isInitiator) {
            try {
                Set<InetSocketAddress> peers = peerDiscovery.bootstrap();
                if (peers.isEmpty()) {
                    throw new IOException("Could not find any peers");
                }
                connectToInitialPeers(peers);
            } catch (IOException e) {
                log.error("Bootstrap failed: {}", e.getMessage());
                throw e;
            }
        }
    }


    private void connectToInitialPeers(Set<InetSocketAddress> peers) {
        // Connect to a subset of peers
        List<InetSocketAddress> peerList = new ArrayList<>(peers);
        Collections.shuffle(peerList);
        int connectCount = Math.min(3, peerList.size());
        
        for (int i = 0; i < connectCount; i++) {
            InetSocketAddress peer = peerList.get(i);
            try {
                connectToPeer(peer.getAddress().getHostAddress(), peer.getPort());
            } catch (IOException e) {
                log.warn("Failed to connect to peer {}: {}", peer, e.getMessage());
            }
        }
    }

   
    /**
     * Generates a unique node identifier using a secure random number generator.
     *
     * <p>
     * This method creates a 32-byte array filled with cryptographically strong random bytes to serve as the
     * unique identifier for the network node. Ensuring uniqueness is crucial for peer identification and
     * network integrity.
     * </p>
     *
     * @return A {@code byte[]} representing the unique node ID.
     */
    private static byte[] generateNodeId() {
        // Use a larger size for better uniqueness
        byte[] id = new byte[32];
        new SecureRandom().nextBytes(id);
        return id;
    }


    
    /**
     * Configures UDP handlers for managing VPN traffic.
     *
     * <p>
     * This method sets up the necessary handlers for processing incoming and outgoing VPN packets.
     * It binds to the specified port and delegates packet handling to appropriate callbacks. This setup
     * is only performed if the node is designated as an initiator.
     * </p>
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
     * Updates the traffic statistics for a specific peer.
     *
     * <p>
     * This method increments the byte counters for a given peer based on whether the data was sent
     * or received. It ensures that traffic metrics are accurately maintained for monitoring and
     * bandwidth estimation purposes.
     * </p>
     *
     * @param peerId     The identifier of the peer (typically in the format "address:port").
     * @param bytes      The number of bytes to add to the counter.
     * @param isReceived {@code true} if the bytes were received from the peer; {@code false} if sent to the peer.
     */
    private void updatePeerStats(String peerId, int bytes, boolean isReceived) {
        Map<String, Long> stats = isReceived ? bytesReceived : bytesSent;
        stats.compute(peerId, (k, v) -> (v == null ? 0L : v) + bytes);
    }



    /**
     * Initiates the P2P network node by solving the initial proof of work, setting up UDP listeners if initiator,
     * and preparing the node to accept peer connections and route network packets.
     *
     * <p>
     * This method performs the following actions:
     * <ul>
     *   <li>Solves the initial proof of work to authenticate the node within the network.</li>
     *   <li>If the node is an initiator, it sets up the necessary listeners for incoming connections.</li>
     *   <li>Connects to initial peers obtained from the bootstrap process.</li>
     *   <li>Starts background services for accepting connections, routing packets, and managing proxies.</li>
     *   <li>Initializes the SOCKS proxy to facilitate external applications to use the VPN network.</li>
     * </ul>
     * </p>
     *
     * @throws IOException  If there is an error during network setup, such as binding to the specified port.
     * @throws Exception    If the proof of work cannot be solved or other initialization errors occur.
     */
    public void start() throws IOException, Exception {
        // Solve initial proof of work
        if (!pow.solve()) {
            throw new RuntimeException("Failed to generate initial proof of work");
        }

        try {
            if (isInitiator) {
                log.info("Starting initiator node on port {}", port);

                // Create and start initiator connection
                VPNConnection serverConn = new VPNConnection("0.0.0.0", port, true, nodeId, pow);
                serverConn.setGossipHandler(this);

            } else {
                // For non-initiator nodes
                try {
                    // First try to find and connect to peers
                    Set<InetSocketAddress> peers_ = peerDiscovery.bootstrap();
                    if (peers_.isEmpty()) {
                        throw new IOException("Could not find any peers");
                    }
                    connectToInitialPeers(peers_);

                    // We're already connected and listening through the VPNConnection 
                    // created in connectToInitialPeers - no need for a second listener
                    log.info("Connected to peers successfully, ready for traffic");

                } catch (IOException e) {
                    log.error("Failed to initialize network: {}", e.getMessage());
                    throw e;
                }
            }

            // Start services that are common to both modes
            // Start threads with debug logging
            executor.submit(() -> {
                Thread.currentThread().setName("AcceptConnectionsThread");
                log.info("Starting AcceptConnectionsThread");
                acceptConnections();
            });

            executor.submit(() -> {
                Thread.currentThread().setName("RoutePacketsThread");
                log.info("Starting RoutePacketsThread");
                routePackets();
            });

            // Start SOCKS proxy
            try {
                int socksPort = port + 1;  // Use next port for SOCKS proxy
                log.info("Starting SOCKS proxy on port {}", socksPort);
                new SocksProxy(networkStack.getUDPHandler(), socksPort);
                log.info("SOCKS proxy started successfully on port {}", socksPort);
            } catch (IOException e) {
                log.error("Failed to start SOCKS proxy: {}", e.getMessage());
                throw e;
            }

            log.info("Network node fully started and ready for connections");
        } catch (Exception e) {
            log.error("Failed to start network: {}", e.getMessage());
            throw e;
        }
    }




    /**
     * Continuously listens for and accepts incoming peer connection requests.
     *
     * <p>
     * This method runs in a dedicated thread and handles new connections by delegating them to
     * the {@link #handleNewPeer(Socket)} method. It ensures that the node can accept multiple
     * peer connections concurrently, respecting the maximum peer limit.
     * </p>
     */
       private void acceptConnections() {
        Thread.currentThread().setName("P2P-AcceptLoop");
        Thread.currentThread().setPriority(Thread.NORM_PRIORITY);
        
        try {
            log.info("Starting accept loop with socket timeout: {}", 
                serverSocket.getSoTimeout());
            
            serverSocket.setReuseAddress(true);
            serverSocket.setSoTimeout(1000); // 1 second timeout
            
            while (running && !Thread.currentThread().isInterrupted()) {
                try {
                    Socket socket = serverSocket.accept();
                    socket.setSoTimeout(SOCKET_TIMEOUT);

                    if (peers.size() >= MAX_PEERS) {
                        log.warn("Rejecting connection from {}: peer limit reached", 
                            socket.getInetAddress());
                        socket.close();
                        continue;
                    }

                    // Submit connection handling with a meaningful thread name
                    executor.submit(() -> {
                        Thread.currentThread().setName("P2P-PeerHandler-" + socket.getInetAddress());
                        Thread.currentThread().setPriority(Thread.MIN_PRIORITY);
                        try {
                            handleNewPeer(socket);
                        } catch (Exception e) {
                            log.error("Error handling new peer: {}", e.getMessage());
                        }
                    });

                } catch (SocketTimeoutException e) {
                    // This is expected, just continue
                    Thread.sleep(100);
                } catch (IOException e) {
                    if (running) {
                        log.error("Error accepting connection: {}", e.getMessage());
                        Thread.sleep(1000); // Back off on error
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.info("Accept loop interrupted");
        } catch (Exception e) {
            log.error("Fatal error in accept loop: {}", e.getMessage());
        }
    }
    
    /**
     * Continuously retrieves and routes network packets based on routing decisions.
     *
     * <p>
     * This method operates in a loop, fetching packets from the {@link SwarmRouter} and determining
     * their appropriate destinations. It ensures efficient packet routing by handling each packet
     * asynchronously and updating relevant routing metrics.
     * </p>
     */
    private void routePackets() {
        Thread.currentThread().setName("P2P-PacketRouter");
        Thread.currentThread().setPriority(Thread.MIN_PRIORITY);

        int emptyCount = 0;
        while (running && !Thread.currentThread().isInterrupted()) {
            try {
                ByteBuffer packet = router.getNextPacket();
                if (packet != null) {
                    routePacket(packet);
                    emptyCount = 0;
                } else {
                    emptyCount++;
                    // Exponential backoff with max delay of 1 second
                    long sleepTime = Math.min(10L * emptyCount, 1000L);
                    Thread.sleep(sleepTime);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("Error routing packet: {}", e.getMessage());
                try {
                    Thread.sleep(100); // Brief pause on error
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }
    }
        private void logThreadState() {
        Thread currentThread = Thread.currentThread();
        log.debug("Thread {} (ID: {}) executing, priority: {}", 
            currentThread.getName(),
            currentThread.getId(),
            currentThread.getPriority());
        
        // Print stack trace for debugging
        StackTraceElement[] stackTrace = currentThread.getStackTrace();
        StringBuilder sb = new StringBuilder();
        for (StackTraceElement element : stackTrace) {
            sb.append("\n\tat ").append(element);
        }
        log.debug("Stack trace: {}", sb);
    }
    /**
     * Routes a single network packet to its designated destination.
     *
     * <p>
     * This method parses the incoming packet to determine its destination IP address, retrieves
     * the next hop using the {@link SwarmRouter}, and forwards the packet through the appropriate
     * peer's {@link VPNConnection}. It also applies NAT processing and updates routing metrics based
     * on the packet's transmission.
     * </p>
     *
     * @param packet The {@link ByteBuffer} containing the raw IP packet data to be routed.
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
     * Processes an incoming network packet from a specific peer.
     *
     * <p>
     * This method analyzes the packet to determine if it is destined for the local network or needs
     * to be forwarded to another peer. It updates routing metrics based on the packet's source and
     * destination, and ensures that packets intended for the local subnet are injected into the
     * virtual network interface.
     * </p>
     *
     * @param packet      The {@link ByteBuffer} containing the raw IP packet data.
     * @param sourcePeer  The identifier of the peer from which the packet was received.
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
     * <p>
     * This method calculates and updates metrics such as latency and bandwidth for the route
     * through the specified peer. These metrics inform routing decisions and help optimize
     * packet forwarding within the network.
     * </p>
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
     * Estimates the bandwidth for a specific peer based on recent packet transmissions.
     *
     * <p>
     * This method calculates the bandwidth by summing the bytes sent and received from the peer
     * over a defined duration and normalizes it to bytes per second. It provides an estimate of
     * the current network capacity with the peer.
     * </p>
     *
     * @param peer          The {@link Peer} for which bandwidth is being calculated.
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
     * Searches for a peer based on its identifier.
     *
     * <p>
     * This method iterates through the list of active peers to find a peer that matches the
     * provided identifier. It is used to retrieve peer details required for routing decisions.
     * </p>
     *
     * @param peerId The identifier of the peer to find.
     * @return The {@link Peer} instance if found; {@code null} otherwise.
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
     * <p>
     * This method extracts the subnet portion of the node's IP address to determine the range
     * of IP addresses that are considered part of the local network. It is used for routing
     * decisions and NAT processing.
     * </p>
     *
     * @return A {@link String} representing the local subnet (e.g., "10.0.0").
     */
    private String getLocalSubnet() {
        return ipAddress.substring(0, ipAddress.lastIndexOf('.'));
    }
    
    /**
     * Determines whether a given IP address belongs to the local network.
     *
     * <p>
     * This method checks if the provided IP address falls within the node's local subnet. It is
     * used to decide whether to inject packets into the local network interface or to route them
     * through the P2P network.
     * </p>
     *
     * @param ipAddress The IP address to evaluate.
     * @return {@code true} if the IP address is within the local subnet; {@code false} otherwise.
     */
    private boolean isForLocalNetwork(String ipAddress) {
        String ourSubnet = this.ipAddress.startsWith("10.0.0") ? "10.0.0" : "10.0.1";
        return ipAddress.startsWith(ourSubnet);
    }

    
    /**
     * Conducts a handshake with a connected peer to establish a secure communication channel.
     *
     * <p>
     * This method exchanges peer information and proofs of work to authenticate the peer and
     * validate its legitimacy within the network. It ensures that both parties agree on their
     * identities and have performed the necessary computational work to participate in the network.
     * </p>
     *
     * @param conn The {@link VPNConnection} instance representing the connection to the peer.
     * @throws IOException If the handshake fails due to I/O errors or invalid data exchange.
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
     * Handles the establishment of a new peer connection by performing handshake procedures and validating proofs of work.
     *
     * <p>
     * This method ensures that the connecting peer is authenticated and meets the network's proof-of-work
     * requirements. Upon successful validation, it initializes the peer's connection details and integrates
     * the peer into the network routing mechanisms.
     * </p>
     *
     * @param address The IP address of the new peer.
     * @param port    The port number of the new peer.
     * @param conn    The {@link VPNConnection} instance representing the connection to the peer.
     * @throws Exception If there is an error during the handshake or validation process.
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
     * Initializes and sets up a new peer connection from an accepted socket.
     *
     * <p>
     * This method creates a {@link VPNConnection} instance for the newly connected peer, assigns
     * appropriate handlers, and prepares the connection for data transmission. It ensures that the
     * peer is integrated into the network's routing and NAT mechanisms.
     * </p>
     *
     * @param socket The {@link Socket} representing the incoming peer connection.
     */
    private void handleNewPeer(Socket socket) {
        try {
            log.info("Setting up new peer connection from: {}", socket.getInetAddress());
            
            // Create VPN connection with handler
            VPNConnection conn = new VPNConnection(null, port, isInitiator, this.nodeId);
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
     * Retrieves the UDP handler responsible for managing UDP traffic within the network stack.
     *
     * <p>
     * This method provides access to the {@link UDPHandler} instance from the {@link NetworkStack},
     * allowing for direct manipulation or monitoring of UDP-based VPN traffic.
     * </p>
     *
     * @return The {@link UDPHandler} associated with this network node.
     */
    public UDPHandler getUDPHandler() {
        return networkStack.getUDPHandler();
    }

    /**
     * Initiates a connection to a specified peer using its address and port.
     *
     * <p>
     * This method attempts to establish a secure connection to the given peer by creating a {@link VPNConnection}.
     * It employs an exponential backoff strategy for connection retries and respects the maximum peer limit.
     * Upon successful connection, the peer is integrated into the network's routing and NAT systems.
     * </p>
     *
     * @param address The IP address of the peer to connect to.
     * @param port    The port number of the peer to connect to.
     * @throws IOException If the connection attempt fails after exhausting all retry attempts.
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
    
                // Create connection with pow instance
                VPNConnection conn = new VPNConnection(address, port, isInitiator, nodeId, pow);
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
     * Manages the data traffic from a connected peer by continuously receiving and processing packets.
     *
     * <p>
     * This method runs in a separate thread, listening for incoming VPN packets from the specified peer.
     * It updates latency metrics based on packet reception times and delegates packet processing to
     * the {@link #processIncomingPacket(ByteBuffer, String)} method. If the connection is disrupted,
     * the peer is removed from the network.
     * </p>
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
     * Sends the initial routing information to a newly connected peer to establish routing pathways.
     *
     * <p>
     * This method prepares and transmits the current routing table and peer information to the specified
     * peer using gossip messages. It ensures that both nodes have a consistent view of the network's routing
     * state, facilitating efficient packet forwarding and network synchronization.
     * </p>
     *
     * @param peer The {@link Peer} instance representing the newly connected peer.
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
     * Removes a peer from the network, updating routing tables and cleaning up associated resources.
     *
     * <p>
     * This method deregisters the peer from the active peers list, removes any associated routes
     * from the {@link SwarmRouter}, and closes the peer's {@link VPNConnection}. It also cleans up
     * traffic statistics related to the peer and triggers peer count checks to maintain network health.
     * </p>
     *
     * @param peer The {@link Peer} instance to be removed from the network.
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
     * Verifies that the network maintains the minimum required number of active peers.
     *
     * <p>
     * If the current peer count falls below the defined minimum, this method initiates a bootstrap
     * process to discover and connect to new peers, ensuring network robustness and reliability.
     * </p>
     */
    private void checkPeerCount() {
        if (peers.size() < MIN_PEERS || peerDiscovery.needsBootstrap()) {
            try {
                Set<InetSocketAddress> newPeers = peerDiscovery.bootstrap();
                connectToInitialPeers(newPeers);
            } catch (IOException e) {
                log.warn("Failed to bootstrap new peers: {}", e.getMessage());
            }
        }
    }
    
    /**
     * Initiates a search for new peers by requesting peer lists from existing connections.
     *
     * <p>
     * This method broadcasts peer discovery requests to currently connected peers via gossip messages,
     * allowing the node to expand its peer list and reinforce network connectivity. It ensures that
     * the network remains decentralized and resilient against peer disconnections.
     * </p>
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
     * Executes the gossip protocol to share routing information and known peers with a subset of connected peers.
     *
     * <p>
     * This method selects a random subset of active peers and transmits the current network state,
     * including routing tables and peer lists. Gossiping helps in disseminating network information
     * efficiently, aiding in peer discovery and maintaining synchronized routing paths across the network.
     * </p>
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
     * Processes an incoming gossip message by updating routing tables and discovering new peers.
     *
     * <p>
     * This method validates the received gossip message and integrates any new routing information
     * or peer data into the network. It ensures that the node's routing decisions are informed by
     * the collective knowledge of connected peers, enhancing network efficiency and connectivity.
     * </p>
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
     * Updates the proof of work by generating a new proof and broadcasting it to all connected peers.
     *
     * <p>
     * This method periodically solves a new proof of work to maintain the node's authenticated status
     * within the network. Upon successfully generating a new proof, it disseminates the proof to all
     * peers via gossip messages, ensuring that the network acknowledges the node's ongoing participation.
     * </p>
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
     * Sends keepalive messages to all connected peers to maintain active connections and detect inactive peers.
     *
     * <p>
     * This method periodically transmits ping messages to each peer, signaling the node's continued presence
     * within the network. Receiving acknowledgments from peers confirms active connections, while missing responses
     * may indicate stale or disconnected peers, prompting their removal from the network.
     * </p>
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
     * Evaluates the health of all connected peers and removes any that are deemed stale or unresponsive.
     *
     * <p>
     * This method iterates through the list of active peers, checking metrics such as last seen timestamps
     * and latency. Peers that have not communicated within a defined threshold or exhibit poor performance
     * are removed to maintain network integrity and performance.
     * </p>
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
     * Determines the subnet for a given IP address.
     *
     * <p>
     * This method extracts the subnet portion from the provided IP address, facilitating routing
     * decisions and network segmentation. It assumes a standard IPv4 address format.
     * </p>
     *
     * @param ipAddress The IP address for which the subnet is to be determined.
     * @return A {@link String} representing the subnet in CIDR notation (e.g., "10.0.0.0/24").
     */
    private String getSubnetForIP(String ipAddress) {
        return ipAddress.substring(0, ipAddress.lastIndexOf('.')) + ".0/24";
    }
    
    /**
     * Aggregates and retrieves comprehensive network statistics.
     *
     * <p>
     * This method compiles various metrics such as active peers, traffic statistics, latency,
     * bandwidth estimates, routing information, proof of work status, and NAT mappings. The
     * returned data is suitable for monitoring tools, dashboards, or diagnostic purposes.
     * </p>
     *
     * @return A {@link Map} containing key-value pairs of network statistics and metrics.
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
     * Retrieves detailed information about all active peers in the network.
     *
     * <p>
     * This method collects and formats data such as each peer's address, port, node ID, latency,
     * bandwidth usage, traffic statistics, last seen timestamp, and routing scores. The information
     * is structured in a list of maps for easy consumption by external systems or for display purposes.
     * </p>
     *
     * @return A {@link List} of {@link Map} objects, each containing detailed attributes of a peer.
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
     * Generates a comprehensive string representation of the current routing table.
     *
     * <p>
     * This method iterates through all active routes, detailing each destination, the next hop,
     * hop count, pheromone score, latency, and bandwidth. The output is formatted for readability,
     * making it useful for diagnostics and network monitoring.
     * </p>
     *
     * @return A {@link String} containing the formatted routing table information.
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
     *
     * <p>
     * This method gathers current network metrics and outputs them to the logging system at
     * regular intervals. It includes information such as peer counts, traffic volumes, latency,
     * bandwidth, routing details, and proof of work status. These logs are instrumental in
     * assessing the network's health and performance over time.
     * </p>
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
     * Converts a byte count into a human-readable string with appropriate units.
     *
     * <p>
     * This utility method formats large byte values into kilobytes (KB), megabytes (MB),
     * gigabytes (GB), etc., enhancing the readability of traffic statistics and other
     * byte-based metrics.
     * </p>
     *
     * @param bytes The number of bytes to format.
     * @return A {@link String} representing the formatted byte count with units.
     */
    private String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        int exp = (int) (Math.log(bytes) / Math.log(1024));
        String pre = "KMGTPE".charAt(exp-1) + "";
        return String.format("%.1f %sB", bytes / Math.pow(1024, exp), pre);
    }
    
    /**
     * Retrieves a list of all active peers in the network in a formatted string representation.
     *
     * <p>
     * This method compiles a list of peer addresses along with their corresponding ports and
     * cumulative traffic statistics. The output is structured for easy display or logging.
     * </p>
     *
     * @return A {@link List} of {@link String} objects, each representing an active peer and its traffic.
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
     * Evaluates the overall health of the network node based on various criteria.
     *
     * <p>
     * This method assesses multiple aspects such as the node's running status, peer count,
     * proof of work freshness, active routing paths, and the health metrics of connected peers.
     * It returns {@code true} if the network meets all health criteria, indicating optimal operation.
     * Otherwise, it returns {@code false}, signaling potential issues that may require attention.
     * </p>
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
     * Registers a callback function to receive periodic network statistics updates.
     *
     * <p>
     * This method allows external components or monitoring tools to receive real-time network
     * statistics by providing a {@link Consumer} that processes the statistics map. The callback
     * is invoked at fixed intervals, enabling continuous monitoring and dynamic responses based
     * on network performance.
     * </p>
     *
     * @param callback A {@link Consumer} that accepts a {@link Map} of network statistics.
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
     * Gracefully shuts down the P2P network node by notifying peers, terminating threads, and releasing resources.
     *
     * <p>
     * This method performs the following actions to ensure a clean shutdown:
     * <ul>
     *   <li>Sets the running flag to {@code false} to signal all threads to terminate.</li>
     *   <li>Notifies all connected peers of the shutdown by sending a ping message with a specific payload.</li>
     *   <li>Closes the server socket and shuts down scheduled and executor thread pools.</li>
     *   <li>Removes all active peers from the network, ensuring that routing tables and statistics are cleared.</li>
     *   <li>Logs the shutdown process to aid in monitoring and debugging.</li>
     * </ul>
     * </p>
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
     * Serializes and exports the current network state for persistence or transfer purposes.
     *
     * <p>
     * This method gathers essential network information, including node identifiers, IP addresses,
     * ports, proof of work data, known peers, and active routes. The serialized state can be used
     * to restore the network node's configuration or migrate it to a different environment.
     * </p>
     *
     * @return A {@link Map} containing key-value pairs representing the network's serialized state.
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
     * Imports and restores the network state from a serialized map.
     *
     * <p>
     * This static method reconstructs a {@link P2PNetwork} instance based on the provided serialized
     * state. It initializes network configurations, reconnects to known peers, and restores routing
     * tables to reestablish the network node's previous operational state.
     * </p>
     *
     * @param state A {@link Map} containing the serialized network state to import.
     * @return A new {@link P2PNetwork} instance initialized with the imported state.
     * @throws IOException If there is an error during the state import process.
     */
    public static P2PNetwork importState(Map<String, Object> state) throws IOException {
        int port = (Integer) state.get("port");
        String ipAddress = (String) state.get("ipAddress");
        boolean isInitiator = ipAddress.equals("10.0.0.1");
        
        P2PNetwork network = new P2PNetwork(port, isInitiator, ipAddress);
        
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
     * Generates a comprehensive diagnostic report of the network node.
     *
     * <p>
     * This method compiles detailed information about the node's current status, including peer health,
     * network metrics, routing tables, security status, and overall network integrity. The diagnostic
     * report is formatted as a human-readable string, making it suitable for logging, monitoring, and
     * troubleshooting purposes.
     * </p>
     *
     * @return A {@link String} containing the formatted diagnostic report of the network node.
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
     * Tests the local network connectivity by attempting to bind to the node's designated port.
     *
     * <p>
     * This method verifies whether the specified port is available and can be successfully bound,
     * ensuring that the node can listen for incoming peer connections. It is useful for diagnosing
     * network configuration issues and verifying that the node is ready to operate within the network.
     * </p>
     *
     * @return {@code true} if the port is available and the node can bind to it; {@code false} otherwise.
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
     * Provides a concise string representation of the P2P network node's current status.
     *
     * <p>
     * This method formats essential information such as the node's identifier, IP address, port,
     * active peer count, and routing table size into a single string. It is useful for logging and
     * quick status checks.
     * </p>
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
     * Processes an incoming gossip message by validating and updating network routing and peer information.
     *
     * <p>
     * This method implements the {@link GossipMessage.GossipHandler} interface, allowing the node to
     * react to gossip messages received from peers. It ensures that only valid gossip messages are
     * processed and integrates new routing information and peer data to maintain an up-to-date network state.
     * </p>
     *
     * @param message The {@link GossipMessage} received from a peer.
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
     * Handles an incoming proof of work message by updating the peer's proof and timestamp.
     *
     * <p>
     * This method implements the proof handling mechanism to ensure that peers maintain valid and
     * up-to-date proofs of work. It verifies the received proof against the node's criteria and updates
     * the peer's proof information accordingly.
     * </p>
     *
     * @param proof     The byte array containing the proof of work data received from the peer.
     * @param timestamp The timestamp associated with the received proof of work.
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
     * Updates the last seen timestamp for a peer based on received peer information.
     *
     * <p>
     * This method implements the peer information handling to track active peers within the network.
     * It updates the last seen timestamp to reflect recent communication, aiding in peer health assessment
     * and routing decisions.
     * </p>
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

