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

import org.publiuspseudis.esadvpn.protocol.GossipMessage;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.publiuspseudis.esadvpn.crypto.ProofOfWork;
import org.publiuspseudis.esadvpn.network.P2PNetwork;
import org.publiuspseudis.esadvpn.crypto.SecureChannel;
import org.publiuspseudis.esadvpn.protocol.NetworkProtocolHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code VPNConnection} class manages a secure Virtual Private Network (VPN) connection within
 * the peer-to-peer (P2P) network. It implements the {@link NetworkProtocolHandler} interface to handle
 * various network protocols and the {@link AutoCloseable} interface to ensure proper resource management.
 * </p>
 * 
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Establishing and managing secure channels using cryptographic protocols.</li>
 *   <li>Handling different types of VPN messages, including data packets, gossip messages, proofs of work,
 *       peer information, and keepalive pings.</li>
 *   <li>Managing connection phases to track the state of the VPN connection.</li>
 *   <li>Performing handshakes and maintaining the integrity of the secure channel.</li>
 *   <li>Tracking connection statistics such as bytes sent, bytes received, latency, and bandwidth estimates.</li>
 *   <li>Integrating with swarm intelligence-based routing mechanisms.</li>
 *   <li>Ensuring thread-safe operations and proper shutdown procedures.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Initialize VPNConnection as a client
 * VPNConnection vpnConnection = new VPNConnection("peer.example.com", 51820, false);
 * 
 * // Set a connection handler
 * vpnConnection.setConnectionHandler(new P2PNetwork.ConnectionHandler() {
 *     @Override
 *     public void onNewConnection(String host, int port, VPNConnection connection) {
 *         System.out.println("Connected to " + host + ":" + port);
 *     }
 * });
 * 
 * // Send a data packet
 * byte[] data = "Hello, VPN!".getBytes(StandardCharsets.UTF_8);
 * vpnConnection.sendPacket(data);
 * 
 * // Receive a data packet
 * byte[] receivedData = vpnConnection.receivePacket();
 * if (receivedData != null) {
 *     String message = new String(receivedData, StandardCharsets.UTF_8);
 *     System.out.println("Received: " + message);
 * }
 * 
 * // Close the VPN connection
 * vpnConnection.close();
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>
 * </p>
 * <p>
 * The {@code VPNConnection} class is designed to be thread-safe. It employs synchronization mechanisms
 * and uses thread-safe data structures such as {@code AtomicLong} for tracking statistics. Volatile fields
 * are used to ensure visibility of changes across threads. Additionally, network operations are handled
 * in separate threads to prevent blocking and ensure responsive behavior.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>{@link SecureChannel}: Manages encryption and decryption of messages to ensure secure communication.</li>
 *   <li>{@link GossipMessage}: Handles gossip protocol messages for peer discovery and network information sharing.</li>
 *   <li>SLF4J Logging Framework: Used for logging informational, debug, and error messages.</li>
 * </ul>
 * 
 * @author 
 * Publius Pseudis
 */
public final class VPNConnection implements NetworkProtocolHandler, AutoCloseable {
    /**
     * Unique identifier for this VPN node.
     * Used to distinguish between different nodes within the P2P network.
     */
    private final byte[] nodeId; // Unique ID for the node

    /**
     * Instance of {@link ProofOfWork} used to validate network activities.
     * Ensures that peers perform computational work to prevent spam or malicious behavior.
     */
    private final ProofOfWork pow; // Proof of Work instance

    /**
     * Atomic flag indicating whether the listener thread is actively processing incoming packets.
     * Ensures thread-safe updates to the listener's active state.
     */
    private final AtomicBoolean listenerActive = new AtomicBoolean(false);

    /**
     * Latch used to signal when the listener thread is ready to receive packets.
     * Ensures that initialization processes wait until the listener is fully operational.
     */
    private final CountDownLatch listenerReady = new CountDownLatch(1);
    
    /**
     * Sets the connection handler responsible for managing new peer connections.
     *
     * @param handler The {@link P2PNetwork.ConnectionHandler} instance to handle new connections.
     */
    public void setConnectionHandler(P2PNetwork.ConnectionHandler handler) {
        this.connectionHandler = handler;
    }
    
    /**
     * Retrieves the current phase of the VPN connection.
     *
     * @return The current {@link ConnectionPhase} of the connection.
     */
    public ConnectionPhase getCurrentPhase() {
        return currentPhase;
    }
    /**
     * Checks whether the VPN connection is currently running.
     *
     * @return {@code true} if the connection is running; {@code false} otherwise.
     */
    public boolean isRunning() {
        return running;
    }

    /**
     * Sets the running state of the VPN connection.
     *
     * @param running {@code true} to mark the connection as running; {@code false} to stop it.
     */
    public void setRunning(boolean running) {
        this.running = running;
    }
    
    // =====================
    // Fields
    // =====================

    /**
     * Handles incoming peer connections by implementing the {@link P2PNetwork.ConnectionHandler} interface.
     * This handler manages the logic for establishing and maintaining connections with new peers.
     */
    private P2PNetwork.ConnectionHandler connectionHandler;
    
    /**
     * Represents the current phase of the VPN connection lifecycle.
     * Initialized to {@link ConnectionPhase#INITIAL}.
     */
    private volatile ConnectionPhase currentPhase = ConnectionPhase.INITIAL;
    
    /**
     * The thread responsible for listening to incoming VPN messages.
     * Runs concurrently to handle network communication without blocking the main thread.
     */    
    private volatile Thread listenerThread;
    
    /**
     * Logger instance from SLF4J for logging informational, debug, and error messages.
     * Utilized throughout the class to trace execution flow and record significant events.
     */
    private static final Logger log = LoggerFactory.getLogger(VPNConnection.class);
    
    // =====================
    // Message Types
    // =====================

     /**
     * Message type identifier for echo request messages.
     * Used during connectivity tests to verify UDP communication between peers.
     */
    public static final byte ECHO_REQUEST = 0x01;

    /**
     * Message type identifier for echo response messages.
     * Sent in reply to {@code ECHO_REQUEST} messages to confirm successful UDP communication.
     */
    public static final byte ECHO_RESPONSE = 0x2;

    
    
    /**
     * Message type identifier for data packets.
     * Used to distinguish data payloads from other message types in the VPN communication protocol.
     */
    public static final byte MSG_TYPE_DATA = 0x01;     // Data packet
    
    /**
     * Message type identifier for gossip messages.
     * Facilitates peer list updates and dissemination of network information among peers.
     */
    public static final byte MSG_TYPE_GOSSIP = 0x02;   // Peer list update
    
    /**
     * Message type identifier for proofs of work.
     * Used to validate network activities and prevent spam or malicious behavior.
     */
    public static final byte MSG_TYPE_PROOF = 0x03;    // Proof of work
    
    /**
     * Message type identifier for peer information.
     * Carries metadata about peers, such as public keys and connection details.
     */
    public static final byte MSG_TYPE_PEER_INFO = 0x04;// Peer information
    
    /**
     * Message type identifier for keepalive pings.
     * Ensures the connection remains active and detects stale or disconnected peers.
     */
    public static final byte MSG_TYPE_PING = 0x05;     // Keepalive ping
    
    /**
     * Special message type identifier for echo tests.
     * Utilized during connectivity tests to verify UDP communication between peers.
     */
    private static final byte MSG_TYPE_ECHO = 0x06;  // Special test message type
    public static final byte MSG_TYPE_VERIFY = 0x07;  // Verification request
    // =====================
    // Network Constants
    // =====================
    
    /**
     * Default VPN port number, aligning with WireGuard's standard port.
     * Serves as the primary port for establishing VPN connections.
     */    
    public static final int VPN_PORT = 51820;          // Default VPN port (same as WireGuard)
    
    /**
     * Duration in milliseconds before a socket operation times out.
     * Determines how long the socket waits for data before throwing a {@link SocketTimeoutException}.
     */
    private static final int SOCKET_TIMEOUT = 5000;    // 5 second socket timeout
    
    /**
     * Maximum allowable size for a UDP packet in bytes.
     * Ensures that packets do not exceed network transmission limits.
     */
    private static final int MAX_PACKET_SIZE = 65536;  // Maximum UDP packet size
    
    /**
     * Size of the buffer used for reading incoming UDP packets.
     * Balances memory usage and the ability to handle large packets.
     */
    private static final int BUFFER_SIZE = 16384;      // Read buffer size
    
    
    /**
     * Mapping of message type identifiers to their corresponding human-readable names.
     * Facilitates logging and debugging by providing meaningful names for message types.
     */
    private final Map<Byte, String> MESSAGE_TYPE_NAMES = new HashMap<>() {{
        put(MSG_TYPE_DATA, "DATA");
        put(MSG_TYPE_GOSSIP, "GOSSIP");
        put(MSG_TYPE_PROOF, "PROOF");
        put(MSG_TYPE_PEER_INFO, "PEER_INFO");
        put(MSG_TYPE_PING, "PING");
        put(MSG_TYPE_ECHO, "ECHO");
        put(MSG_TYPE_VERIFY, "VERIFY");
    }};


    
    
    // =====================
    // Connection Components
    // =====================
    
    /**
     * UDP socket used for sending and receiving VPN traffic.
     * Facilitates low-latency, connectionless communication between peers.
     */
    private  DatagramSocket socket = null;

    /**
     * Instance of {@link SecureChannel} managing encryption and decryption of messages.
     * Ensures that all transmitted data remains confidential and tamper-proof.
     */
    private final SecureChannel crypto;
    
    /**
     * Address of the connected peer, encapsulating both hostname/IP and port number.
     * Represents the remote endpoint for VPN communication.
     */
    private InetSocketAddress peerAddress;
    
    /**
     * Indicates whether the VPN connection is currently active and operational.
     * Controls the execution of listener threads and network operations.
     */
    private volatile boolean running;
    
    // =====================
    // Statistics
    // =====================
    
    /**
     * Atomic counter tracking the total number of bytes sent over the VPN connection.
     * Provides a thread-safe mechanism for accumulating sent data statistics.
     */    
    private final AtomicLong bytesSent;
    
    /**
     * Atomic counter tracking the total number of bytes received over the VPN connection.
     * Ensures accurate and thread-safe aggregation of incoming data statistics.
     */
    private final AtomicLong bytesReceived;
    
    /**
     * The most recent latency measurement of the VPN connection in milliseconds.
     * Reflects the time taken for data to travel between peers.
     */
    private volatile double lastLatency;

    /**
     * The latest estimated bandwidth of the VPN connection in bytes per second.
     * Calculated based on recent data transmission rates.
     */
    private volatile long lastBandwidthEstimate;

    /**
     * Timestamp marking the last reset of statistical counters.
     * Used to calculate bandwidth estimates over defined intervals.
     */
    private long lastStatsReset;
    
    /**
     * Instance of {@link GossipMessage} handling gossip protocol messages.
     * Manages peer discovery and dissemination of network state information.
     */
    private GossipMessage gossipHandler;

    // =====================
    // Connection State
    // =====================

    /**
     * Timestamp of the last received UDP packet in milliseconds.
     * Used to determine if the connection has become stale due to inactivity.
     */
    private volatile long lastReceivedTime;

    /**
     * Indicates whether the initial handshake with the peer has been successfully completed.
     * Determines if the secure channel is established and ready for data transmission.
     */
    private volatile boolean handshakeCompleted;

    /**
     * Threshold in milliseconds to consider a VPN connection as stale.
     * If the time since the last received packet exceeds this value, the connection is deemed inactive.
     */
    private static final long STALE_THRESHOLD = 30000; // 30 seconds

    /**
     * Flag indicating whether this {@code VPNConnection} instance is operating in server mode.
     * Controls behaviors specific to server-side operations, such as listening for incoming connections.
     */
    private final boolean isServer;

    /**
     * The last received UDP packet stored for processing.
     * Utilized during handshake and connection establishment phases.
     */
    private DatagramPacket lastReceivedPacket = null;

    // =====================
    // Constructors and Methods
    // =====================
        
    /**
     * Establishes a connection to a specified peer within the P2P VPN network.
     *
     * @param bindAddress
     * @param port  The port number on which the peer is listening.
     * @param isInitiator  Indicates whether the connection is being established as a server.
     * @param nodeId node id
     * @param pow instance of proof of work
     * @throws java.lang.Exception If an error occurs while attempting to connect to the peer.
     */
    public VPNConnection(String bindAddress, int port, boolean isInitiator, byte[] nodeId, ProofOfWork pow) throws Exception {
        if (nodeId == null) {
            throw new IllegalArgumentException("nodeId cannot be null");
        }
        this.nodeId = nodeId;
        this.pow = (pow != null) ? pow : new ProofOfWork(nodeId);
        this.isServer = isInitiator;
        setRunning(true);
        this.currentPhase = ConnectionPhase.INITIAL;

        // Initialize crypto and metrics first
        this.crypto = new SecureChannel();
        this.bytesSent = new AtomicLong(0);
        this.bytesReceived = new AtomicLong(0);
        this.lastLatency = Double.MAX_VALUE;
        this.lastBandwidthEstimate = 0;
        this.lastStatsReset = System.currentTimeMillis();
        this.lastReceivedTime = System.currentTimeMillis();

        try {
            // Create socket
            this.socket = new DatagramSocket(null);
            this.socket.setReuseAddress(true);
            this.socket.setSoTimeout(isServer ? SOCKET_TIMEOUT : 1000);

            // Set up socket options
            try {
                this.socket.setTrafficClass(0x2E);
                this.socket.setReceiveBufferSize(BUFFER_SIZE);
                this.socket.setSendBufferSize(BUFFER_SIZE);
            } catch (SocketException e) {
                log.warn("Could not set socket performance parameters: {}", e.getMessage());
            }

            // If we're a client connecting to a peer, use our own port for binding
            if (!isInitiator) {
                // Store peer address for later use
                this.peerAddress = new InetSocketAddress(bindAddress, port);

                // For the client, bind to any available port
                InetSocketAddress bindAddr = new InetSocketAddress(
                    "0.0.0.0",  // Bind to all interfaces
                    0  // Let the system assign an available port
                );

                log.info("Client binding to {}", bindAddr);
                this.socket.bind(bindAddr);
                log.info("Client assigned port: {}", socket.getLocalPort());

                // Perform connection steps
                testUDPSocket();
                echoTest();
                performHandshake();
            } else {
                // Server mode - bind to specified port
                InetSocketAddress bindAddr = new InetSocketAddress(
                    "0.0.0.0",  // Bind to all interfaces
                    port
                );

                log.info("Server binding to {}", bindAddr);
                this.socket.bind(bindAddr);

                testUDPSocket();
                startServerListener();
            }

            log.debug("Set socket buffer sizes: send={}, receive={}",
                socket.getSendBufferSize(), socket.getReceiveBufferSize());

        } catch (Exception e) {
            log.error("VPNConnection initialization failed: {}", e.getMessage(), e);
            setRunning(false);
            if (socket != null) {
                socket.close();
            }
            throw e;
        }
    }
    
    /**
    * Performs a basic test of the UDP socket by sending a test packet if acting as a client
    * and logs the socket's configuration details.
    *
    * <p>
    * This method is used during initialization to ensure that the socket is properly bound
    * and capable of sending packets. It sends a test packet to the peer if the connection
    * is not in server mode.
    * </p>
    */
    private void testUDPSocket() {
        try {
            String msg = isServer ? "Server socket test" : "Client socket test";
            log.info("{}: Local port={}, Bound={}, Connected={}, Address={}",  
                msg,
                socket.getLocalPort(),
                socket.isBound(),
                socket.isConnected(),
                socket.getLocalAddress());

            if (!isServer && peerAddress != null) {
                // Simple UDP test packet
                byte[] test = new byte[] {1,2,3,4};
                DatagramPacket packet = new DatagramPacket(test, test.length, peerAddress);
                socket.send(packet);
                log.info("Sent test packet to {}", peerAddress);
            }
        } catch (IOException e) {
            log.error("Socket test failed: {}", e.getMessage());
        }
    }
     /**
     * Sets the socket timeout duration.
     *
     * @param timeout The timeout duration in milliseconds.
     * @throws SocketException If an error occurs while setting the socket timeout.
     */
    public void setTimeout(int timeout) throws SocketException {
        if (socket != null) {
            socket.setSoTimeout(timeout);
        }
    }

    /**
     * Initializes and starts the server listener thread to handle incoming UDP packets.
     *
     * <p>
     * This method sets up a dedicated listener thread that continuously listens for incoming
     * UDP packets from peers. It processes different message types based on the current connection
     * phase and delegates handling to appropriate methods.
     * </p>
     *
     * @throws IOException If an error occurs while binding the socket or starting the listener.
     */
    private void startServerListener() throws IOException {
        if (!isServer) return;

        listenerThread = new Thread(() -> {
            log.debug("[UDP-Listener] Server listener starting on port {}", socket.getLocalPort());
            listenerActive.set(true);
            byte[] buffer = new byte[MAX_PACKET_SIZE];
            DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

            try {
                // Signal that we're ready to receive
                listenerReady.countDown();

                while (running && listenerActive.get()) {
                    try {
                        socket.receive(packet);

                        if (packet.getLength() > 0) {
                            ByteBuffer msg = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());
                            byte type = msg.get();

                            log.debug("[UDP-Listener] Received message type {} size {} from {}", 
                                type, packet.getLength(), packet.getSocketAddress());

                            // Handle verification request immediately
                            if (type == 0x01) {
                                handleFirstMessage(packet);
                                continue;
                            }

                            // Handle echo requests immediately regardless of state
                            if (type == MSG_TYPE_ECHO) {
                                handleEchoPacket(packet);
                                continue;
                            }

                            // Check for connection from new peer
                            if (!packet.getSocketAddress().equals(peerAddress)) {
                                log.debug("[UDP-Listener] New peer connection from: {}", packet.getSocketAddress());
                                currentPhase = ConnectionPhase.INITIAL;
                                peerAddress = null;  // Clear existing peer
                            }

                            handleBasedOnPhase(packet, msg, type);
                        }

                    } catch (SocketTimeoutException e) {
                        // Normal timeout, continue
                    } catch (IOException e) {
                        if (running && listenerActive.get()) {
                            log.error("[UDP-Listener] Error in server listener: {}", e.getMessage());
                        }
                    }
                }
            } finally {
                listenerActive.set(false);
            }
                log.debug("[UDP-Listener] Server listener stopped cleanly");
            }, "UDP-Listener");

        listenerThread.setDaemon(true);
        listenerThread.start();

        // Wait for listener to be ready
        try {
            if (!listenerReady.await(5, TimeUnit.SECONDS)) {
                throw new IOException("UDP listener failed to initialize");
            }
            log.info("Server listener started on port {}", socket.getLocalPort());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while waiting for listener to start", e);
        }
    }

    /**
     * Processes an incoming echo packet by sending an appropriate echo response.
     *
     * <p>
     * This method handles {@code ECHO_REQUEST} messages by extracting the random data payload
     * and sending back an {@code ECHO_RESPONSE} with the same data. It ensures that echo
     * tests confirm successful UDP communication between peers.
     * </p>
     *
     * @param packet The received {@link DatagramPacket} containing the echo request.
     * @throws IOException If an error occurs while sending the echo response.
     */
    private void handleEchoPacket(DatagramPacket packet) throws IOException {
        if (packet.getLength() < 2) {
            log.debug("Echo packet too short, ignoring");
            return;
        }

        log.debug("Handling echo packet from {}, length: {}", 
            packet.getSocketAddress(), packet.getLength());

        ByteBuffer msg = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());
        byte type = msg.get();
        byte subtype = msg.get();

        log.debug("Echo packet type: {}, subtype: {}", type, subtype);

        if (type == MSG_TYPE_ECHO && subtype == ECHO_REQUEST) {
            // Copy just the random data portion
            byte[] randomData = new byte[msg.remaining()];
            msg.get(randomData);

            ByteBuffer response = ByteBuffer.allocate(randomData.length + 2);
            response.put(MSG_TYPE_ECHO);
            response.put(ECHO_RESPONSE);  // Make sure this is 0x02
            response.put(randomData);
            response.flip();

            log.debug("Sending echo response with {} bytes of random data to {}", 
                randomData.length, packet.getSocketAddress());

            DatagramPacket responsePacket = new DatagramPacket(
                response.array(),
                response.limit(),
                packet.getAddress(),
                packet.getPort()
            );
            socket.send(responsePacket);
        } else {
            log.debug("Ignoring non-request echo packet (type: {}, subtype: {})", 
                type, subtype);
        }
    }



     /**
     * Performs the server-side handshake by exchanging public keys and establishing a secure channel.
     *
     * @throws Exception If an error occurs during the handshake process.
     */
    public void performServerHandshake() throws Exception {
        log.debug("[UDP-Listener] Starting server handshake with peer: {}", peerAddress);

        try {
            // Get stored peer key from raw message
            ByteBuffer msg = ByteBuffer.wrap(lastReceivedPacket.getData(), 0, lastReceivedPacket.getLength());
            msg.get();  // Skip type byte
            byte[] peerKey = new byte[msg.remaining()];
            msg.get(peerKey);
            lastReceivedPacket = null;

            log.debug("[UDP-Listener] Using peer's public key, length: {}", peerKey.length);

            // Send our public key unencrypted
            byte[] publicKey = crypto.getPublicKey();
            log.debug("[UDP-Listener] Sending our public key, length: {}", publicKey.length);
            sendMessage(MSG_TYPE_PEER_INFO, publicKey);

            // Establish secure channel
            crypto.establishSecureChannel(peerKey);

            // Send acknowledgment
            log.debug("[UDP-Listener] Sending handshake acknowledgment");
            ByteBuffer ack = ByteBuffer.allocate(1);
            ack.put((byte)1);
            ack.flip();
            sendMessage(MSG_TYPE_PEER_INFO, ack.array());

            // Mark handshake as complete
            handshakeCompleted = crypto.isEstablished();

            currentPhase = ConnectionPhase.NETWORK_HANDSHAKE_COMPLETE;
            log.info("[UDP-Listener] Secure channel established with {}", peerAddress);

        } catch (IOException e) {
            handshakeCompleted = false;
            log.error("[UDP-Listener] Server handshake failed: {}", e.getMessage());
            throw e;
        }
    }
    
    /**
     * Performs an echo test to verify UDP connectivity by sending and receiving an echo packet.
     *
     * @throws IOException If the echo test fails due to no response or network issues.
     */
 
private void echoTest() throws IOException, InterruptedException {
    if (isServer || handshakeCompleted) return;

    // Create echo request with random data
    byte[] randomData = new byte[8];
    new SecureRandom().nextBytes(randomData);
    
    // Add echo message type byte and request subtype
    ByteBuffer message = ByteBuffer.allocate(10);
    message.put(MSG_TYPE_ECHO);
    message.put(ECHO_REQUEST);
    message.put(randomData);
    message.flip();

    byte[] requestPacket = message.array();
    DatagramPacket packet = new DatagramPacket(
        requestPacket, 
        requestPacket.length, 
        peerAddress
    );

    int maxAttempts = 3;
    int attemptDelay = 1000; // 1 second between attempts

    for (int attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            log.debug("Client sending echo test to {} (attempt {}/{})", 
                peerAddress, attempt, maxAttempts);
            
            socket.send(packet);

            // Create receive packet
            // Wait for response
            byte[] responseData = new byte[requestPacket.length];
            DatagramPacket responsePacket = new DatagramPacket(
                responseData, 
                responseData.length,
                peerAddress.getAddress(),
                peerAddress.getPort()
            );

            socket.setSoTimeout(1000);

            // Keep reading until we get a valid echo response or timeout
            long endTime = System.currentTimeMillis() + 1000;  // 1 second total time
            while (System.currentTimeMillis() < endTime) {
                socket.receive(responsePacket);
                
                // Skip if not an echo message
                if (responsePacket.getLength() < 2) {
                    continue;
                }

                if (responseData[0] != MSG_TYPE_ECHO) {
                    log.debug("Received non-echo message (type: {}), skipping", responseData[0]);
                    continue;
                }

                if (responseData[1] != ECHO_RESPONSE) {
                    log.debug("Received non-response echo message (subtype: {}), skipping", responseData[1]);
                    continue;
                }

                // Compare just the random data portion
                byte[] receivedRandomData = Arrays.copyOfRange(responseData, 2, responseData.length);
                byte[] sentRandomData = Arrays.copyOfRange(requestPacket, 2, requestPacket.length);
                
                if (Arrays.equals(receivedRandomData, sentRandomData)) {
                    log.debug("Received valid echo response from {}", 
                        responsePacket.getSocketAddress());
                    return; // Success
                } else {
                    log.debug("Received echo response with mismatched data");
                }
            }
            
            // If we get here, we timed out without finding a valid response
            if (attempt == maxAttempts) {
                throw new IOException("Echo response validation failed after exhausting retries");
            }
            log.debug("Echo test attempt {} timed out, retrying...", attempt);
            Thread.sleep(attemptDelay);
            
        } catch (SocketTimeoutException e) {
            if (attempt == maxAttempts) {
                throw new IOException("UDP connectivity test failed - server not responding after " + 
                    maxAttempts + " attempts");
            }
            log.debug("Echo test attempt {} failed, retrying...", attempt);
            Thread.sleep(attemptDelay);
        }
    }
}
    /**
     * Stores the received UDP packet for later processing.
     *
     * @param packet The received {@link DatagramPacket} to be stored.
    */
    private synchronized void storePacket(DatagramPacket packet) {
        // Make a copy of the packet data
        byte[] data = new byte[packet.getLength()];
        System.arraycopy(packet.getData(), packet.getOffset(), data, 0, packet.getLength());
        
        lastReceivedPacket = new DatagramPacket(data, data.length);
        lastReceivedPacket.setSocketAddress(packet.getSocketAddress());
        log.debug("Stored packet from {}", packet.getSocketAddress());
    }
    


    /**
     * Constructs a new {@code VPNConnection} instance with specified nodeId.
     *
     * @param peerHost The hostname or IP address of the peer to connect to.
     * @param peerPort The port number of the peer to connect to.
     * @param isServer A flag indicating whether this is a server instance.
     * @param nodeId The node ID to use for this connection.
     * @throws Exception If an error occurs during initialization.
     */
    public VPNConnection(String peerHost, int peerPort, boolean isServer, byte[] nodeId) throws Exception {
        this(peerHost, peerPort, isServer, nodeId, new ProofOfWork(nodeId));
    }

    /**
     * Sets the gossip handler responsible for processing gossip protocol messages.
     *
     * @param handler The {@link GossipMessage.GossipHandler} instance to handle gossip messages.
     */
    public synchronized void setGossipHandler(GossipMessage.GossipHandler handler) {
        if (this.gossipHandler == null) {
            this.gossipHandler = new GossipMessage();
        }
        this.gossipHandler.setHandler(handler);
    }
    
    /**
    * Handles incoming packets based on the current connection phase.
    *
    * <p>
    * Depending on the {@code currentPhase}, this method delegates packet processing to
    * appropriate handlers. It manages state transitions and ensures that messages are
    * processed according to the connection's lifecycle.
    * </p>
    *
    * @param packet The received {@link DatagramPacket}.
    * @param msg    The {@link ByteBuffer} containing the packet's data.
    * @param type   The type identifier of the received message.
    */
    private void handleBasedOnPhase(DatagramPacket packet, ByteBuffer msg, byte type) {
        try {
            switch (currentPhase) {
                case INITIAL, UDP_VERIFIED -> {
                    if (type == MSG_TYPE_PEER_INFO) {
                        peerAddress = (InetSocketAddress) packet.getSocketAddress();
                        log.debug("[UDP-Listener] Processing peer info from: {}", packet.getSocketAddress());
                        storePacket(packet);
                        performServerHandshake();
                        currentPhase = ConnectionPhase.SECURE_CHANNEL_ESTABLISHED;
                        if (connectionHandler != null) {
                            connectionHandler.onNewConnection(
                                peerAddress.getHostString(), 
                                peerAddress.getPort(), 
                                this
                            );
                        }
                    }
                }
                case SECURE_CHANNEL_ESTABLISHED, NETWORK_HANDSHAKE_COMPLETE -> {
                    if (crypto.isEstablished()) {
                        log.debug("[UDP-Listener] Processing established channel message type {} from {}", 
                            type, packet.getSocketAddress());
                        handleControlMessage(type, msg);
                    } else {
                        log.warn("[UDP-Listener] Received message type {} but channel not established", type);
                    }
                }
            }
        } catch (Exception e) {
            log.error("[UDP-Listener] Error in phase handler: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Processes the first message received from a new peer to initiate the handshake process.
     *
     * <p>
     * This method extracts the requesting node's ID from the incoming message and responds
     * with a verification response containing the local node's ID and a timestamp. It also
     * updates the connection phase based on the reception of peer information.
     * </p>
     *
     * @param packet The received {@link DatagramPacket} containing the verification request.
     * @throws SocketException If an error occurs while handling the verification response.
     */
   private void handleFirstMessage(DatagramPacket packet) throws SocketException {
        try {
            ByteBuffer message = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());
            byte type = message.get();

            log.debug("Received first message type: {}, size: {}, raw data: {}", 
                      type, packet.getLength(), 
                      bytesToHex(Arrays.copyOf(packet.getData(), packet.getLength())));

            // Handle verification request
            if (type == 0x01) {
                // Check minimum message length (1 byte type + nodeId length)
                if (packet.getLength() < 1 + nodeId.length) {
                    log.warn("Message too short for verification request: {} bytes", packet.getLength());
                    return;
                }

                // Extract requesting node's ID
                byte[] requestNodeId = new byte[nodeId.length];
                message.get(requestNodeId);

                log.debug("Received verification request from {} with nodeId length: {}", 
                    packet.getSocketAddress(), requestNodeId.length);

                // Get current proof and timestamp 
                byte[] currentProof = pow.getCurrentProof();
                long timestamp = pow.getTimestamp();

                if (currentProof == null) {
                    log.warn("No valid proof available");
                    return;
                }

                // Create response with nodeId and proof
                ByteBuffer response = ByteBuffer.allocate(nodeId.length + currentProof.length);
                response.put(nodeId);          // Include our nodeId
                response.put(currentProof);    // Include complete proof data
                response.flip();

                log.debug("Sending verification response: nodeId length {}, proof length {}", 
                    nodeId.length, currentProof.length);

                DatagramPacket responsePacket = new DatagramPacket(
                    response.array(),
                    response.limit(),
                    packet.getAddress(),
                    packet.getPort()
                );

                socket.send(responsePacket);
                log.debug("Sent verification response to {}", packet.getSocketAddress());
            }

            if (isServer && peerAddress == null) {
                peerAddress = (InetSocketAddress) packet.getSocketAddress();
                log.debug("Server connected to peer: {}", peerAddress);
            }
        } catch (IOException | IllegalStateException e) {
            log.error("Error handling first message: {}", e.getMessage());
            throw new SocketException("Failed to handle first message: " + e.getMessage());
        }
    }

    /**
     * Converts an array of bytes into its corresponding hexadecimal string representation.
     *
     * <p>
     * This utility method is useful for logging binary data in a human-readable hexadecimal format,
     * aiding in debugging and monitoring network messages.
     * </p>
     *
     * @param bytes The array of bytes to convert.
     * @return A {@code String} representing the hexadecimal values of the input bytes.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
    
    /**
     * Performs a secure handshake with the connected peer by exchanging public keys and establishing a secure channel.
     *
     * @throws Exception If an error occurs during the handshake process.
     */
    private void performHandshake() throws Exception {
        log.debug("Starting handshake with peer: {}", peerAddress);

        try {
            // Send our public key unencrypted
            byte[] publicKey = crypto.getPublicKey();
            log.debug("Sending public key, length: {}", publicKey.length);
            sendMessage(MSG_TYPE_PEER_INFO, publicKey);

            // Wait for peer's public key
            log.debug("Waiting for peer's public key...");
            byte[] peerKey = receivePeerInfo();
            if (peerKey == null) {
                throw new IOException("Failed to receive peer's public key");
            }
            log.debug("Received peer's public key, length: {}", peerKey.length);

            // Establish secure channel
            crypto.establishSecureChannel(peerKey);

            // Wait for server's acknowledgment
            log.debug("Waiting for handshake acknowledgment");
            byte[] ack = receiveMessage();
            if (ack == null || ack.length != 1 || ack[0] != 1) {
                throw new IOException("Invalid handshake acknowledgment");
            }

            // Mark handshake as complete
            handshakeCompleted = crypto.isEstablished();

            // Send our info after handshake
            ByteBuffer info = ByteBuffer.allocate(32);  // Use fixed size for peer info
            info.putInt(4); // Version
            info.putLong(System.currentTimeMillis());
            info.flip();
            sendMessage(MSG_TYPE_PEER_INFO, info.array());

            // Send our proof
            ByteBuffer proof = ByteBuffer.allocate(40);  // Use fixed size for proof
            proof.putInt(1); // Proof version
            proof.putLong(System.currentTimeMillis());
            proof.flip();
            sendMessage(MSG_TYPE_PROOF, proof.array());

            log.info("Secure channel established with {}", peerAddress);
            currentPhase = ConnectionPhase.NETWORK_HANDSHAKE_COMPLETE;

        } catch (IOException e) {
            handshakeCompleted = false;
            throw new IOException("Handshake failed: " + e.getMessage(), e);
        }
    }
    
    /**
     * Sends a VPN data packet to the connected peer.
     *
     * @param data The plaintext data to be sent.
     * @throws IOException If an error occurs during sending.
     */
    public void sendPacket(byte[] data) throws IOException {
       if (!running) {
           return;
       }

       try {
           log.debug("Sending VPN packet of size {}", data.length);

           // Create message with type header and encrypt
           byte[] encrypted = crypto.encryptMessage(data);
           ByteBuffer message = ByteBuffer.allocate(1 + encrypted.length);
           message.put(MSG_TYPE_DATA);
           message.put(encrypted);
           message.flip();

           // Send via UDP
           DatagramPacket packet = new DatagramPacket(
               message.array(), 
               message.position(), 
               message.limit(), 
               peerAddress
           );
           socket.send(packet);
           log.debug("Sent encrypted VPN packet size {}", packet.getLength());

       } catch (Exception e) {
           log.error("Failed to send VPN packet: {}", e.getMessage());
           throw new IOException("Failed to send packet", e);
       }
   }
    
    /**
     * Receives a VPN data packet from the connected peer.
     *
     * @return The decrypted plaintext data received, or {@code null} if no data is received.
     * @throws IOException If an error occurs during receiving or decryption.
     */
    public byte[] receivePacket() throws IOException {
        if (!running) {
            return null;
        }

        byte[] buffer = new byte[MAX_PACKET_SIZE];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        try {
            log.debug("Waiting for VPN packet");
            socket.receive(packet);
            lastReceivedTime = System.currentTimeMillis();

            ByteBuffer message = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());
            byte type = message.get();

            switch (type) {
                case MSG_TYPE_DATA -> {
                    byte[] encrypted = new byte[message.remaining()];
                    message.get(encrypted);
                    byte[] decrypted = crypto.decryptMessage(encrypted);
                    log.debug("Received encrypted VPN packet size {}, decrypted size {}",
                            encrypted.length, decrypted.length);
                    return decrypted;
                }

                case MSG_TYPE_PING -> {
                    sendMessage(MSG_TYPE_PING, new byte[0]);
                    return null;
                }

                case MSG_TYPE_GOSSIP, MSG_TYPE_PROOF, MSG_TYPE_PEER_INFO -> {
                    handleControlMessage(type, message);
                    return null;
                }
                default -> {
                    log.warn("Unknown message type: {}", type);
                    return null;
                }
            }
        } catch (SocketTimeoutException e) {
            return null;
        } catch (Exception e) {
            throw new IOException("Failed to receive packet", e);
        }
    }

    /**
     * Processes control messages such as gossip, proof of work, and peer information.
     *
     * <p>
     * Depending on the message type, this method delegates processing to the appropriate
     * handlers. It ensures that control messages are handled securely and correctly,
     * maintaining the integrity of the VPN connection.
     * </p>
     *
     * @param type    The type identifier of the received control message.
     * @param message The {@link ByteBuffer} containing the message data.
     * @throws IOException If an error occurs during message processing.
     */
    private void handleControlMessage(byte type, ByteBuffer message) {    
        try {
            byte[] data = new byte[message.remaining()];
            message.get(data);

            switch (type) {
                case MSG_TYPE_PING -> {
                    // Never encrypt pings
                    log.debug("Received ping, sending response");
                    sendMessage(MSG_TYPE_PING, new byte[]{});
                }
                case MSG_TYPE_GOSSIP, MSG_TYPE_PROOF, MSG_TYPE_PEER_INFO -> {
                    // Only try to decrypt if both secure channel and handshake complete
                    if (crypto.isEstablished() && handshakeCompleted) {
                        try {
                            data = crypto.decryptMessage(data);
                        } catch (Exception e) {
                            log.debug("Received unencrypted control message type {} size {}", type, data.length);
                        }
                    }

                    GossipMessage localHandler;
                    synchronized(this) {
                        localHandler = this.gossipHandler;
                    }

                    if (localHandler != null) {
                        localHandler.processMessage(type, data);
                    }
                }
                default -> log.warn("Unknown message type: {}", type);
            }

        } catch (IOException e) {
            log.error("Error handling control message of type {} and size {}: {} ({})", 
                type, message.remaining(), e.getMessage(), e.getClass().getName(), e);
        }
    }
    
    /**
     * Sends a control message to the connected peer.
     *
     * @param type The type of the message to send.
     * @param data The data payload of the message.
     * @throws IOException If an error occurs during sending.
     */
    @Override
    public void sendMessage(byte type, byte[] data)  throws IOException {
        if (!isRunning()) {
            return;
        }

        try {
            byte[] messageData;

            // Don't encrypt pings or messages during handshake
            if (type == MSG_TYPE_PING || !handshakeCompleted) {
                messageData = data;
            } else {
                // Only encrypt if secure channel established
                if (crypto.isEstablished()) {
                    messageData = crypto.encryptMessage(data);
                } else {
                    messageData = data;
                }
            }

            ByteBuffer message = ByteBuffer.allocate(1 + messageData.length);
            message.put(type);
            message.put(messageData);
            message.flip();

            DatagramPacket packet = new DatagramPacket(message.array(), message.limit(), peerAddress);
            socket.send(packet);
            log.debug("Sent {} bytes type {} to {}", message.limit(), type, peerAddress);
            updateLastSeen();
        } catch (Exception e) {
            throw new IOException("Failed to send message", e);
        }
    }

    
    /**
     * Sends a gossip message to the connected peer.
     *
     * @param gossip The {@link GossipMessage} instance containing gossip information.
     * @throws IOException If an error occurs during sending.
     */
    public void sendGossip(GossipMessage gossip) throws IOException {
        sendMessage(MSG_TYPE_GOSSIP, gossip.serialize());
    }
    
    /**
     * Sends a proof of work message to the connected peer.
     *
     * @param proof     The proof of work data.
     * @param timestamp The timestamp associated with the proof.
     * @throws IOException If an error occurs during sending.
     */
    public void sendProof(byte[] proof, long timestamp) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(proof.length + 8);
        buffer.put(proof);
        buffer.putLong(timestamp);
        sendMessage(MSG_TYPE_PROOF, buffer.array());
    }
    
    /**
     * Receives a raw message from the connected peer.
     *
     * @return The data payload of the received message, or {@code null} if no message is received.
     * @throws IOException If an error occurs during receiving.
     */
private byte[] receiveMessage() throws IOException {
    byte[] buffer = new byte[MAX_PACKET_SIZE];
    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

    try {
        log.debug("Waiting to receive message on port {} from {}", 
            socket.getLocalPort(),
            isServer ? "any" : peerAddress);

        while (running) {  // Loop until we get a non-echo message
            // Check if we have a stored packet first
            synchronized(this) {
                if (lastReceivedPacket != null) {
                    packet = lastReceivedPacket;
                    lastReceivedPacket = null;
                    log.debug("Using stored packet from {}", packet.getSocketAddress());
                } else {
                    socket.receive(packet);
                }
            }

            log.debug("Received {} bytes from {}", 
                packet.getLength(), 
                packet.getSocketAddress());
            lastReceivedTime = System.currentTimeMillis();

            ByteBuffer message = ByteBuffer.wrap(
                packet.getData(),
                packet.getOffset(),
                packet.getLength()
            );

            if (!message.hasRemaining()) {
                log.warn("Received empty packet");
                continue;
            }

            byte type = message.get();
            log.debug("Received message type: {} ({})", 
                MESSAGE_TYPE_NAMES.getOrDefault(type, "UNKNOWN"), type);

            // Handle echo requests immediately and continue listening
            if (type == MSG_TYPE_ECHO) {
                handleEchoPacket(packet);
                continue;  // Keep listening for non-echo messages
            }

            // For non-echo messages, return the data
            byte[] data = new byte[message.remaining()];
            message.get(data);
            return data;
        }

        throw new IOException("Connection closed while receiving message");

    } catch (IOException e) {
        if ("Connection closed by peer".equals(e.getMessage())) {
            setRunning(false);
            socket.close();
        }
        throw e;
    }
}


    

    /**
     * Verifies that the handshake has been completed successfully.
     *
     * @throws IOException If the secure channel has not been established.
     */
    private void verifyHandshake()  throws IOException {
        if (!handshakeCompleted) {
            throw new IOException("Secure channel not established");
        }
    }
    

    /**
     * Updates the connection latency.
     *
     * @param latency The new latency value in milliseconds.
     */
    public void updateLatency(double latency) {
        this.lastLatency = latency;
    }
    
    /**
     * Retrieves the current latency of the connection.
     *
     * @return The last recorded latency in milliseconds.
     */
    public double getLatency(){
        return lastLatency;
    }
    
    /**
     * Retrieves the current bandwidth estimate of the connection.
     *
     * @return The last estimated bandwidth in bytes per second.
     */
    public long getBandwidthEstimate() {
        long now = System.currentTimeMillis();
        long duration = now - lastStatsReset;
        
        if (duration > 0) {
            lastBandwidthEstimate = ((bytesSent.get() + bytesReceived.get()) * 1000) / duration;
            
            // Reset counters periodically
            if (duration > 60000) { // 1 minute
                bytesSent.set(0);
                bytesReceived.set(0);
                lastStatsReset = now;
            }
        }
        
        return lastBandwidthEstimate;
    }
    
    /**
     * Checks if the connection is stale based on the last received packet time.
     *
     * @return {@code true} if the connection is stale; {@code false} otherwise.
     */
    public boolean isStale() {
        return System.currentTimeMillis() - lastReceivedTime > STALE_THRESHOLD;
    }
    
    /**
     * Updates the timestamp of the last received packet to the current time.
     */
    public void updateLastSeen() {
        lastReceivedTime = System.currentTimeMillis();
    }
    
    /**
     * Closes the VPN connection, terminating all ongoing processes and releasing resources.
     *
     * @throws IOException If an error occurs during socket closure.
     */
    @Override
    public void close() throws IOException {
        setRunning(false);
        if (listenerThread != null) {
            listenerThread.interrupt();
        }
        socket.close();
    }
    
    /**
     * Returns a string representation of the {@code VPNConnection} instance, detailing the peer address,
     * latency, and bandwidth estimates.
     *
     * @return A {@code String} summarizing the VPN connection information.
     */
    @Override
    public String toString() {
        return String.format("VPNConnection[peer=%s, latency=%.1fms, bandwidth=%d B/s]",
            peerAddress, lastLatency, lastBandwidthEstimate);
    }
    
    /**
     * Receives peer information during the handshake process.
     *
     * @return A byte array containing the decrypted peer information.
     * @throws IOException If an error occurs during receiving or decryption.
     */
 public byte[] receivePeerInfo() throws IOException {
    byte[] buffer = new byte[MAX_PACKET_SIZE];
    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

    try {
        socket.receive(packet);
        lastReceivedTime = System.currentTimeMillis();

        ByteBuffer message = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());
        byte type = message.get();

        // Handle echo requests during handshake
        if (type == MSG_TYPE_ECHO) {
            handleEchoPacket(packet);
            // After handling echo, try to receive peer info again
            return receivePeerInfo();
        }

        if (type != MSG_TYPE_PEER_INFO) {
            throw new IOException(String.format("Expected peer info message (%d), got: %d (%s)", 
                MSG_TYPE_PEER_INFO, type, 
                MESSAGE_TYPE_NAMES.getOrDefault(type, "UNKNOWN")));
        }

        byte[] data = new byte[message.remaining()];
        message.get(data);

        // Only try to decrypt if secure channel is established
        if (crypto.isEstablished()) {
            return crypto.decryptMessage(data);
        }
        return data;
    } catch (Exception e) {
        if (e instanceof IOException iOException) {
            throw iOException;
        }
        throw new IOException("Failed to receive peer info: " + e.getMessage(), e);
    }
}

    /**
     * Receives a proof of work message during the handshake process.
     *
     * @return A byte array containing the decrypted proof of work.
     * @throws IOException If an error occurs during receiving or decryption.
     */
    public byte[] receiveProof() throws IOException{
        byte[] buffer = new byte[MAX_PACKET_SIZE];
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length);

        socket.receive(packet);
        lastReceivedTime = System.currentTimeMillis();

        ByteBuffer message = ByteBuffer.wrap(packet.getData(), 0, packet.getLength());
        byte type = message.get();

        if (type != MSG_TYPE_PROOF) {
            throw new IOException("Expected proof message, got: " + type);
        }

        byte[] encryptedData = new byte[message.remaining()];
        message.get(encryptedData);

        try {
            return crypto.decryptMessage(encryptedData);
        } catch (Exception e) {
            throw new IOException("Failed to decrypt proof", e);
        }
    }
    
    /**
     * Handles incoming messages based on their type by delegating to appropriate handlers.
     *
     * @param type The type identifier of the received message.
     * @param data The data payload of the message.
     * @throws IOException If an error occurs during message handling.
     */
    @Override
    public void handleMessage(byte type, byte[] data) throws IOException {
        try {
            ByteBuffer message;
            if (type == MSG_TYPE_PEER_INFO || type == MSG_TYPE_ECHO || !crypto.isEstablished()) {
                message = ByteBuffer.wrap(data);
            } else {
                byte[] decrypted = crypto.decryptMessage(data);
                message = ByteBuffer.wrap(decrypted);
            }

            switch (type) {
                case MSG_TYPE_GOSSIP -> {
                    if (gossipHandler != null) {
                        gossipHandler.processMessage(type, message.array());
                    }
                }
                case MSG_TYPE_PROOF -> {
                    if (gossipHandler != null) {
                        gossipHandler.processMessage(type, message.array());
                    }
                }
                case MSG_TYPE_PEER_INFO -> {
                    if (gossipHandler != null) {
                        gossipHandler.processMessage(type, message.array());
                    }
                    // Update connection phase if this is an acknowledgment
                    if (message.remaining() == 1 && message.get(0) == 1) {
                        currentPhase = ConnectionPhase.NETWORK_HANDSHAKE_COMPLETE;
                    }
                }
                case MSG_TYPE_PING -> sendMessage(MSG_TYPE_PING, new byte[0]);
                default -> log.warn("Unknown message type: {}", type);
            }
        } catch (Exception e) {
            throw new IOException("Failed to handle message", e);
        }
    }

    /**
     * Retrieves the current phase of the VPN connection.
     *
     * @return The current {@link ConnectionPhase} of the connection.
     */
    @Override
    public ConnectionPhase getPhase() {
        return currentPhase;
    }
    
}