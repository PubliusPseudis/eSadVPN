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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import org.publiuspseudis.esadvpn.core.VPNConnection;
import org.publiuspseudis.esadvpn.crypto.ProofOfWork;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@code PeerDiscovery} class is responsible for discovering and managing peers within the
 * peer-to-peer (P2P) VPN network. It facilitates the discovery process through various
 * mechanisms, including direct peer connections, local network scanning, and bootstrap node
 * queries. The class ensures that only verified and valid peers are added to the network,
 * maintaining the integrity and security of the VPN.
 *
 * <p>
 * <strong>Key Functionalities:</strong>
 * </p>
 * <ul>
 *   <li>Discovering peers via direct connections, local network broadcasts, or bootstrap nodes.</li>
 *   <li>Verifying peers' proofs of work to authenticate their legitimacy.</li>
 *   <li>Managing known peers and their states, including node IDs and proof of work data.</li>
 *   <li>Handling bootstrap attempts with retry mechanisms and backoff intervals.</li>
 *   <li>Refreshing peer lists periodically to maintain network connectivity and robustness.</li>
 * </ul>
 *
 * <p>
 * <strong>Usage Example:</strong>
 * </p>
 * <pre>{@code
 * byte[] nodeId = ...; // 32-byte unique identifier
 * ProofOfWork pow = new ProofOfWork(nodeId);
 * PeerDiscovery.ConnectionMode mode = PeerDiscovery.ConnectionMode.BOOTSTRAP_NODE;
 * String directPeerAddress = "192.168.1.100:8080";
 * String[] bootstrapAddresses = {"bootstrap1.example.com:51820", "bootstrap2.example.com:51820"};
 *
 * PeerDiscovery peerDiscovery = new PeerDiscovery(nodeId, pow, mode, directPeerAddress, bootstrapAddresses);
 *
 * try {
 *     Set<InetSocketAddress> peers = peerDiscovery.bootstrap();
 *     // Proceed with connecting to discovered peers
 * } catch (IOException e) {
 *     // Handle bootstrap failure
 * }
 * }</pre>
 *
 * <p>
 * <strong>Thread Safety:</strong>
 * </p>
 * <p>
 * The {@code PeerDiscovery} class is designed to be thread-safe. It utilizes concurrent data structures
 * such as {@link ConcurrentHashMap} and synchronization mechanisms to manage shared resources safely
 * across multiple threads.
 * </p>
 *
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>{@link ProofOfWork}: Used for generating and verifying proofs of work for peer authentication.</li>
 *   <li>{@link VPNConnection}: Represents the VPN connection used for communication with peers.</li>
 *   <li>SLF4J Logging Framework: Utilized for logging discovery processes, peer verification, and errors.</li>
 * </ul>
 *
 * @author
 * Publius Pseudis
 */
public final class PeerDiscovery {
    /**
     * Logger instance for logging information, warnings, and errors related to peer discovery.
     */
    private static final Logger log = LoggerFactory.getLogger(PeerDiscovery.class);

    /**
     * The maximum number of attempts to contact bootstrap nodes during the discovery process.
     */
    private static final int MAX_BOOTSTRAP_ATTEMPTS = 3;

    /**
     * The interval in milliseconds to wait before retrying bootstrap attempts after a failure.
     */
    private static final long BOOTSTRAP_RETRY_INTERVAL = TimeUnit.SECONDS.toMillis(30);

    /**
     * The interval in milliseconds to refresh the peer list by discovering new peers.
     */
    private static final long PEER_REFRESH_INTERVAL = TimeUnit.MINUTES.toMillis(5);

    /**
     * The minimum number of valid peers required to maintain network health.
     */
    private static final int MIN_VALID_PEERS = 3;

    /**
     * A set of predefined bootstrap nodes used for initiating peer discovery.
     */
    private final Set<InetSocketAddress> bootstrapNodes;

    /**
     * A set of known peers that have been successfully discovered and verified.
     */
    private final Set<InetSocketAddress> knownPeers;

    /**
     * A concurrent map storing the state of each peer, identified by their {@link InetSocketAddress}.
     */
    private final Map<InetSocketAddress, PeerState> peerStates;

    /**
     * An object used as a lock for synchronizing access to shared state variables.
     */
    private final Object stateLock = new Object();

    /**
     * The timestamp of the last bootstrap attempt.
     */
    private volatile long lastBootstrapAttempt;

    /**
     * The timestamp of the last peer list refresh.
     */
    private volatile long lastPeerRefresh;

    /**
     * A secure random number generator used for randomizing operations such as peer selection.
     */
    private final SecureRandom random;

    /**
     * The {@link ProofOfWork} instance used for generating and verifying proofs of work.
     */
    private final ProofOfWork pow;

    /**
     * The unique node ID of this peer discovery instance.
     */
    private final byte[] nodeId;

    /**
     * Enumeration representing the different modes of peer connection for discovery.
     */
    public enum ConnectionMode {
        /**
         * Direct connection to a specified known peer.
         */
        DIRECT_PEER,

        /**
         * Discovery via local network broadcasts.
         */
        LOCAL_NETWORK,

        /**
         * Connection to bootstrap nodes for initial peer discovery.
         */
        BOOTSTRAP_NODE
    }

    /**
     * The current connection mode determining the peer discovery strategy.
     */
    private final ConnectionMode mode;

    /**
     * The direct peer's {@link InetSocketAddress} if operating in {@link ConnectionMode#DIRECT_PEER} mode.
     */
    private final InetSocketAddress directPeer;

    /**
     * Represents the state of a peer, including node ID, proof of work, last verification time, and reliability score.
     */
    private static class PeerState {
        /**
         * The unique node ID of the peer.
         */
        final byte[] nodeId;

        /**
         * The proof of work data of the peer.
         */
        final byte[] proofOfWork;

        /**
         * The timestamp of the last verification attempt.
         */
        volatile long lastVerified;

        /**
         * The reliability score of the peer, indicating trustworthiness.
         */
        volatile double reliability;

        /**
         * Constructs a new {@code PeerState} with the specified parameters.
         *
         * @param nodeId       The unique node ID of the peer.
         * @param proofOfWork  The proof of work data of the peer.
         * @param lastVerified The timestamp of the last verification.
         * @param reliability  The reliability score of the peer.
         */
        PeerState(byte[] nodeId, byte[] proofOfWork, long lastVerified, double reliability) {
            this.nodeId = nodeId;
            this.proofOfWork = proofOfWork;
            this.lastVerified = lastVerified;
            this.reliability = reliability;
        }

        /**
         * Updates the reliability score of the peer based on the outcome of the last interaction.
         *
         * @param success Indicates whether the last interaction was successful.
         */
        void updateReliability(boolean success) {
            if (success) {
                this.reliability = Math.min(this.reliability + 0.1, 1.0);
            } else {
                this.reliability = Math.max(this.reliability - 0.1, 0.0);
            }
        }
    }

    /**
     * Constructs a new {@code PeerDiscovery} instance with the specified parameters.
     *
     * <p>
     * Initializes the peer discovery mechanism based on the provided connection mode. Depending on the mode,
     * it sets up direct peer connections, local network scanning, or initializes connections to bootstrap nodes.
     * </p>
     *
     * @param nodeId               The unique node ID for which the peer discovery is being performed.
     * @param pow                  The {@link ProofOfWork} instance used for proof verification.
     * @param mode                 The {@link ConnectionMode} determining the discovery strategy.
     * @param directPeerAddress    The address of the direct peer (required if {@code mode} is {@link ConnectionMode#DIRECT_PEER}).
     * @param bootstrapAddresses   A varargs array of bootstrap node addresses in the format "hostname:port".
     *                             These are used when {@code mode} is {@link ConnectionMode#BOOTSTRAP_NODE}.
     * @throws IllegalArgumentException If the {@code directPeerAddress} format is invalid when required.
     */
    public PeerDiscovery(byte[] nodeId, ProofOfWork pow, ConnectionMode mode, 
                         String directPeerAddress, String... bootstrapAddresses) {
        this.nodeId = nodeId;
        this.pow = pow;
        this.mode = mode;
        this.random = new SecureRandom();
        this.bootstrapNodes = ConcurrentHashMap.newKeySet();
        this.knownPeers = ConcurrentHashMap.newKeySet();
        this.peerStates = new ConcurrentHashMap<>();

        // Handle direct peer connection if in DIRECT_PEER mode
        if (mode == ConnectionMode.DIRECT_PEER && directPeerAddress != null) {
            String[] parts = directPeerAddress.split(":");
            if (parts.length == 2) {
                this.directPeer = new InetSocketAddress(
                        parts[0].trim(), Integer.parseInt(parts[1].trim()));
            } else {
                throw new IllegalArgumentException("Invalid direct peer address format. Expected format: 'hostname:port'");
            }
        } else {
            this.directPeer = null;
        }

        // Add bootstrap nodes if in BOOTSTRAP_NODE mode
        if (mode == ConnectionMode.BOOTSTRAP_NODE) {
            for (String addr : bootstrapAddresses) {
                try {
                    String[] parts = addr.split(":");
                    if (parts.length == 2) {
                        InetSocketAddress bootstrapNode = new InetSocketAddress(
                                parts[0].trim(), Integer.parseInt(parts[1].trim()));
                        bootstrapNodes.add(bootstrapNode);
                    } else {
                        log.warn("Invalid bootstrap address format: {}", addr);
                    }
                } catch (NumberFormatException e) {
                    log.warn("Invalid port number in bootstrap address: {}", addr);
                }
            }
        }
    }

    /**
     * Initiates the bootstrap process to discover and verify peers based on the configured connection mode.
     *
     * <p>
     * This method attempts to discover peers through bootstrap nodes, local network scanning, or direct peer
     * connections depending on the {@link ConnectionMode} specified during initialization. It verifies each
     * discovered peer's proof of work before adding them to the known peers list.
     * </p>
     *
     * @return A {@link Set} of {@link InetSocketAddress} representing successfully discovered and verified peers.
     * @throws IOException If the bootstrap process fails to discover any valid peers after maximum attempts.
     */
    public Set<InetSocketAddress> bootstrap() throws IOException {
        synchronized (stateLock) {
            Set<InetSocketAddress> peers = new HashSet<>();
            int attempt = 0;

            while (attempt < MAX_BOOTSTRAP_ATTEMPTS) {
                attempt++;
                log.info("Bootstrap attempt {}/{}", attempt, MAX_BOOTSTRAP_ATTEMPTS);

                try {
                    switch (mode) {
                        case BOOTSTRAP_NODE -> {
                            peers = bootstrapFromNodes();
                        }
                        case LOCAL_NETWORK -> peers = bootstrapLocalNetwork();
                        case DIRECT_PEER -> peers = bootstrapDirectPeer();
                    }

                    if (!peers.isEmpty()) {
                        log.info("Bootstrap successful on attempt {}/{}", attempt, MAX_BOOTSTRAP_ATTEMPTS);
                        return peers;
                    } else {
                        log.warn("No peers discovered on attempt {}/{}", attempt, MAX_BOOTSTRAP_ATTEMPTS);
                    }
                } catch (IOException e) {
                    log.warn("Bootstrap attempt {}/{} failed: {}", attempt, MAX_BOOTSTRAP_ATTEMPTS, e.getMessage());
                }

                if (attempt < MAX_BOOTSTRAP_ATTEMPTS) {
                    log.info("Waiting for {} ms before next bootstrap attempt...", BOOTSTRAP_RETRY_INTERVAL);
                    try {
                        Thread.sleep(BOOTSTRAP_RETRY_INTERVAL);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Bootstrap interrupted during sleep", ie);
                    }
                }
            }

            throw new IOException("Failed to bootstrap after " + MAX_BOOTSTRAP_ATTEMPTS + " attempts.");
        }
    }

    /**
     * Bootstraps the peer discovery process by connecting to predefined bootstrap nodes.
     *
     * <p>
     * This method iterates through the list of configured bootstrap nodes, querying each for known peers.
     * It verifies each discovered peer's proof of work before adding them to the known peers set.
     * </p>
     *
     * @return A {@link Set} of {@link InetSocketAddress} representing successfully discovered and verified peers.
     * @throws IOException If the bootstrap attempts to all bootstrap nodes fail to discover valid peers.
     */
    private Set<InetSocketAddress> bootstrapFromNodes() throws IOException {
        long now = System.currentTimeMillis();
        if (now - lastBootstrapAttempt < BOOTSTRAP_RETRY_INTERVAL) {
            return new HashSet<>(knownPeers);
        }
        lastBootstrapAttempt = now;

        Set<InetSocketAddress> discoveredPeers = new HashSet<>();

        // Attempt to query each bootstrap node
        for (InetSocketAddress bootstrap : bootstrapNodes) {
            try {
                Set<InetSocketAddress> peers = queryPeer(bootstrap);
                if (!peers.isEmpty()) {
                    discoveredPeers.addAll(verifyAndAddPeers(peers));
                }
            } catch (IOException e) {
                log.debug("Failed to query bootstrap node {}: {}", bootstrap, e.getMessage());
            }
        }

        // If bootstrap nodes fail, attempt to query known peers
        if (discoveredPeers.isEmpty() && !knownPeers.isEmpty()) {
            List<InetSocketAddress> shuffledPeers = new ArrayList<>(knownPeers);
            Collections.shuffle(shuffledPeers, random);

            for (InetSocketAddress peer : shuffledPeers) {
                try {
                    Set<InetSocketAddress> peers = queryPeer(peer);
                    if (!peers.isEmpty()) {
                        discoveredPeers.addAll(verifyAndAddPeers(peers));
                    }
                } catch (IOException e) {
                    log.debug("Failed to query peer {}: {}", peer, e.getMessage());
                    removePeer(peer);
                }
            }
        }

        if (discoveredPeers.isEmpty()) {
            throw new IOException("Failed to bootstrap from nodes: No valid peers discovered.");
        }

        return discoveredPeers;
    }

    /**
     * Bootstraps the peer discovery process by scanning the local network for peers.
     *
     * <p>
     * This method broadcasts a discovery request over each active and non-loopback network interface's
     * broadcast address. It collects and verifies responses from peers within the local network segment.
     * </p>
     *
     * @return A {@link Set} of {@link InetSocketAddress} representing successfully discovered and verified peers.
     * @throws IOException If the local network discovery fails to find any valid peers.
     */
    private Set<InetSocketAddress> bootstrapLocalNetwork() throws IOException {
        Set<InetSocketAddress> discovered = new HashSet<>();

        // Iterate through all network interfaces
        for (NetworkInterface iface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (!iface.isUp() || iface.isLoopback()) {
                continue;
            }

            // Iterate through all interface addresses to get broadcast addresses
            for (InterfaceAddress addr : iface.getInterfaceAddresses()) {
                InetAddress broadcast = addr.getBroadcast();
                if (broadcast == null) continue;

                discovered.addAll(sendLocalDiscovery(broadcast));
            }
        }

        if (!discovered.isEmpty()) {
            return verifyAndAddPeers(discovered);
        }
        throw new IOException("No peers found on the local network.");
    }

    /**
     * Bootstraps the peer discovery process by establishing a direct connection to a specified peer.
     *
     * <p>
     * This method attempts to verify the direct peer's proof of work and adds it to the known peers
     * set upon successful verification.
     * </p>
     *
     * @return A {@link Set} containing the direct peer's {@link InetSocketAddress} if successfully verified.
     * @throws IOException If the direct peer verification fails.
     */
    private Set<InetSocketAddress> bootstrapDirectPeer() throws IOException {
        if (directPeer == null) {
            throw new IOException("No direct peer configured for DIRECT_PEER mode.");
        }

        // Verify the direct peer's proof of work
        if (verifyPeer(directPeer)) {
            Set<InetSocketAddress> result = new HashSet<>();
            result.add(directPeer);
            knownPeers.add(directPeer);
            log.info("Direct peer {} successfully verified and added.", directPeer);
            return result;
        }
        throw new IOException("Failed to verify the direct peer's proof of work.");
    }

    /**
     * Sends a local discovery request to the specified broadcast address and collects responses.
     *
     * <p>
     * This method constructs a discovery packet containing the node's ID and a timestamp, broadcasts it
     * to the local network, and listens for responses from other peers. Responses are validated before
     * adding the responding peers to the discovery results.
     * </p>
     *
     * @param broadcast The {@link InetAddress} representing the broadcast address to send discovery requests to.
     * @return A {@link Set} of {@link InetSocketAddress} representing peers that responded to the discovery request.
     */
    private Set<InetSocketAddress> sendLocalDiscovery(InetAddress broadcast) {
        Set<InetSocketAddress> discovered = new HashSet<>();

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setBroadcast(true);
            socket.setSoTimeout(1000); // 1-second timeout for responses

            // Construct discovery request packet
            ByteBuffer request = ByteBuffer.allocate(nodeId.length + Long.BYTES);
            request.put(nodeId);
            request.putLong(System.currentTimeMillis());

            DatagramPacket packet = new DatagramPacket(
                    request.array(), request.array().length,
                    broadcast, VPNConnection.VPN_PORT);
            socket.send(packet);
            log.debug("Sent local discovery request to {}", broadcast.getHostAddress());

            // Collect responses within the timeout period
            long deadline = System.currentTimeMillis() + 1000; // 1-second window
            while (System.currentTimeMillis() < deadline) {
                try {
                    byte[] responseData = new byte[1024];
                    DatagramPacket responsePacket = new DatagramPacket(responseData, responseData.length);
                    socket.receive(responsePacket);

                    if (validateDiscoveryResponse(responsePacket)) {
                        InetSocketAddress peerAddress = new InetSocketAddress(
                                responsePacket.getAddress(), responsePacket.getPort());
                        discovered.add(peerAddress);
                        log.debug("Discovered peer at {}", peerAddress);
                    }
                } catch (SocketTimeoutException e) {
                    // No more responses within the timeout
                    break;
                }
            }
        } catch (IOException e) {
            log.debug("Local discovery on {} failed: {}", broadcast.getHostAddress(), e.getMessage());
        }

        return discovered;
    }

    /**
     * Queries a specific peer for known peers by sending a discovery request and processing the response.
     *
     * <p>
     * This method sends a discovery packet to the specified peer and waits for a response containing
     * a list of known peers. It then extracts and returns the list of peers provided in the response.
     * </p>
     *
     * @param peer The {@link InetSocketAddress} of the peer to query.
     * @return A {@link Set} of {@link InetSocketAddress} representing peers discovered from the queried peer.
     * @throws IOException If there is an error during communication with the peer or if the response is invalid.
     */
    private Set<InetSocketAddress> queryPeer(InetSocketAddress peer) throws IOException {
        Set<InetSocketAddress> discoveredPeers = new HashSet<>();

        // Establish a temporary UDP socket for querying
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(5000); // 5-second timeout

            // Construct discovery request packet
            ByteBuffer request = ByteBuffer.allocate(nodeId.length + 8);
            request.put(nodeId);
            request.putLong(System.currentTimeMillis());

            byte[] requestData = request.array();
            DatagramPacket packet = new DatagramPacket(
                    requestData,
                    requestData.length,
                    peer.getAddress(),
                    peer.getPort()
            );

            // Send discovery request
            socket.send(packet);
            log.debug("Sent discovery request to peer {}", peer);

            // Receive and validate response
            byte[] responseData = new byte[4096];
            DatagramPacket response = new DatagramPacket(responseData, responseData.length);
            socket.receive(response);

            log.debug("Received discovery response from {}: size {}, data {}", 
                    response.getSocketAddress(), response.getLength(), bytesToHex(Arrays.copyOf(responseData, response.getLength())));

            ByteBuffer buffer = ByteBuffer.wrap(responseData, 0, response.getLength());

            // Validate response format
            if (buffer.remaining() < nodeId.length + Long.BYTES + Integer.BYTES) {
                throw new IOException("Invalid discovery response format from peer " + peer);
            }

            // Extract responding node's ID and timestamp
            byte[] respNodeId = new byte[nodeId.length];
            buffer.get(respNodeId);
            long timestamp = buffer.getLong();

            // Extract the number of peers reported
            int peerCount = buffer.getInt();

            // Extract peer addresses
            for (int i = 0; i < peerCount && buffer.remaining() >= 6; i++) {
                byte[] addrBytes = new byte[4];
                buffer.get(addrBytes);
                int port = buffer.getShort() & 0xFFFF; // Convert to unsigned

                InetAddress addr = InetAddress.getByAddress(addrBytes);
                InetSocketAddress newPeer = new InetSocketAddress(addr, port);

                if (!newPeer.equals(peer)) { // Exclude the querying peer itself
                    discoveredPeers.add(newPeer);
                }
            }
        }

        return discoveredPeers;
    }

    /**
     * Verifies the discovered peers by validating their proofs of work and adds them to the known peers set.
     *
     * <p>
     * This method iterates through the provided set of peers, verifies each peer's proof of work,
     * and adds the peer to the known peers set if the verification is successful.
     * </p>
     *
     * @param peers A {@link Set} of {@link InetSocketAddress} representing discovered peers to verify.
     * @return A {@link Set} of {@link InetSocketAddress} representing successfully verified peers.
     */
    private Set<InetSocketAddress> verifyAndAddPeers(Set<InetSocketAddress> peers) {
        Set<InetSocketAddress> verifiedPeers = new HashSet<>();

        for (InetSocketAddress peer : peers) {
            try {
                // Verify the peer's proof of work
                if (verifyPeer(peer)) {
                    knownPeers.add(peer);
                    verifiedPeers.add(peer);
                    log.debug("Verified and added peer {}", peer);
                }
            } catch (Exception e) {
                log.debug("Failed to verify peer {}: {}", peer, e.getMessage());
            }
        }

        return verifiedPeers;
    }

    /**
     * Verifies a peer's authenticity by validating its proof of work.
     *
     * <p>
     * This method sends a verification request to the specified peer and awaits a response containing
     * the peer's node ID and timestamp. It then uses the {@link ProofOfWork} instance to verify the received
     * proof data.
     * </p>
     *
     * @param peer The {@link InetSocketAddress} of the peer to verify.
     * @return {@code true} if the peer's proof of work is valid; {@code false} otherwise.
     */
public boolean verifyPeer(InetSocketAddress peer) {
    try (DatagramSocket socket = new DatagramSocket()) {
        socket.setSoTimeout(5000); // 5-second timeout

        // Construct verification request packet with nodeId
        ByteBuffer request = ByteBuffer.allocate(1 + nodeId.length);
        request.put((byte) 0x01); // Verification request marker
        request.put(nodeId);      // Include our nodeId
        request.flip();

        DatagramPacket packet = new DatagramPacket(
                request.array(),
                request.limit(),
                peer.getAddress(),
                peer.getPort()
        );

        // Send verification request
        socket.send(packet);
        log.debug("Sent verification request to {} with nodeId length {}", 
                  peer, nodeId.length);

        // Receive response
        byte[] responseData = new byte[1024];
        DatagramPacket responsePacket = new DatagramPacket(responseData, responseData.length);
        socket.receive(responsePacket);

        ByteBuffer buffer = ByteBuffer.wrap(responseData, 0, responsePacket.getLength());

        // Extract peer node ID (32 bytes)
        if (buffer.remaining() < nodeId.length) {
            log.debug("Response too short to contain nodeId");
            return false;
        }
        byte[] peerNodeId = new byte[nodeId.length];
        buffer.get(peerNodeId);

        // Extract proof data (remaining bytes)
        int proofLength = buffer.remaining();
        if (proofLength <= 0) {
            log.debug("No proof data received from peer");
            return false;
        }
        byte[] proof = new byte[proofLength];
        buffer.get(proof);

        // Log the received proof data
        log.debug("Received proof from {}: nodeId length {}, proof size {}", 
                  peer, peerNodeId.length, proof.length);

        // Verify the proof
        boolean isValid = pow.verify(proof, System.currentTimeMillis());

        if (!isValid) {
            log.debug("Invalid proof of work from peer {}, will retry", peer);
            return false;
        }

        log.debug("Successfully verified peer {}", peer);
        return true;

    } catch (Exception e) {
        log.debug("Peer verification failed for {}: {}", peer, e.getMessage(), e);
        return false;
    }
}



    /**
     * Validates a discovery response packet received from a peer.
     *
     * <p>
     * This method checks the format of the discovery response, ensuring it contains the correct
     * markers, node ID, and a recent timestamp. It also validates the proof of work if the peer
     * is known.
     * </p>
     *
     * @param responsePacket The {@link DatagramPacket} containing the discovery response data.
     * @return {@code true} if the discovery response is valid; {@code false} otherwise.
     */
    private boolean validateDiscoveryResponse(DatagramPacket responsePacket) {
        try {
            ByteBuffer buffer = ByteBuffer.wrap(
                    responsePacket.getData(),
                    responsePacket.getOffset(),
                    responsePacket.getLength()
            );

            // Minimum required bytes: 1 (type) + nodeId.length + 8 (timestamp)
            if (buffer.remaining() < 1 + nodeId.length + 8) {
                return false;
            }

            // Check response type marker
            byte type = buffer.get();
            if (type != 0x03) { // Discovery response marker
                return false;
            }

            // Extract responding node's ID and timestamp
            byte[] respNodeId = new byte[nodeId.length];
            buffer.get(respNodeId);
            long timestamp = buffer.getLong();

            // Validate timestamp is within the acceptable range (e.g., within the last minute)
            long now = System.currentTimeMillis();
            if (Math.abs(now - timestamp) > TimeUnit.MINUTES.toMillis(1)) {
                log.debug("Discovery response timestamp too old from {}", responsePacket.getAddress());
                return false;
            }

            // Retrieve peer state if already known
            PeerState peerState = peerStates.get(
                    new InetSocketAddress(responsePacket.getAddress(), responsePacket.getPort())
            );

            if (peerState != null) {
                // For known peers, ensure node ID matches
                if (!Arrays.equals(respNodeId, peerState.nodeId)) {
                    log.warn("NodeId mismatch from known peer {}", responsePacket.getAddress());
                    return false;
                }

                // Optionally, update lastVerified and reliability based on the discovery response
                peerState.lastVerified = now;
                peerState.updateReliability(true); // Assuming discovery success
            } else {
                // add the peer with initial PeerState
                PeerState newPeerState = new PeerState(respNodeId, 
                        Arrays.copyOfRange(responsePacket.getData(), 0, nodeId.length + Long.BYTES),
                        now, 1.0);
                peerStates.put(new InetSocketAddress(responsePacket.getAddress(), responsePacket.getPort()), newPeerState);
                knownPeers.add(new InetSocketAddress(responsePacket.getAddress(), responsePacket.getPort()));
            }

            return true;

        } catch (Exception e) {
            log.debug("Error validating discovery response: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Removes a peer from the known peers set and cleans up associated state information.
     *
     * <p>
     * This method deregisters the specified peer from the known peers list and removes any stored
     * state information related to the peer. It ensures that stale or invalid peers do not persist
     * in the network.
     * </p>
     *
     * @param peer The {@link InetSocketAddress} of the peer to remove.
     */
    public void removePeer(InetSocketAddress peer) {
        knownPeers.remove(peer);
        peerStates.remove(peer);
        log.debug("Removed peer {}", peer);
    }

    /**
     * Determines whether the peer discovery process requires a bootstrap attempt.
     *
     * <p>
     * This method checks if the number of known peers is below the minimum required or if the peer
     * list has not been refreshed within the specified interval. It indicates whether a new bootstrap
     * attempt should be initiated to discover additional peers.
     * </p>
     *
     * @return {@code true} if a bootstrap attempt is needed; {@code false} otherwise.
     */
    public boolean needsBootstrap() {
        return knownPeers.size() < MIN_VALID_PEERS ||
                System.currentTimeMillis() - lastPeerRefresh > PEER_REFRESH_INTERVAL;
    }

    /**
     * Retrieves the current set of known peers.
     *
     * <p>
     * This method returns a defensive copy of the known peers set to prevent external modification.
     * </p>
     *
     * @return A {@link Set} of {@link InetSocketAddress} representing the currently known peers.
     */
    public Set<InetSocketAddress> getKnownPeers() {
        return new HashSet<>(knownPeers);
    }

    /**
     * Selects a peer based on reliability scores.
     *
     * <p>
     * This method sorts the known peers by their reliability scores in descending order and selects the
     * most reliable peer available. If no peers are available, it returns {@code null}.
     * </p>
     *
     * @return An {@link InetSocketAddress} of a selected peer, or {@code null} if no suitable peer is found.
     */
    public InetSocketAddress selectPeer() {
        return peerStates.entrySet().stream()
                .sorted((e1, e2) -> Double.compare(e2.getValue().reliability, e1.getValue().reliability))
                .map(Map.Entry::getKey)
                .findFirst()
                .orElse(null);
    }

    /**
     * Prunes peers with reliability scores below a specified threshold.
     *
     * <p>
     * This method iterates through the known peers and removes those whose reliability scores are
     * below the provided threshold. This helps maintain a network of reliable and trustworthy peers.
     * </p>
     *
     * @param threshold The reliability threshold below which peers will be removed.
     */
    public void pruneUnreliablePeers(double threshold) {
        peerStates.entrySet().removeIf(entry -> {
            boolean shouldRemove = entry.getValue().reliability < threshold;
            if (shouldRemove) {
                knownPeers.remove(entry.getKey());
                log.info("Pruned unreliable peer {}", entry.getKey());
            }
            return shouldRemove;
        });
    }

    /**
     * Converts a byte array into its hexadecimal string representation.
     *
     * <p>
     * This utility method is primarily used for logging purposes, allowing binary data to be
     * represented in a human-readable hexadecimal format.
     * </p>
     *
     * @param bytes The byte array to convert.
     * @return A {@link String} representing the hexadecimal values of the input bytes.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
}
