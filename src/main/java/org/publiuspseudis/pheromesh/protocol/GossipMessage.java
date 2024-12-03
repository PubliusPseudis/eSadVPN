package org.publiuspseudis.pheromesh.protocol;

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


import org.publiuspseudis.pheromesh.routing.RouteInfo;
import org.publiuspseudis.pheromesh.core.VPNConnection;
import java.io.*;
import java.nio.ByteBuffer;
import java.util.*;
import org.publiuspseudis.pheromesh.network.Peer;

/**
 * <p>
 * The {@code GossipMessage} class represents a message used within a gossip protocol
 * for peer discovery and network state synchronization with swarm intelligence-based
 * routing capabilities.
 * </p>
 *
 * <p>
 * This class encapsulates various components essential for maintaining an updated and
 * synchronized view of the network, including the node's identity, proof of work,
 * known peers, and routing information. It supports serialization and deserialization
 * for network transmission and provides mechanisms for handling different types of
 * gossip messages through a handler interface.
 * </p>
 *
 * <p>
 * <strong>Message Types:</strong></p>
 * <ul>
 *   <li>{@link #GOSSIP_TYPE_FULL}: Full peer list update</li>
 *   <li>{@link #GOSSIP_TYPE_DELTA}: Only changes since last gossip</li>
 *   <li>{@link #GOSSIP_TYPE_PING}: Keepalive with minimal info</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Creating a list of peers
 * List<Peer> peers = Arrays.asList(
 *     new Peer("192.168.1.2", 8080, nodeId1),
 *     new Peer("192.168.1.3", 8080, nodeId2)
 * );
 * 
 * // Creating a map of routes
 * Map<String, RouteInfo> routes = new HashMap<>();
 * routes.put("192.168.1.4", new RouteInfo("192.168.1.4", "192.168.1.2", 2));
 * 
 * // Creating a GossipMessage instance
 * GossipMessage message = new GossipMessage(
 *     myNodeId,
 *     myProofOfWork,
 *     System.currentTimeMillis(),
 *     peers,
 *     routes
 * );
 * 
 * // Serializing the message for transmission
 * byte[] serializedData = message.serialize();
 * 
 * // Deserializing the message upon reception
 * GossipMessage receivedMessage = GossipMessage.deserialize(serializedData);
 * 
 * // Handling the received message
 * receivedMessage.setHandler(new GossipMessage.GossipHandler() {
 *     @Override
 *     public void handleGossip(GossipMessage message) {
 *         // Process the received gossip message
 *     }
 * 
 *     @Override
 *     public void handleProof(byte[] proof, long timestamp) {
 *         // Handle proof of work
 *     }
 * 
 *     @Override
 *     public void handlePeerInfo(byte[] nodeId) {
 *         // Handle peer information
 *     }
 * });
 * 
 * // Processing the message based on its type
 * receivedMessage.processMessage(messageType, data);
 * }</pre>
 * 
 * @author
 * Publius Pseudis
 * 
 * @version 1.0
 * @since 2024-01-01
 */
public class GossipMessage {
    /**
     * Unique identifier for the node sending the gossip message.
     * Represented as a byte array.
     */
    private final byte[] nodeId;

    /**
     * Proof of work associated with the node, used for validating the node's authenticity.
     * Represented as a byte array.
     */
    private final byte[] proofOfWork;

    /**
     * Timestamp indicating when the proof of work was generated.
     * Represented in milliseconds since the epoch.
     */
    private final long proofTimestamp;

    /**
     * List of known peers in the network.
     * Each peer is represented by a {@link PeerInfo} record.
     */
    private final List<PeerInfo> knownPeers;

    /**
     * Routing information mapping destinations to their respective route details.
     * The key is the destination's identifier (e.g., IP address), and the value is a {@link RouteInfo} object.
     */
    private final Map<String, RouteInfo> routes;

    /**
     * Message type indicating a full peer list update.
     */
    public static final byte GOSSIP_TYPE_FULL = 1;    // Full peer list update

    /**
     * Message type indicating only changes since the last gossip.
     */
    public static final byte GOSSIP_TYPE_DELTA = 2;   // Only changes since last gossip

    /**
     * Message type indicating a keepalive message with minimal information.
     */
    public static final byte GOSSIP_TYPE_PING = 3;    // Keepalive with minimal info

    /**
     * Interface for handling different types of gossip messages.
     */
    public interface GossipHandler {
        /**
         * Handles a full gossip message containing complete peer and routing information.
         *
         * @param message The {@link GossipMessage} instance containing the gossip data.
         */
        void handleGossip(GossipMessage message);

        /**
         * Handles a proof of work along with its associated timestamp.
         *
         * @param proof     The proof of work as a byte array.
         * @param timestamp The timestamp indicating when the proof was generated.
         */
        void handleProof(byte[] proof, long timestamp);

        /**
         * Handles information about a specific peer identified by its node ID.
         *
         * @param nodeId The unique identifier of the peer as a byte array.
         */
        void handlePeerInfo(byte[] nodeId);
    }

    /**
     * The handler responsible for processing incoming gossip messages.
     */
    private GossipHandler handler;

    /**
     * Sets the handler responsible for processing gossip messages.
     *
     * @param handler An implementation of the {@link GossipHandler} interface.
     */
    public void setHandler(GossipHandler handler) {
        this.handler = handler;
    }

    /**
     * Default constructor for creating an empty gossip message.
     * Primarily used for message handling and deserialization purposes.
     */
    public GossipMessage() {
        this.nodeId = new byte[0];
        this.proofOfWork = new byte[0];
        this.proofTimestamp = 0;
        this.knownPeers = new ArrayList<>();
        this.routes = new HashMap<>();
    }

    /**
     * Determines whether this {@code GossipMessage} is equal to another object.
     * Two gossip messages are considered equal if their node IDs, proofs of work,
     * and proof timestamps are identical.
     *
     * @param o The object to compare with.
     * @return {@code true} if the objects are equal; {@code false} otherwise.
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        GossipMessage that = (GossipMessage) o;
        return proofTimestamp == that.proofTimestamp &&
               Arrays.equals(nodeId, that.nodeId) &&
               Arrays.equals(proofOfWork, that.proofOfWork);
    }

    /**
     * Computes the hash code for this {@code GossipMessage}.
     * The hash code is based on the node ID, proof of work, and proof timestamp.
     *
     * @return The hash code value.
     */
    @Override
    public int hashCode() {
        int result = Arrays.hashCode(nodeId);
        result = 31 * result + Arrays.hashCode(proofOfWork);
        result = 31 * result + Long.hashCode(proofTimestamp);
        return result;
    }

    /**
     * Processes an incoming message based on its type.
     * Delegates handling to the appropriate method in the {@link GossipHandler}.
     *
     * @param msgType The type of the message, corresponding to one of the GOSSIP_TYPE_* constants.
     * @param data    The raw data of the message as a byte array.
     */
    public void processMessage(byte msgType, byte[] data) {
        if (handler == null) return;

        switch (msgType) {
            case VPNConnection.MSG_TYPE_GOSSIP -> {
                try {
                    GossipMessage gossip = GossipMessage.deserialize(data);
                    handler.handleGossip(gossip);
                } catch (IOException e) {
                    // Log error
                }
            }
            case VPNConnection.MSG_TYPE_PROOF -> {
                ByteBuffer buf = ByteBuffer.wrap(data);
                byte[] proof = new byte[data.length - 8];
                buf.get(proof);
                long timestamp = buf.getLong();
                handler.handleProof(proof, timestamp);
            }
            case VPNConnection.MSG_TYPE_PEER_INFO -> handler.handlePeerInfo(data);
            // You can add more cases here if new message types are introduced
        }
    }

    /**
     * Creates a new gossip message with peer and routing information.
     *
     * @param nodeId         The unique identifier of the node sending the message.
     * @param proofOfWork    The proof of work associated with the node.
     * @param proofTimestamp The timestamp indicating when the proof of work was generated.
     * @param peers          A list of {@link Peer} instances representing known peers.
     * @param routes         A map of routing information mapping destinations to {@link RouteInfo}.
     */
    public GossipMessage(byte[] nodeId, byte[] proofOfWork, long proofTimestamp, 
                        List<Peer> peers, Map<String, RouteInfo> routes) {
        this.nodeId = nodeId;
        this.proofOfWork = proofOfWork;
        this.proofTimestamp = proofTimestamp;
        this.knownPeers = new ArrayList<>();
        this.routes = new HashMap<>(routes);
        
        // Convert Peer objects to lightweight PeerInfo for transmission
        for (Peer peer : peers) {
            this.knownPeers.add(new PeerInfo(
                peer.getNodeId(),
                peer.getAddress(),
                peer.getPort(),
                peer.getProofOfWork(),
                peer.getLastProofTimestamp(),
                peer.getRouteScore()
            ));
        }
    }

    /**
     * Represents a peer's information for network transmission.
     *
     * <p>
     * This record holds essential details about a peer, including its node ID, address, port,
     * proof of work, proof timestamp, and route score. It is used to transmit lightweight peer
     * information within gossip messages.
     * </p>
    *
    * @param nodeId         The unique identifier of the peer node.
    * @param address        The IP address of the peer node.
    * @param port           The port number on which the peer node is listening.
    * @param proofOfWork    The proof of work data used for validating the peer.
    * @param proofTimestamp The timestamp when the proof of work was generated.
    * @param routeScore     The score indicating the quality of the route to this peer.
    */
    public record PeerInfo(
        byte[] nodeId,
        String address,
        int port,
        byte[] proofOfWork,
        long proofTimestamp,
        double routeScore
    ) {}

    /**
     * Serializes the gossip message for network transmission.
     *
     * @return A byte array representing the serialized gossip message.
     * @throws IOException If an I/O error occurs during serialization.
     */
    public byte[] serialize() throws IOException {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             DataOutputStream dos = new DataOutputStream(baos)) {
            
            // Write message type and basic info
            dos.writeByte(GOSSIP_TYPE_FULL);
            dos.writeInt(nodeId.length);
            dos.write(nodeId);
            dos.writeInt(proofOfWork.length);
            dos.write(proofOfWork);
            dos.writeLong(proofTimestamp);
            
            // Write peer list
            dos.writeInt(knownPeers.size());
            for (PeerInfo peer : knownPeers) {
                dos.writeInt(peer.nodeId().length);
                dos.write(peer.nodeId());
                byte[] addressBytes = peer.address().getBytes();
                dos.writeInt(addressBytes.length);
                dos.write(addressBytes);
                dos.writeInt(peer.port());
                dos.writeInt(peer.proofOfWork().length);
                dos.write(peer.proofOfWork());
                dos.writeLong(peer.proofTimestamp());
                dos.writeDouble(peer.routeScore());
            }
            
            // Write routes information
            dos.writeInt(routes.size());
            for (Map.Entry<String, RouteInfo> entry : routes.entrySet()) {
                RouteInfo route = entry.getValue();
                dos.writeUTF(entry.getKey());          // Destination
                dos.writeUTF(route.getNextHop());           // Next hop
                dos.writeInt(route.getHopCount());          // Hop count
                dos.writeDouble(route.getPheromoneLevel()); // Pheromone level
                dos.writeDouble(route.getLatency());        // Latency
                dos.writeLong(route.getBandwidth());        // Bandwidth
            }
            
            return baos.toByteArray();
        }
    }

    /**
     * Deserializes a gossip message from network data.
     *
     * @param data The byte array containing the serialized gossip message.
     * @return A {@link GossipMessage} instance reconstructed from the provided data.
     * @throws IOException If an I/O error occurs during deserialization or if the message type is unsupported.
     */
    public static GossipMessage deserialize(byte[] data) throws IOException {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
             DataInputStream dis = new DataInputStream(bais)) {
            
            byte messageType = dis.readByte();
            if (messageType != GOSSIP_TYPE_FULL) {
                throw new IOException("Unsupported message type: " + messageType);
            }
            
            // Read basic info
            byte[] nodeId = new byte[dis.readInt()];
            dis.readFully(nodeId);
            byte[] proofOfWork = new byte[dis.readInt()];
            dis.readFully(proofOfWork);
            long proofTimestamp = dis.readLong();
            
            // Read peer list
            int peerCount = dis.readInt();
            List<Peer> peers = new ArrayList<>(peerCount);
            
            for (int i = 0; i < peerCount; i++) {
                byte[] peerNodeId = new byte[dis.readInt()];
                dis.readFully(peerNodeId);
                byte[] addressBytes = new byte[dis.readInt()];
                dis.readFully(addressBytes);
                String address = new String(addressBytes);
                int port = dis.readInt();
                byte[] peerProof = new byte[dis.readInt()];
                dis.readFully(peerProof);
                long peerProofTimestamp = dis.readLong();
                double routeScore = dis.readDouble();
                
                Peer peer = new Peer(address, port, peerNodeId);
                peer.setProofOfWork(peerProof);
                peer.setLastProofTimestamp(peerProofTimestamp);
                peer.setRouteScore(routeScore);
                peers.add(peer);
            }
            
            // Read routes
            int routeCount = dis.readInt();
            Map<String, RouteInfo> routes = new HashMap<>(routeCount);
            
            for (int i = 0; i < routeCount; i++) {
                String destination = dis.readUTF();
                String nextHop = dis.readUTF();
                int hopCount = dis.readInt();
                RouteInfo route = new RouteInfo(destination, nextHop, hopCount);
                route.setPheramoneLevel(dis.readDouble());
                route.setLatency(dis.readDouble());
                route.setBandwidth(dis.readLong());
                routes.put(destination, route);
            }
            
            return new GossipMessage(nodeId, proofOfWork, proofTimestamp, peers, routes);
        }
    }

    /**
     * Validates the gossip message format and basic constraints.
     *
     * @return {@code true} if the message is valid; {@code false} otherwise.
     */
    public boolean isValid() {
        if (nodeId == null || nodeId.length == 0 || 
            proofOfWork == null || proofOfWork.length == 0) {
            return false;
        }

        // Check timestamp is not in the future
        if (proofTimestamp > System.currentTimeMillis()) {
            return false;
        }

        // Validate each peer info
        for (PeerInfo peer : knownPeers) {
            if (peer.nodeId() == null || peer.nodeId().length == 0 ||
                peer.address() == null || peer.address().isEmpty() ||
                peer.port() <= 0 || peer.port() > 65535 ||
                peer.proofOfWork() == null || peer.proofOfWork().length == 0 ||
                peer.proofTimestamp() > System.currentTimeMillis()) {
                return false;
            }
        }

        // Validate routes
        for (RouteInfo route : routes.values()) {
            if (route.getDestination() == null || route.getDestination().isEmpty() ||
                route.getNextHop() == null || route.getNextHop().isEmpty() ||
                route.getHopCount() < 1 || route.getHopCount() > 255 ||
                route.getPheromoneLevel() < RouteInfo.getMIN_PHEROMONE() ||
                route.getLatency() < 0 || route.getBandwidth() < 0) {
                return false;
            }
        }

        return true;
    }

    /**
     * Retrieves the node ID of the sender.
     *
     * @return A byte array representing the node ID.
     */
    public byte[] getNodeId() { return nodeId; }

    /**
     * Retrieves the proof of work associated with the sender.
     *
     * @return A byte array representing the proof of work.
     */
    public byte[] getProofOfWork() { return proofOfWork; }

    /**
     * Retrieves the timestamp of when the proof of work was generated.
     *
     * @return The proof timestamp in milliseconds since the epoch.
     */
    public long getProofTimestamp() { return proofTimestamp; }

    /**
     * Retrieves the list of known peers.
     *
     * @return A list of {@link PeerInfo} records representing known peers.
     */
    public List<PeerInfo> getKnownPeers() { return knownPeers; }

    /**
     * Retrieves the routing information.
     *
     * @return A map mapping destinations to their respective {@link RouteInfo}.
     */
    public Map<String, RouteInfo> getRoutes() { return routes; }
}
