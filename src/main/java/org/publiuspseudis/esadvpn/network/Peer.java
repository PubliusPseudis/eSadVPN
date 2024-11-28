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

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.publiuspseudis.esadvpn.core.VPNConnection;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.publiuspseudis.esadvpn.routing.RouteInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code Peer} class represents a peer within the peer-to-peer (P2P) VPN network.
 * It encapsulates the peer's network address, identity, proof of work, and various routing metrics
 * such as latency and bandwidth. The class also manages the connection to the peer and tracks
 * data transfer statistics.
 * </p>
 * 
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Maintaining connection details with the peer.</li>
 *   <li>Tracking and updating data transfer statistics (bytes sent and received).</li>
 *   <li>Measuring and updating latency and bandwidth estimates.</li>
 *   <li>Determining the staleness of the peer based on activity.</li>
 *   <li>Calculating and updating routing scores based on network metrics.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Create a new peer instance
 * String peerAddress = "192.168.1.100";
 * int peerPort = 8081;
 * byte[] peerNodeId = new byte[32]; // Assume this is initialized appropriately
 * Peer peer = new Peer(peerAddress, peerPort, peerNodeId);
 * 
 * // Set proof of work details
 * byte[] proof = ...; // Obtain proof of work bytes
 * long proofTimestamp = System.currentTimeMillis();
 * peer.setProofOfWork(proof);
 * peer.setLastProofTimestamp(proofTimestamp);
 * 
 * // Update metrics based on network activity
 * peer.recordBytesSent(1024);
 * peer.recordBytesReceived(2048);
 * peer.updateLatency(50.5); // Latency in milliseconds
 * 
 * // Check if the peer is stale
 * if (peer.isStale()) {
 *     // Handle stale peer
 * }
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>
 * </p>
 * <p>
 * The {@code Peer} class utilizes atomic operations and volatile variables to ensure thread-safe
 * updates to metrics such as bytes sent/received, latency, and bandwidth. This design allows
 * concurrent access and modification of peer metrics without risking data inconsistencies.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>{@link VPNConnection}: Manages the VPN connection to the peer.</li>
 *   <li>SLF4J Logging Framework: Used for logging events and debugging.</li>
 * </ul>
 * 
 * @author
 * Publius Pseudis
 */
public class Peer {
    /**
     * Logger instance for logging information, warnings, and errors.
     */
    private static final Logger log = LoggerFactory.getLogger(Peer.class);
    private final Map<String, Double> peerReputations = new ConcurrentHashMap<>();
    public void initializeReputation(String peerId) {
        peerReputations.put(peerId, RouteInfo.INIT_REPUTATION);
    }

    public void updatePeerReputation(String peerId, boolean success) {
        double currentRep = peerReputations.getOrDefault(peerId, RouteInfo.INIT_REPUTATION);
        if (success) {
            peerReputations.put(peerId, Math.min(1.0, currentRep + RouteInfo.DELTA_R_POS));
        } else {
            peerReputations.put(peerId, Math.max(0.0, currentRep - RouteInfo.DELTA_R_NEG));
        }
    }

    public double getPeerReputation(String peerId) {
        return peerReputations.getOrDefault(peerId, RouteInfo.INIT_REPUTATION);
    }
    /**
     * The IP address of the peer.
     */
    private final String address;
    
    /**
     * The port number on which the peer is listening.
     */
    private final int port;
    
    /**
     * The unique node ID of the peer.
     */
    private final byte[] nodeId;
    
    /**
     * The proof of work associated with the peer.
     */
    private byte[] proofOfWork;
    
    /**
     * The timestamp when the peer last provided a proof of work.
     */
    private long lastProofTimestamp;
    
    /**
     * The timestamp of the last gossip message received from the peer.
     */
    private volatile long lastGossip;
    
    /**
     * The {@link VPNConnection} instance managing the connection to the peer.
     */
    private VPNConnection connection;
    
    // Routing and metrics
    
    /**
     * The score representing the quality of the route through this peer.
     * Higher scores indicate better routes.
     */
    private volatile double routeScore;
    
    /**
     * The total number of bytes sent to the peer.
     */
    private final AtomicLong bytesSent;
    
    /**
     * The total number of bytes received from the peer.
     */
    private final AtomicLong bytesReceived;
    
    /**
     * The current latency measured to the peer in milliseconds.
     */
    private volatile double latency;
    
    /**
     * The timestamp of the last latency update.
     */
    private volatile long lastLatencyUpdate;
    
    /**
     * The estimated bandwidth to the peer in bytes per second.
     */
    private volatile long estimatedBandwidth;
    
    /**
     * The timestamp of the last bandwidth calculation.
     */
    private volatile long lastBandwidthCalculation;
    
    // Timeouts and thresholds
    
    /**
     * The duration after which a peer is considered stale if no activity is detected.
     */
    private static final long STALE_THRESHOLD = TimeUnit.SECONDS.toMillis(30);
    
    /**
     * The interval at which bandwidth estimates are recalculated.
     */
    private static final long BANDWIDTH_CALC_INTERVAL = TimeUnit.SECONDS.toMillis(5);
    
    /**
     * The interval at which latency measurements are updated.
     */
    private static final long LATENCY_UPDATE_INTERVAL = TimeUnit.SECONDS.toMillis(10);
    
    /**
     * The timestamp of the last time the peer was seen.
     */
    private volatile long lastSeen;

    /**
     * Creates a new peer with the specified network address and identity.
     *
     * @param address The IP address of the peer.
     * @param port    The port number on which the peer is listening.
     * @param nodeId  The unique node ID of the peer.
     */
    public Peer(String address, int port, byte[] nodeId) {
        this.address = address;
        this.port = port;
        this.nodeId = nodeId;
        this.lastGossip = System.currentTimeMillis();
        this.lastSeen = System.currentTimeMillis();
        
        // Initialize metrics
        this.routeScore = 0.0;
        this.bytesSent = new AtomicLong(0);
        this.bytesReceived = new AtomicLong(0);
        this.latency = Double.MAX_VALUE;
        this.lastLatencyUpdate = 0;
        this.estimatedBandwidth = 0;
        this.lastBandwidthCalculation = System.currentTimeMillis();
    }

    /**
     * Updates the last seen timestamp to mark the peer as active.
     */
    public void updateLastSeen() {
        this.lastSeen = System.currentTimeMillis();
    }
    
    /**
     * Determines whether the peer connection is considered stale based on inactivity.
     *
     * @return {@code true} if the peer is stale; {@code false} otherwise.
     */
    public boolean isStale() {
        return System.currentTimeMillis() - lastSeen > STALE_THRESHOLD;
    }

    /**
     * Records the number of bytes sent to this peer and updates the bandwidth estimate.
     *
     * @param bytes The number of bytes sent.
     */
    public void recordBytesSent(long bytes) {
        bytesSent.addAndGet(bytes);
        updateBandwidthEstimate();
    }

    /**
     * Records the number of bytes received from this peer and updates the bandwidth estimate.
     *
     * @param bytes The number of bytes received.
     */
    public void recordBytesReceived(long bytes) {
        bytesReceived.addAndGet(bytes);
        updateBandwidthEstimate();
    }

    /**
     * Updates the latency measurement for this peer using an exponential moving average.
     * Only updates if the designated interval has passed since the last update.
     *
     * @param newLatency The newly measured latency in milliseconds.
     */
    public void updateLatency(double newLatency) {
        long now = System.currentTimeMillis();
        if (now - lastLatencyUpdate >= LATENCY_UPDATE_INTERVAL) {
            // Use exponential moving average for latency
            if (this.latency == Double.MAX_VALUE) {
                this.latency = newLatency;
            } else {
                this.latency = (this.latency * 0.7) + (newLatency * 0.3);
            }
            this.lastLatencyUpdate = now;
            updateRouteScore(); // Recalculate route score with new latency
        }
    }

    /**
     * Updates the bandwidth estimate based on recent traffic. Uses an exponential moving average
     * to smooth out fluctuations in bandwidth measurements.
     */
    private void updateBandwidthEstimate() {
        long now = System.currentTimeMillis();
        long interval = now - lastBandwidthCalculation;
        
        if (interval >= BANDWIDTH_CALC_INTERVAL) {
            long totalBytes = bytesSent.get() + bytesReceived.get();
            long bytesPerSecond = (totalBytes * 1000) / interval;
            
            // Update bandwidth estimate with some smoothing
            if (estimatedBandwidth == 0) {
                estimatedBandwidth = bytesPerSecond;
            } else {
                estimatedBandwidth = (estimatedBandwidth * 7 + bytesPerSecond * 3) / 10;
            }
            
            // Reset counters
            bytesSent.set(0);
            bytesReceived.set(0);
            lastBandwidthCalculation = now;
            
            updateRouteScore(); // Recalculate route score with new bandwidth
        }
    }

    /**
     * Updates the overall route score based on current latency and bandwidth metrics.
     * Combines normalized latency and bandwidth scores with equal weighting.
     */
    private void updateRouteScore() {
        // Normalize metrics to 0-1 range
        double latencyScore = 1.0 / (1 + this.latency);
        double bandwidthScore = Math.log1p(this.estimatedBandwidth) / 10.0;
        
        // Calculate weighted score
        this.routeScore = (latencyScore * 0.5) + (bandwidthScore * 0.5);
        
        log.debug("Updated route score for peer {}: score={}, latency={}, bandwidth={}", 
            address, routeScore, latency, estimatedBandwidth);
    }

    // Getters and setters

    /**
     * Retrieves the IP address of the peer.
     *
     * @return The IP address as a {@link String}.
     */
    public String getAddress() { return address; }

    /**
     * Retrieves the port number of the peer.
     *
     * @return The port number as an {@code int}.
     */
    public int getPort() { return port; }

    /**
     * Retrieves the node ID of the peer.
     *
     * @return The node ID as a byte array.
     */
    public byte[] getNodeId() { return nodeId; }

    /**
     * Retrieves the proof of work associated with the peer.
     *
     * @return The proof of work as a byte array.
     */
    public byte[] getProofOfWork() { return proofOfWork; }

    /**
     * Sets the proof of work for the peer.
     *
     * @param pow The proof of work as a byte array.
     */
    public void setProofOfWork(byte[] pow) { this.proofOfWork = pow; }

    /**
     * Retrieves the timestamp of the last proof of work provided by the peer.
     *
     * @return The timestamp in milliseconds since the epoch.
     */
    public long getLastProofTimestamp() { return lastProofTimestamp; }

    /**
     * Sets the timestamp of the last proof of work provided by the peer.
     *
     * @param timestamp The timestamp in milliseconds since the epoch.
     */
    public void setLastProofTimestamp(long timestamp) { this.lastProofTimestamp = timestamp; }

    /**
     * Updates the timestamp of the last gossip message received from the peer.
     */
    public void updateLastGossip() { this.lastGossip = System.currentTimeMillis(); }

    /**
     * Retrieves the timestamp of the last gossip message received from the peer.
     *
     * @return The timestamp in milliseconds since the epoch.
     */
    public long getLastGossip() { return lastGossip; }

    /**
     * Retrieves the VPN connection instance associated with this peer.
     *
     * @return The {@link VPNConnection} instance.
     */
    public VPNConnection getConnection() { return connection; }

    /**
     * Sets the VPN connection instance for this peer.
     *
     * @param conn The {@link VPNConnection} instance to be associated with the peer.
     */
    public void setConnection(VPNConnection conn) { this.connection = conn; }

    /**
     * Retrieves the current route score for this peer.
     *
     * @return The route score as a {@code double}.
     */
    public double getRouteScore() { return routeScore; }

    /**
     * Sets the route score for this peer.
     *
     * @param score The route score as a {@code double}.
     */
    public void setRouteScore(double score) { this.routeScore = score; }

    /**
     * Retrieves the current latency measurement to the peer.
     *
     * @return The latency in milliseconds as a {@code double}.
     */
    public double getLatency() { return latency; }

    /**
     * Retrieves the estimated bandwidth to the peer.
     *
     * @return The estimated bandwidth in bytes per second as a {@code long}.
     */
    public long getEstimatedBandwidth() { return estimatedBandwidth; }

    /**
     * Provides a string representation of the peer, including address, port, route score,
     * latency, and bandwidth.
     *
     * @return A formatted {@link String} representing the peer.
     */
    @Override
    public String toString() {
        return String.format("Peer[address=%s, port=%d, score=%.3f, latency=%.2fms, bandwidth=%d B/s]",
            address, port, routeScore, latency, estimatedBandwidth);
    }
}
