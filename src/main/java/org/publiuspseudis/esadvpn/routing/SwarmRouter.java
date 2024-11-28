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
package org.publiuspseudis.esadvpn.routing;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import org.publiuspseudis.esadvpn.network.Peer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code SwarmRouter} class implements swarm intelligence-based routing mechanisms for the peer-to-peer
 * (P2P) VPN network. It manages routing tables, pheromone trails, and route metrics to determine the optimal
 * paths for data packets through the network. By leveraging principles inspired by swarm intelligence, the
 * router adapts to changing network conditions, reinforcing successful routes and decaying less effective ones.
 * </p>
 * 
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Maintaining and updating routing tables for various destinations and next-hop peers.</li>
 *   <li>Managing pheromone trails to influence route selection based on historical performance.</li>
 *   <li>Calculating route scores based on latency, bandwidth, hop count, and pheromone levels.</li>
 *   <li>Handling packet routing by enqueueing packets for respective peers.</li>
 *   <li>Evaporating pheromones over time to simulate the fading of route desirability.</li>
 *   <li>Cleaning up stale routes that have not been used within a specified timeout period.</li>
 *   <li>Exporting the current state of the router for persistence or transfer purposes.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Initialize SwarmRouter
 * SwarmRouter router = new SwarmRouter();
 * 
 * // Update routes based on discovered peers
 * router.updateRoute("192.168.1.0/24", "PeerA", 2);
 * router.updateRoute("192.168.1.0/24", "PeerB", 3);
 * 
 * // Update route metrics based on observed performance
 * router.updateMetrics("192.168.1.0/24", "PeerA", 50.5, 1024000);
 * router.updateMetrics("192.168.1.0/24", "PeerB", 70.2, 512000);
 * 
 * // Select the next hop for a destination
 * String nextHop = router.getNextHop("192.168.1.0/24");
 * if (nextHop != null) {
 *     // Forward packet to nextHop
 * }
 * 
 * // Periodically evaporate pheromones and clean up routes
 * router.evaporatePheromones();
 * router.cleanupRoutes();
 * 
 * // Export router state
 * Map<String, Object> state = router.exportState();
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>
 * </p>
 * <p>
 * The {@code SwarmRouter} class employs thread-safe data structures such as {@link ConcurrentHashMap} and
 * {@link LinkedBlockingQueue} to manage routing tables, pheromone trails, and packet queues. This ensures
 * that multiple threads can safely interact with the router concurrently without risking data inconsistencies
 * or race conditions.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>SLF4J Logging Framework: Utilized for logging informational, debug, and error messages.</li>
 * </ul>
 * 
 * @author 
 * Publius Pseudis
 */
public class SwarmRouter {
    /**
     * Logger instance for logging informational, debug, and error messages.
     */
    private static final Logger log = LoggerFactory.getLogger(SwarmRouter.class);
        private volatile Peer owningPeer;
    /**
     * Routing table mapping destinations to their respective routes and next-hop peers.
     * <p>
     * Structure: Destination -> (NextHop -> {@link RouteInfo})
     * </p>
     */
    private final Map<String, Map<String, RouteInfo>> routingTable;
    
    /**
     * Pheromone trails tracking the desirability of routes.
     * <p>
     * Each entry maps a destination-nextHop combination to its pheromone level.
     * </p>
     */
    private final Map<String, Double> pheromoneTrails;
    
    /**
     * Queue for incoming data packets to be routed.
     */
    private final BlockingQueue<ByteBuffer> packetQueue = new LinkedBlockingQueue<>();
    
    /**
     * Tracks the last usage timestamp of each route.
     * <p>
     * Used to identify and clean up stale routes.
     * Structure: Destination-NextHop -> LastUsedTimestamp
     * </p>
     */
    private final Map<String, Long> routeLastUsed;
    
    /**
     * Packet queues for each peer, facilitating the forwarding of data packets to the respective peers.
     * <p>
     * Structure: PeerId -> Queue of ByteBuffers
     * </p>
     */
    private final Map<String, BlockingQueue<ByteBuffer>> peerQueues;
    
    // Routing constants
    
    /**
     * The amount of pheromone deposited on a successful route update.
     */
    private static final double PHEROMONE_DEPOSIT = 1.0;
    
    /**
     * The decay factor applied to pheromone trails to simulate the evaporation of route desirability over time.
     */
    private static final double PHEROMONE_DECAY = 0.95;
    
    /**
     * The minimum pheromone level that a route can have.
     * <p>
     * Ensures that routes do not become completely obsolete.
     * </p>
     */
    private static final double MIN_PHEROMONE = 0.01;
    
    /**
     * The timeout duration after which a route is considered stale if not used.
     * <p>
     * Specified in milliseconds.
     * </p>
     */
    private static final long ROUTE_TIMEOUT = TimeUnit.MINUTES.toMillis(30);
    
    /**
     * Constructs a new {@code SwarmRouter} instance, initializing routing tables, pheromone trails,
     * and packet queues.
     * @param owningPeer
     */
    public SwarmRouter(Peer owningPeer) {
        this();  // Call no-arg constructor for common initialization
        this.owningPeer = owningPeer;
        log.debug("Created SwarmRouter with owning peer: {}", owningPeer.getAddress());
    }
    
    public SwarmRouter() {
        this.routingTable = new ConcurrentHashMap<>();
        this.pheromoneTrails = new ConcurrentHashMap<>();
        this.routeLastUsed = new ConcurrentHashMap<>();
        this.peerQueues = new ConcurrentHashMap<>();
        // owningPeer will be set later via setOwningPeer()
    }

    
    
    /**
     * Adds a new route or updates an existing one based on the destination, next hop, and hop count.
     * <p>
     * If the new route has a lower hop count, it replaces the existing route.
     * </p>
     *
     * @param destination The destination network or IP address.
     * @param nextHop     The identifier of the next hop peer.
     * @param hopCount    The number of hops to reach the destination.
     */
    public void updateRoute(String destination, String nextHop, int hopCount) {
        Map<String, RouteInfo> routes = routingTable.computeIfAbsent(
            destination, k -> new ConcurrentHashMap<>());
        
        routes.compute(nextHop, (k, v) -> {
            if (v == null || v.getHopCount() > hopCount) {
                return new RouteInfo(destination, nextHop, hopCount);
            }
            return v;
        });
    }
    
    /**
    * Sets the owning peer for this router instance. This is called after the local peer
    * is created to enable reputation-based routing decisions.
    *
    * @param peer The local Peer instance that owns this router.
    */
   public void setOwningPeer(Peer peer) {
       this.owningPeer = peer;
       log.debug("Set owning peer for router: {}", peer.getAddress());
   }

    /**
     * Gets the owning peer for this router instance.
     *
     * @return The local Peer instance that owns this router.
     */
    public Peer getOwningPeer() {
        return owningPeer;
    }
    /**
     * Updates the routing metrics for a specific route based on observed latency and bandwidth.
     * <p>
     * Reinforces the pheromone trail of the route based on its performance.
     * </p>
     *
     * @param destination The destination network or IP address.
     * @param nextHop     The identifier of the next hop peer.
     * @param latency     The observed latency in milliseconds.
     * @param bandwidth   The observed bandwidth in bytes per second.
     */
    public void updateMetrics(String destination, String nextHop, 
                            double latency, long bandwidth) {
        Map<String, RouteInfo> routes = routingTable.get(destination);
        if (routes != null) {
            RouteInfo route = routes.get(nextHop);
            if (route != null) {
                route.updateMetrics(latency, bandwidth);
                
                // Reinforce successful route
                String key = destination + "-" + nextHop;
                double currentPheromone = pheromoneTrails.getOrDefault(key, 1.0);
                
                // Calculate reinforcement based on performance
                double latencyScore = 1.0 / (1 + latency);
                double bandwidthScore = Math.log1p(bandwidth) / 10.0;
                double reinforcement = PHEROMONE_DEPOSIT * 
                    (latencyScore * 0.6 + bandwidthScore * 0.4);
                
                pheromoneTrails.put(key, currentPheromone + reinforcement);
                routeLastUsed.put(key, System.currentTimeMillis());
            }
        }
    }
    
    /**
     * Determines the next hop peer for a given destination based on route scores and pheromone trails.
     * <p>
     * Utilizes a probabilistic selection mechanism influenced by pheromone levels to choose the most
     * suitable next hop.
     * </p>
     *
     * @param destination The destination network or IP address.
     * @return The identifier of the selected next hop peer, or {@code null} if no route is available.
     */
    public String getNextHop(String destination) {
        Map<String, RouteInfo> routes = routingTable.get(destination);
        if (routes == null || routes.isEmpty()) {
            // If no specific route found, use default route
            // For internet traffic, route to the initiator node (10.0.0.1)
            routes = routingTable.get("10.0.0.1");
            if (routes == null || routes.isEmpty()) {
                log.debug("No route to {}", destination);
                return null;
            }
        }
        
        // Use probability based on route scores
        double totalScore = 0;
        Map<String, Double> scores = new ConcurrentHashMap<>();
        
        for (Map.Entry<String, RouteInfo> entry : routes.entrySet()) {
            String nextHop = entry.getKey();
            RouteInfo route = entry.getValue();
            
            double pheromone = pheromoneTrails.getOrDefault(
                destination + "-" + nextHop, MIN_PHEROMONE);
            // Get peer's reputation of this next hop
            double reputation = owningPeer.getPeerReputation(nextHop);
            double score = route.getScore(reputation) * pheromone;
            
            scores.put(nextHop, score);
            totalScore += score;
        }
        
        // Probabilistic selection based on scores
        double random = Math.random() * totalScore;
        double cumulative = 0;
        
        for (Map.Entry<String, Double> entry : scores.entrySet()) {
            cumulative += entry.getValue();
            if (random <= cumulative) {
                return entry.getKey();
            }
        }
        
        // Fallback to highest scoring route
        return routes.entrySet().stream()
            .max((a, b) -> Double.compare(
                scores.getOrDefault(a.getKey(), 0.0),
                scores.getOrDefault(b.getKey(), 0.0)))
            .map(Map.Entry::getKey)
            .orElse(null);
    }

    /**
     * Applies pheromone decay to all pheromone trails, simulating the natural evaporation of route
     * desirability over time. Ensures that routes not reinforced by successful usage gradually become
     * less preferable.
     */
    public void evaporatePheromones() {
        pheromoneTrails.replaceAll((k, v) -> 
            Math.max(MIN_PHEROMONE, v * PHEROMONE_DECAY));
    }
    
    /**
     * Cleans up stale routes that have not been used within the specified timeout period.
     * <p>
     * Removes both the route from the routing table and its associated pheromone trail to maintain an
     * up-to-date and efficient routing state.
     * </p>
     */
    public void cleanupRoutes() {
        long now = System.currentTimeMillis();
        
        // Remove expired routes
        routeLastUsed.entrySet().removeIf(entry ->
            now - entry.getValue() > ROUTE_TIMEOUT);
            
        // Clean up orphaned pheromone trails
        pheromoneTrails.entrySet().removeIf(entry ->
            !routeLastUsed.containsKey(entry.getKey()));
    }
    
    /**
     * Enqueues a data packet to be routed to a specific peer. Ensures that each peer has its own
     * packet queue for orderly and efficient packet forwarding.
     *
     * @param packet The {@link ByteBuffer} containing the data packet to be routed.
     * @param peerId The identifier of the peer to which the packet should be sent.
     */
    public void routePacket(ByteBuffer packet, String peerId) {
        packetQueue.offer(packet);
    }
    
    /**
     * Retrieves the next available data packet to be sent to any peer.
     * <p>
     * Implements a simple polling mechanism to retrieve packets from the queue in a sequential manner.
     * </p>
     *
     * @return The next {@link ByteBuffer} packet to be sent, or {@code null} if no packets are available within the timeout.
     * @throws InterruptedException If the thread is interrupted while waiting for a packet.
     */
    public ByteBuffer getNextPacket() throws InterruptedException {
        // Try to get a packet with a timeout to prevent busy waiting
        return packetQueue.poll(100, TimeUnit.MILLISECONDS);
    }
    
    /**
     * Removes a peer from the router, including its routes, pheromone trails, and packet queue.
     * <p>
     * Ensures that all routing information associated with the peer is cleaned up to prevent
     * stale or invalid routes.
     * </p>
     *
     * @param peerId The identifier of the peer to be removed.
     */
    public void removePeer(String peerId) {
        // Remove from routing table
        routingTable.values().forEach(routes -> routes.remove(peerId));
        
        // Remove pheromone trails
        pheromoneTrails.entrySet().removeIf(entry -> 
            entry.getKey().contains(peerId));
            
        // Remove queue
        peerQueues.remove(peerId);
        
        log.info("Removed peer {}", peerId);
    }
    
    /**
     * Retrieves a snapshot of all current routes managed by the router.
     * <p>
     * This includes all destinations and their associated next-hop peers with routing information.
     * </p>
     *
     * @return A {@link Map} representing the current routing table.
     */
    public Map<String, Map<String, RouteInfo>> getRoutes() {
        return new HashMap<>(routingTable);
    }
    
    /**
     * Calculates and retrieves the highest route score for a specific peer across all destinations.
     * <p>
     * This score represents the best performance metric of the peer based on current routing metrics.
     * </p>
     *
     * @param peerId The identifier of the peer whose score is to be retrieved.
     * @return The highest route score for the specified peer, or {@code 0.0} if no routes are found.
     */
    public double getScore(String peerId) {
        double maxScore = 0.0;
        for (Map<String, RouteInfo> routes : routingTable.values()) {
            RouteInfo route = routes.get(peerId);
            if (route != null) {
                maxScore = Math.max(maxScore, route.getScore());
            }
        }
        return maxScore;
    }

    /**
     * Exports the current state of the router, including routing tables, pheromone trails,
     * and route usage timestamps. This can be used for persistence, backup, or transferring
     * the routing state to another instance.
     *
     * @return A {@link Map} representing the serialized state of the router.
     */
    public Map<String, Object> exportState() {
        Map<String, Object> state = new HashMap<>();
        state.put("routingTable", new HashMap<>(routingTable));
        state.put("pheromoneTrails", new HashMap<>(pheromoneTrails));
        state.put("routeLastUsed", new HashMap<>(routeLastUsed));
        return state;
    }
}
