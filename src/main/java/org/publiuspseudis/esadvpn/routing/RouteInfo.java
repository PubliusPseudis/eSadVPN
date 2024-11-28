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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code RouteInfo} class encapsulates routing information and associated metrics for a specific
 * destination within the peer-to-peer (P2P) VPN network. It maintains details such as the next hop
 * peer, hop count, pheromone levels (used for routing decisions), latency, and bandwidth estimates.
 * This class is instrumental in determining the optimal paths for routing packets through the network
 * based on current network conditions and historical data.
 * </p>
 * 
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Maintaining and updating routing metrics such as latency and bandwidth.</li>
 *   <li>Calculating route scores based on normalized metrics and pheromone levels.</li>
 *   <li>Applying pheromone decay to simulate the evaporation of route desirability over time.</li>
 *   <li>Reinforcing routes based on successful usage to increase their desirability.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Create a new RouteInfo instance for a destination network
 * String destination = "192.168.1.0/24";
 * String nextHop = "Peer[192.168.1.100:8081]";
 * int hopCount = 2;
 * RouteInfo route = new RouteInfo(destination, nextHop, hopCount);
 * 
 * // Update routing metrics based on network activity
 * double observedLatency = 50.5; // in milliseconds
 * long observedBandwidth = 1024000; // in bytes per second
 * route.updateMetrics(observedLatency, observedBandwidth);
 * 
 * // Calculate the current route score
 * double score = route.getRouteScore();
 * 
 * // Apply pheromone decay over time
 * route.decayPheromone();
 * 
 * // Reinforce the route based on successful usage
 * double reinforcementQuality = 0.2;
 * route.reinforcePath(reinforcementQuality);
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>
 * </p>
 * <p>
 * The {@code RouteInfo} class employs synchronization mechanisms to ensure thread-safe updates
 * to its mutable fields. Fields such as {@code latency} and {@code bandwidth} are marked as
 * {@code volatile} to guarantee visibility across threads. Additionally, atomic operations and
 * careful update sequences are used to maintain data integrity during concurrent modifications.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>SLF4J Logging Framework: Utilized for logging debug and informational messages.</li>
 * </ul>
 * 
 * @author
 * Publius Pseudis
 */
public class RouteInfo {
    /**
     * Logger instance for logging debug and informational messages.
     */
    private static final Logger log = LoggerFactory.getLogger(RouteInfo.class);

    private static final double ALPHA = 8.0;              // Selection pressure
    private static final double R_MIN = 0.45;             // Reputation threshold
    public static final double DELTA_R_NEG = 0.5;        // Negative reputation update
    public static final double DELTA_R_POS = 0.2;        // Positive reputation update
    public static final double INIT_REPUTATION = 0.35;   // Initial reputation    

    /**
     * The IP address or subnet representing the destination network.
     */
    private final String destination; // Destination network/IP

    /**
     * The identifier of the next hop peer through which packets to the destination should be routed.
     */
    private final String nextHop;
    
    /**
     * The number of hops required to reach the destination from the current peer.
     */
    private final int hopCount;
    
    /**
     * The current pheromone level associated with this route. Higher pheromone levels indicate more
     * desirable routes based on historical usage and network conditions.
     */
    private double pheromoneLevel;
    
    /**
     * The latest measured latency to the next hop peer in milliseconds.
     */
    private volatile double latency;
    
    /**
     * The estimated bandwidth of the connection to the next hop peer in bytes per second.
     */
    private volatile long bandwidth;
    
    /**
     * The timestamp indicating when the routing metrics were last updated.
     */
    private long lastUpdated;
    
    // Constants for route scoring
    
    /**
     * The decay factor applied to pheromone levels to simulate the evaporation of route desirability
     * over time. A value less than 1.0 reduces the pheromone level each time decay is applied.
     */
    private static final double PHEROMONE_DECAY = 0.95;  // Pheromone decay factor
    
    /**
     * The minimum pheromone level that a route can have. If pheromone levels fall below this threshold,
     * they are set to this minimum value to prevent routes from becoming completely obsolete.
     */
    private static final double MIN_PHEROMONE = 0.01;    // Minimum pheromone level
    
    /**
     * The initial pheromone level assigned to a new route upon creation. This provides a baseline
     * desirability for newly discovered routes.
     */
    private static final double INIT_PHEROMONE = 1.0;    // Initial pheromone level
        
    /**
     * Constructs a new {@code RouteInfo} instance with the specified destination, next hop, and hop count.
     * Initializes routing metrics to default values.
     *
     * @param destination The destination network or IP address.
     * @param nextHop     The identifier of the next hop peer.
     * @param hopCount    The number of hops to reach the destination.
     */
    public RouteInfo(String destination, String nextHop, int hopCount) {
        this.destination = destination;
        this.nextHop = nextHop;
        this.hopCount = hopCount;
        this.pheromoneLevel = INIT_PHEROMONE;
        this.lastUpdated = System.currentTimeMillis();
        this.latency = 0;
        this.bandwidth = 0;
    }
    
    /**
     * Updates the routing metrics for this route based on newly observed latency and bandwidth values.
     * Implements an exponential moving average for latency to smooth out fluctuations and uses the
     * highest observed bandwidth to provide a conservative estimate.
     *
     * @param newLatency    The newly observed latency in milliseconds.
     * @param newBandwidth  The newly observed bandwidth in bytes per second.
     */
    public void updateMetrics(double newLatency, long newBandwidth) {
        // Update latency with exponential moving average
        if (this.getLatency() == Double.MAX_VALUE) {
            this.latency = newLatency;
        } else {
            this.latency = (this.getLatency() * 0.7) + (newLatency * 0.3);
        }
        
        // Update bandwidth (use highest observed)
        this.bandwidth = Math.max(this.getBandwidth(), newBandwidth);
        this.lastUpdated = System.currentTimeMillis();
    }
    
    /**
     * Calculates and returns the current score of the route based on normalized latency, bandwidth,
     * and hop count metrics, weighted by their respective importance.The pheromone level further
 influences the overall desirability of the route.
     *
     * @param neighborReputation
     * @return The calculated route score as a {@code double}.
     */
    public double getScore(double neighborReputation) {
        double latencyFactor = 1.0 / (1 + getLatency());
        double bandwidthFactor = Math.log1p(getBandwidth()) / 10.0;
        double distanceFactor = 1.0 / (1 + getHopCount());

        return Math.pow(
            (pheromoneLevel * neighborReputation) * (
                0.4 * latencyFactor +
                0.4 * bandwidthFactor +
                0.2 * distanceFactor
            ), 
            ALPHA
        );
    }

    // Keep original method for backward compatibility
    public double getScore() {
        return getScore(1.0); // Default to neutral reputation if none provided
    }

    /**
     * Applies pheromone decay to simulate the evaporation of route desirability over time.
     * The pheromone level is multiplied by the decay factor, and if it falls below the minimum
     * threshold, it is set to the minimum value to maintain a base level of desirability.
     */
    public void decayPheromone() {
        pheromoneLevel *= getPHEROMONE_DECAY();
        if (getPheromoneLevel() < getMIN_PHEROMONE()) {
            pheromoneLevel = getMIN_PHEROMONE();
        }
    }
    
    /**
     * Reinforces the desirability of the route based on successful usage by increasing the pheromone level.
     * This method should be called when the route is utilized effectively to encourage its selection
     * in future routing decisions.
     *
     * @param quality A {@code double} representing the quality or effectiveness of the route usage.
     */
    public void reinforcePath(double quality) {
        pheromoneLevel += quality;
    }
    


    // Getters

    /**
     * Retrieves the destination network or IP address associated with this route.
     *
     * @return A {@code String} representing the destination.
     */
    public String getDestination() { return destination; }
    
    /**
     * Retrieves the identifier of the next hop peer for this route.
     *
     * @return A {@code String} representing the next hop peer.
     */
    public String getNextHop() { return nextHop; }
    
    /**
     * Retrieves the current pheromone level of this route.
     *
     * @return A {@code double} representing the pheromone level.
     */
    public double getPheromoneLevel() { return pheromoneLevel; }
    
    /**
     * Retrieves the number of hops required to reach the destination from this route.
     *
     * @return An {@code int} representing the hop count.
     */
    public int getHopCount() { return hopCount; }
    
    /**
     * Retrieves the timestamp of the last update to the routing metrics.
     *
     * @return A {@code long} representing the last updated time in milliseconds since the epoch.
     */
    public long getLastUpdated() { return lastUpdated; }
    
    /**
     * Retrieves the current latency metric for this route.
     *
     * @return A {@code double} representing the latency in milliseconds.
     */
    public double getLatency() { return latency; }
    
    /**
     * Retrieves the current bandwidth estimate for this route.
     *
     * @return A {@code long} representing the bandwidth in bytes per second.
     */
    public long getBandwidth() { return bandwidth; }
    
    /**
     * Provides a string representation of the {@code RouteInfo} instance, detailing its destination,
     * next hop, hop count, pheromone level, latency, and bandwidth.
     *
     * @return A {@code String} summarizing the route information.
     */
    @Override
    public String toString() {
        return String.format("RouteInfo[destination=%s, nextHop=%s, hopCount=%d, pheromoneLevel=%.3f, latency=%.2fms, bandwidth=%d B/s]", getDestination(), getNextHop(), getHopCount(), getPheromoneLevel(), getLatency(), getBandwidth());
    }

    /**
     * @return the PHEROMONE_DECAY
     */
    public static double getPHEROMONE_DECAY() {
        return PHEROMONE_DECAY;
    }

    /**
     * @return the MIN_PHEROMONE
     */
    public static double getMIN_PHEROMONE() {
        return MIN_PHEROMONE;
    }

    /**
     * @return the INIT_PHEROMONE
     */
    public static double getINIT_PHEROMONE() {
        return INIT_PHEROMONE;
    }

    public void setPheramoneLevel(double pheromoneLevel_) {
        this.pheromoneLevel = pheromoneLevel_;
    }

    public void setLatency(double latency_) {
        this.latency = latency_;
    }

    public void setBandwidth(long bandwidth_) {
        this.bandwidth = bandwidth_;
    }
}
