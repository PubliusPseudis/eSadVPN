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
package org.publiuspseudis.pheromesh.app;

import org.publiuspseudis.pheromesh.proxy.SocksProxy;
import org.publiuspseudis.pheromesh.network.P2PNetwork;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code Main} class serves as the entry point for the Publius Pseudis Everyday Swarm 
 * Assisted Decentralized VPN (pheromesh) application. It initializes and manages the lifecycle of 
 * VPN nodes within a peer-to-peer (P2P) network and sets up a SOCKS proxy to facilitate 
 * secure internet access through the VPN.
 * </p>
 * 
 * <p>
 * <strong>Program Description:</strong>
 * The pheromesh application allows users to create and join a decentralized VPN network. 
 * Users can operate in two primary modes:
 * </p>
 * 
 * <ul>
 *   <li><strong>P2P Mode:</strong> Initializes the first node (initiator) in the VPN network, 
 *       listening on a specified port and setting up a SOCKS proxy on the subsequent port.</li>
 *   <li><strong>Connect Mode:</strong> Joins an existing VPN network by connecting to a specified 
 *       peer address and port, and sets up a SOCKS proxy on the subsequent port.</li>
 * </ul>
 * 
 * <p>
 * The application ensures secure communication between peers using underlying P2P network 
 * protocols and provides a SOCKS proxy to route internet traffic securely through the VPN.
 * </p>
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Start the first VPN node (initiator) on port 8942
 * java -jar pheromesh.jar p2p 8942
 * // This will start the VPN service on port 8942 and the SOCKS proxy on port 8943
 * 
 * // Connect a second VPN node to the existing network via localhost on port 8942
 * java -jar pheromesh.jar connect 8944 localhost 8942
 * // This will start the VPN service on port 8944 and the SOCKS proxy on port 8945
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>
 * </p>
 * <p>
 * The {@code Main} class is designed to be thread-safe. It utilizes concurrent data structures 
 * and atomic variables to manage network connections and ensure consistent behavior across 
 * multiple threads.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>{@link P2PNetwork}: Manages peer-to-peer network communications and VPN connections.</li>
 *   <li>{@link SocksProxy}: Implements a SOCKS proxy server to route internet traffic through the VPN.</li>
 *   <li>SLF4J Logging Framework: Used for logging informational, debug, and error messages.</li>
 * </ul>
 * 
 * @author 
 * Publius Pseudis
 */
public class Main {
    
    /**
     * Logger instance from SLF4J for logging informational, debug, and error messages.
     * Utilized throughout the class to trace execution flow and record significant events.
     */
    private static final Logger log = LoggerFactory.getLogger(Main.class);
    /**
     * DISALLOWED. STATIC ONLY.
     *
     * <p>
     * Prevents instantiation of the {@code Main} class.
     * </p>
     */
    private Main() {
        throw new UnsupportedOperationException("Main class cannot be instantiated.");
    }

    /**
     * The entry point of the pheromesh application.
     * 
     * <p>
     * Parses command-line arguments to determine the operating mode (p2p or connect), 
     * initializes the P2P network, and sets up the SOCKS proxy accordingly.
     * </p>
     * 
     * <p>
     * <strong>Modes:</strong></p>
     * <ul>
     *   <li><strong>p2p:</strong> Starts the first node (initiator) in the VPN network.</li>
     *   <li><strong>connect:</strong> Connects to an existing VPN network by joining a specified peer.</li>
     * </ul>
     * 
     * 
     * @param args Command-line arguments specifying the mode and associated parameters.
     *             <ul>
     *               <li>For <strong>p2p</strong> mode: <code>p2p [port]</code></li>
     *               <li>For <strong>connect</strong> mode: <code>connect [local-port] [peer-host] [peer-port]</code></li>
     *             </ul>
     */
        public static void main(String[] args) {
        try {
            if (args.length < 2) {
                printUsage();
                return;
            }

            String mode = args[0].toLowerCase();
            int port = Integer.parseInt(args[1]);

            switch (mode) {
                case "p2p" -> {
                    log.info("Starting P2P VPN node on port {}", port);
                    P2PNetwork network = new P2PNetwork(port, true, null);  // true = initiator, don't need peer address since we would be the initator.
                    network.start();
                }
                case "connect" -> {
                    if (args.length < 4) {
                        System.out.println("Error: peer address and port required for connect mode");
                        System.out.println("Usage: java -jar pheromesh.jar connect [local-port] [peer-host] [peer-port]");
                        System.exit(1);
                    }
                    String peerHost = args[2];
                    int peerPort = Integer.parseInt(args[3]);
                    log.info("Connecting to P2P network via {}:{}", peerHost, peerPort);
                    String peerAddress = peerHost + ":" + peerPort;
                    P2PNetwork network = new P2PNetwork(port, false, peerAddress);  // Pass peer address
                    
                    // Start the network and ensure SOCKS proxy is started
                    try {
                        network.start();
                        log.info("P2P network and SOCKS proxy started successfully");
                    } catch (Exception e) {
                        log.error("Failed to start network or SOCKS proxy: {}", e.getMessage());
                        throw e;
                    }
                }
                default -> {
                    System.out.println("Invalid mode. Use 'p2p' or 'connect'");
                    System.exit(1);
                }
            }

            // Keep main thread alive
            Thread.currentThread().join();

        } catch (Exception e) {
            log.error("Fatal error", e);
            System.exit(1);
        }
    }


    /**
     * Prints the usage instructions for the pheromesh application.
     * 
     * <p>
     * Provides guidance on how to execute the program in different modes, along with examples.
     * </p>
     */
    private static void printUsage() {
        System.out.println("Usage: java -jar pheromesh.jar [mode] [options]");
        System.out.println("Modes:");
        System.out.println("  p2p [port]");
        System.out.println("    Start first node (initiator)");
        System.out.println("    - VPN service will listen on [port]");
        System.out.println("    - SOCKS proxy will start on [port+1]");
        System.out.println();
        System.out.println("  connect [local-port] [peer-host] [peer-port]");
        System.out.println("    Connect to existing network");
        System.out.println("    - VPN service will listen on [local-port]");
        System.out.println("    - SOCKS proxy will start on [local-port+1]");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  # Start first node:");
        System.out.println("  java -jar pheromesh.jar p2p 8942");
        System.out.println("  # VPN on 8942, SOCKS proxy on 8943");
        System.out.println();
        System.out.println("  # Connect second node:");
        System.out.println("  java -jar pheromesh.jar connect 8944 localhost 8942");
        System.out.println("  # VPN on 8944, SOCKS proxy on 8945");
    }
}
