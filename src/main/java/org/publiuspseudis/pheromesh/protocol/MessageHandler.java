package org.publiuspseudis.pheromesh.protocol;


import org.publiuspseudis.pheromesh.protocol.GossipMessage;

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


/**
 * <p>
 * The {@code MessageHandler} interface defines a generic handler for asynchronous message processing
 * within the VPN framework. Implementations of this interface are responsible for handling various
 * types of messages, including gossip messages, proofs of work, and peer information updates.
 * </p>
 *
 * <p>
 * This interface facilitates the decoupling of message reception from message processing,
 * allowing for flexible and scalable handling of network communication events. By implementing
 * this interface, developers can define custom behaviors for different message types, enhancing
 * the responsiveness and adaptability of the VPN application.
 * </p>
 *
 * <p>
 * <strong>Example Implementation:</strong>
 * </p>
 * <pre>{@code
 * public class MyMessageHandler implements MessageHandler {
 *     
 *     @Override
 *     public void handleGossip(GossipMessage message) {
 *         // Process the received gossip message
 *         System.out.println("Received gossip message: " + message);
 *         // Additional processing logic...
 *     }
 * 
 *     @Override
 *     public void handleProof(byte[] proof, long timestamp) {
 *         // Validate and process the proof of work
 *         System.out.println("Received proof of work at timestamp: " + timestamp);
 *         // Additional validation and processing logic...
 *     }
 * 
 *     @Override
 *     public void handlePeerInfo(byte[] nodeId) {
 *         // Update peer information based on the received node ID
 *         System.out.println("Received peer info for node ID: " + Arrays.toString(nodeId));
 *         // Additional update logic...
 *     }
 * }
 * }</pre>
 * 
 * <p>
 * <strong>Usage:</strong>
 * </p>
 * <pre>{@code
 * // Instantiate the message handler
 * MessageHandler handler = new MyMessageHandler();
 * 
 * // Create a gossip message (assuming GossipMessage is properly defined)
 * GossipMessage gossip = new GossipMessage(/* parameters *);
 * 
 * // Handle the gossip message
 * handler.handleGossip(gossip);
 * 
 * // Handle a proof of work
 * byte[] proof = {/* proof data *};
 * long timestamp = System.currentTimeMillis();
 * handler.handleProof(proof, timestamp);
 * 
 * // Handle peer information
 * byte[] nodeId = {/* node ID data *};
 * handler.handlePeerInfo(nodeId);
 * }</pre>
 * 
 * @author
 * Publius Pseudis
 * 
 * @version 1.0
 * @since 2024-01-01
 */
public interface MessageHandler {
    
    /**
     * Handles a received gossip message, processing peer and routing information.
     *
     * @param message The {@link GossipMessage} instance containing gossip data.
     */
    void handleGossip(GossipMessage message);
    
    /**
     * Handles a received proof of work, validating the authenticity of a node.
     *
     * @param proof     A byte array representing the proof of work.
     * @param timestamp The timestamp indicating when the proof was generated.
     */
    void handleProof(byte[] proof, long timestamp);
    
    /**
     * Handles received peer information, updating the network state with the new peer.
     *
     * @param nodeId A byte array representing the unique identifier of the peer.
     */
    void handlePeerInfo(byte[] nodeId);
}
