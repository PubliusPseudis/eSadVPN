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


import java.io.IOException;
import org.publiuspseudis.pheromesh.core.ConnectionPhase;

/**
 * <p>
 * The {@code NetworkProtocolHandler} interface defines a contract for handling network protocol messages
 * within the VPN framework. Implementations of this interface are responsible for processing incoming
 * messages, sending outgoing messages, and managing the current connection phase.
 * </p>
 *
 * <p>
 * This interface facilitates asynchronous and synchronous communication between different components
 * of the VPN application, ensuring that messages are correctly interpreted and dispatched based on their
 * type and content. By implementing this interface, developers can define custom behaviors for various
 * network protocols, enhancing the flexibility and scalability of the VPN system.
 * </p>
 *
 * <p>
 * <strong>Example Implementation:</strong>
 * </p>
 * <pre>{@code
 * public class MyNetworkProtocolHandler implements NetworkProtocolHandler {
 *     
 *     private ConnectionPhase currentPhase;
 *     
 *     @Override
 *     public void handleMessage(byte type, byte[] data) throws IOException {
 *         switch (type) {
 *             case MESSAGE_TYPE_GOSSIP:
 *                 // Process gossip message
 *                 GossipMessage gossip = GossipMessage.deserialize(data);
 *                 processGossip(gossip);
 *                 break;
 *             
 *             case MESSAGE_TYPE_PROOF:
 *                 // Process proof of work
 *                 byte[] proof = extractProof(data);
 *                 long timestamp = extractTimestamp(data);
 *                 verifyProof(proof, timestamp);
 *                 break;
 *             
 *             case MESSAGE_TYPE_PEER_INFO:
 *                 // Process peer information
 *                 byte[] nodeId = extractNodeId(data);
 *                 updatePeerInfo(nodeId);
 *                 break;
 *             
 *             default:
 *                 // Handle unknown message type
 *                 log.warn("Received unknown message type: {}", type);
 *         }
 *     }
 *     
 *     @Override
 *     public void sendMessage(byte type, byte[] data) throws IOException {
 *         // Serialize and send the message over the network
 *         byte[] serializedMessage = serializeMessage(type, data);
 *         networkConnection.send(serializedMessage);
 *     }
 *     
 *     @Override
 *     public ConnectionPhase getPhase() {
 *         return currentPhase;
 *     }
 *     
 *     // Additional helper methods...
 * }
 * }</pre>
 * 
 * <p>
 * <strong>Usage:</strong>
 * </p>
 * <pre>{@code
 * // Instantiate the network protocol handler
 * NetworkProtocolHandler protocolHandler = new MyNetworkProtocolHandler();
 * 
 * // Handling an incoming message
 * byte incomingType = receivedData[0];
 * byte[] incomingData = Arrays.copyOfRange(receivedData, 1, receivedData.length);
 * protocolHandler.handleMessage(incomingType, incomingData);
 * 
 * // Sending a message
 * byte messageType = NetworkProtocolHandler.MESSAGE_TYPE_GOSSIP;
 * byte[] messageData = GossipMessage.createGossipData();
 * protocolHandler.sendMessage(messageType, messageData);
 * 
 * // Retrieving the current connection phase
 * ConnectionPhase phase = protocolHandler.getPhase();
 * }</pre>
 * 
 * @author
 * Publius Pseudis
 * 
 * @version 1.0
 * @since 2024-01-01
 */
public interface NetworkProtocolHandler {
    
    /**
     * Handles an incoming network protocol message based on its type and data.
     *
     * <p>
     * This method is invoked when a new message is received from the network. Implementations should
     * parse the message based on its type and perform the necessary actions, such as updating internal
     * state, responding to requests, or triggering other processes within the VPN framework.
     * </p>
     *
     * @param type The type identifier of the incoming message. This could correspond to different
     *             protocols or message categories within the VPN system.
     * @param data The raw data payload of the message as a byte array. The structure of this data
     *             depends on the message type and should be parsed accordingly.
     * @throws IOException If an I/O error occurs during message processing, such as issues with
     *                     deserialization or network communication.
     *
     * @see #sendMessage(byte, byte[])
     */
    void handleMessage(byte type, byte[] data) throws IOException;
    
    /**
     * Sends a network protocol message with the specified type and data.
     *
     * <p>
     * This method is used to transmit messages to other peers or components within the VPN framework.
     * Implementations should serialize the data appropriately and ensure that it is sent over the
     * correct communication channel or protocol.
     * </p>
     *
     * @param type The type identifier of the message to be sent. This could correspond to different
     *             protocols or message categories within the VPN system.
     * @param data The raw data payload of the message as a byte array. The structure of this data
     *             depends on the message type and should be serialized accordingly.
     * @throws IOException If an I/O error occurs during message transmission, such as issues with
     *                     serialization or network communication.
     *
     * @see #handleMessage(byte, byte[])
     */
    void sendMessage(byte type, byte[] data) throws IOException;
    
    /**
     * Retrieves the current phase of the network connection.
     *
     * <p>
     * The connection phase indicates the current state of the network protocol handler, such as
     * whether the connection is initializing, established, or terminating. This information can be
     * used to make decisions about sending or processing messages based on the connection state.
     * </p>
     *
     * @return The current {@link ConnectionPhase} of the network connection.
     *
     * @see ConnectionPhase
     */
    ConnectionPhase getPhase();
}
