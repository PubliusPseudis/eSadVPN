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

/**
 * <p>
 * The {@code ConnectionPhase} enum represents the various stages involved in establishing and maintaining
 * a Virtual Private Network (VPN) connection. Each phase corresponds to a specific step in the VPN connection
 * lifecycle, ensuring a structured and secure connection process.
 * </p>
 *
 * <p>
 * The typical sequence of connection phases is as follows:</p>
 * <ol>
 *   <li>{@link #INITIAL}: The starting phase before any connection attempts are made.</li>
 *   <li>{@link #UDP_VERIFIED}: Verification of UDP (User Datagram Protocol) connectivity.</li>
 *   <li>{@link #SECURE_CHANNEL_ESTABLISHED}: Establishment of a secure communication channel.</li>
 *   <li>{@link #NETWORK_HANDSHAKE_COMPLETE}: Completion of the network handshake, indicating a fully established VPN connection.</li>
 * </ol>
 * 
 *
 * <p>
 * This enumeration is essential for managing the state transitions within the VPN connection process,
 * allowing for appropriate handling and error management at each stage.
 * </p>
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * ConnectionPhase currentPhase = ConnectionPhase.INITIAL;
 * 
 * // Attempt to verify UDP connectivity
 * if (verifyUDP()) {
 *     currentPhase = ConnectionPhase.UDP_VERIFIED;
 * }
 * 
 * // Establish a secure channel
 * if (establishSecureChannel()) {
 *     currentPhase = ConnectionPhase.SECURE_CHANNEL_ESTABLISHED;
 * }
 * 
 * // Complete the network handshake
 * if (completeNetworkHandshake()) {
 *     currentPhase = ConnectionPhase.NETWORK_HANDSHAKE_COMPLETE;
 * }
 * 
 * // Now the VPN connection is fully established
 * }</pre>
 * 
 * @author 
 * Publius Pseudis
 * 
 * @version 1.0
 * @since 2024-01-01
 */
public enum ConnectionPhase {
    
    /**
     * The initial phase of the VPN connection process.
     * <p>
     * In this phase, the VPN client is preparing to establish a connection.
     * No network communication has been attempted yet.
     * </p>
     */
    INITIAL,
    
    /**
     * The phase where UDP connectivity has been verified.
     * <p>
     * During this phase, the VPN client ensures that UDP packets can be sent and received,
     * which is essential for establishing a reliable communication channel.
     * Successful verification indicates that the underlying network supports UDP traffic,
     * which is commonly used for VPN data transmission.
     * </p>
     */
    UDP_VERIFIED,
    
    /**
     * The phase where a secure communication channel has been established.
     * <p>
     * In this phase, cryptographic protocols are used to create a secure tunnel between
     * the VPN client and server. This ensures that all data transmitted is encrypted and
     * protected from eavesdropping or tampering.
     * </p>
     */
    SECURE_CHANNEL_ESTABLISHED,
    
    /**
     * The phase where the network handshake is complete.
     * <p>
     * This final phase signifies that all necessary handshakes and negotiations between
     * the VPN client and server have been successfully completed. The VPN connection
     * is now fully established, allowing for secure and authenticated data exchange.
     * </p>
     */
    NETWORK_HANDSHAKE_COMPLETE;
}
