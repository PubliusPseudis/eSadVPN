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
package org.publiuspseudis.pheromesh.network;

import java.nio.ByteBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code IPPacket} class is responsible for handling IPv4 packet processing within the VPN framework.
 * It provides functionalities to create, serialize, deserialize, and validate IPv4 packets.
 * </p>
 *
 * <p>
 * This class manages the construction and interpretation of IPv4 headers, including fields such as
 * version, header length, type of service, total length, identification, flags, fragment offset,
 * time to live (TTL), protocol, checksum, source IP, and destination IP. Additionally, it supports
 * payload extraction and checksum verification to ensure data integrity.
 * </p>
 *
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Creating a payload
 * ByteBuffer payload = ByteBuffer.wrap(new byte[]{/* payload data * /});
 * 
 * // Defining source and destination IP addresses
 * byte[] sourceIP = {(byte)192, (byte)168, 1, 2};
 * byte[] destIP = {(byte)192, (byte)168, 1, 3};
 * 
 * // Creating an IPPacket instance
 * IPPacket ipPacket = IPPacket.create(IPPacket.PROTO_TCP, sourceIP, destIP, payload);
 * 
 * // Serializing the packet for transmission
 * ByteBuffer serializedPacket = ipPacket.getPacket();
 * 
 * // Deserializing the packet upon reception
 * IPPacket receivedPacket = new IPPacket(serializedPacket);
 * 
 * // Verifying the checksum
 * boolean isValid = receivedPacket.verifyChecksum();
 * 
 * // Accessing payload
 * ByteBuffer receivedPayload = receivedPacket.getPayload();
 * }</pre>
 * 
 * @author
 * Publius Pseudis
 * 
 * @version 1.0
 * @since 2024-01-01
 */
public class IPPacket {
    /**
     * Logger instance for logging information, warnings, and errors.
     */
    private static final Logger log = LoggerFactory.getLogger(IPPacket.class);
    
    // IP header offsets
    /**
     * Offset for the IP version field within the header.
     */
    private static final int VERSION_OFFSET = 0;
    
    /**
     * Offset for the Internet Header Length (IHL) field within the header.
     */
    private static final int IHL_OFFSET = 0;
    
    /**
     * Offset for the Type of Service (ToS) field within the header.
     */
    private static final int TOS_OFFSET = 1;
    
    /**
     * Offset for the Total Length field within the header.
     */
    private static final int TOTAL_LENGTH_OFFSET = 2;
    
    /**
     * Offset for the Identification field within the header.
     */
    private static final int ID_OFFSET = 4;
    
    /**
     * Offset for the Flags field within the header.
     */
    private static final int FLAGS_OFFSET = 6;
    
    /**
     * Offset for the Time To Live (TTL) field within the header.
     */
    private static final int TTL_OFFSET = 8;
    
    /**
     * Offset for the Protocol field within the header.
     */
    private static final int PROTOCOL_OFFSET = 9;
    
    /**
     * Offset for the Header Checksum field within the header.
     */
    private static final int CHECKSUM_OFFSET = 10;
    
    /**
     * Offset for the Source IP Address field within the header.
     */
    private static final int SRC_IP_OFFSET = 12;
    
    /**
     * Offset for the Destination IP Address field within the header.
     */
    private static final int DST_IP_OFFSET = 16;
    
    // IP protocols
    /**
     * Protocol number for Internet Control Message Protocol (ICMP).
     */
    public static final int PROTO_ICMP = 1;
    
    /**
     * Protocol number for Transmission Control Protocol (TCP).
     */
    public static final int PROTO_TCP = 6;
    
    /**
     * Protocol number for User Datagram Protocol (UDP).
     */
    public static final int PROTO_UDP = 17;
    
    /**
     * The {@code ByteBuffer} containing the entire IP packet, including headers and payload.
     */
    private final ByteBuffer packet;
    
    /**
     * The length of the IP header in bytes.
     */
    private final int headerLength;
    
    /**
     * Constructs a new {@code IPPacket} instance by wrapping the provided {@code ByteBuffer}.
     * It calculates the header length based on the Internet Header Length (IHL) field.
     *
     * @param packet The {@code ByteBuffer} containing the IP packet data.
     */
    public IPPacket(ByteBuffer packet) {
        this.packet = packet;
        this.headerLength = (packet.get(IHL_OFFSET) & 0x0F) * 4;
    }
    
    /**
     * Creates a new IP packet with the specified protocol, source IP, destination IP, and payload.
     * It constructs the IPv4 header, appends the payload, and calculates the checksum.
     *
     * @param protocol The protocol number (e.g., {@code PROTO_TCP}, {@code PROTO_UDP}).
     * @param sourceIP A byte array representing the source IP address (4 bytes).
     * @param destIP   A byte array representing the destination IP address (4 bytes).
     * @param payload  A {@code ByteBuffer} containing the payload data.
     * @return A new {@code IPPacket} instance representing the constructed IP packet.
     */
    public static IPPacket create(int protocol, byte[] sourceIP, byte[] destIP, ByteBuffer payload) {
        ByteBuffer packet = ByteBuffer.allocate(20 + payload.remaining());
        
        // Version and IHL
        packet.put((byte) 0x45);  // IPv4, 5 words header
        
        // Type of Service (ToS)
        packet.put((byte) 0);
        
        // Total Length
        packet.putShort((short) (20 + payload.remaining()));
        
        // Identification
        packet.putShort((short) 0);
        
        // Flags and Fragment Offset
        packet.putShort((short) 0x4000);  // Don't fragment
        
        // Time To Live (TTL)
        packet.put((byte) 64);
        
        // Protocol
        packet.put((byte) protocol);
        
        // Header Checksum (initially 0)
        packet.putShort((short) 0);
        
        // Source IP Address
        packet.put(sourceIP);
        
        // Destination IP Address
        packet.put(destIP);
        
        // Payload
        packet.put(payload);
        packet.flip();
        
        // Calculate and update checksum
        updateChecksum(packet);
        
        return new IPPacket(packet);
    }
    
    /**
     * Retrieves the source IP address from the IP packet.
     *
     * @return An integer representing the source IP address.
     */
    public int getSourceIP() {
        return packet.getInt(SRC_IP_OFFSET);
    }
    
    /**
     * Retrieves the destination IP address from the IP packet.
     *
     * @return An integer representing the destination IP address.
     */
    public int getDestinationIP() {
        return packet.getInt(DST_IP_OFFSET);
    }
    
    /**
     * Retrieves the protocol number from the IP packet.
     *
     * @return An integer representing the protocol number.
     */
    public int getProtocol() {
        return packet.get(PROTOCOL_OFFSET) & 0xFF;
    }
    
    /**
     * Retrieves the payload data from the IP packet.
     *
     * @return A {@code ByteBuffer} containing the payload data.
     */
    public ByteBuffer getPayload() {
        ByteBuffer payload = packet.duplicate();
        payload.position(headerLength);
        return payload.slice();
    }
    
    /**
     * Retrieves the entire packet data, including headers and payload.
     *
     * @return A duplicate {@code ByteBuffer} of the entire IP packet.
     */
    public ByteBuffer getPacket() {
        return packet.duplicate();
    }
    
    /**
     * Updates the IP header checksum based on the current state of the packet.
     * This method calculates the checksum by summing all 16-bit words in the header,
     * adding any carry-over bits, and then taking the one's complement of the sum.
     *
     * @param packet The {@code ByteBuffer} containing the IP packet data.
     */
    private static void updateChecksum(ByteBuffer packet) {
        // Clear existing checksum
        packet.putShort(CHECKSUM_OFFSET, (short) 0);
        
        // Calculate checksum
        int sum = 0;
        int position = packet.position();
        packet.position(0);
        
        while (packet.hasRemaining()) {
            if (packet.remaining() >= 2) {
                sum += packet.getShort() & 0xFFFF;
            } else {
                sum += (packet.get() & 0xFF) << 8;
            }
        }
        
        // Add carry bits
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        
        // Store checksum
        packet.putShort(CHECKSUM_OFFSET, (short) ~sum);
        packet.position(position);
    }
    
    /**
     * Verifies the IP header checksum to ensure the integrity of the packet.
     * This method recalculates the checksum and compares it with the original value.
     *
     * @return {@code true} if the checksum is valid; {@code false} otherwise.
     */
    public boolean verifyChecksum() {
        int original = packet.getShort(CHECKSUM_OFFSET) & 0xFFFF;
        
        // Calculate checksum
        packet.putShort(CHECKSUM_OFFSET, (short) 0);
        int sum = 0;
        int position = packet.position();
        packet.position(0);
        
        while (packet.hasRemaining()) {
            if (packet.remaining() >= 2) {
                sum += packet.getShort() & 0xFFFF;
            } else {
                sum += (packet.get() & 0xFF) << 8;
            }
        }
        
        // Restore original checksum and position
        packet.putShort(CHECKSUM_OFFSET, (short) original);
        packet.position(position);
        
        // Add carry bits
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        
        return (short) ~sum == original;
    }
    
    /**
     * Formats an IP address from its integer representation to the standard dotted-decimal notation.
     *
     * @param ip An integer representing the IP address.
     * @return A {@code String} in the format "x.x.x.x" representing the IP address.
     */
    public static String formatIP(int ip) {
        return String.format("%d.%d.%d.%d",
            (ip >> 24) & 0xFF,
            (ip >> 16) & 0xFF,
            (ip >> 8) & 0xFF,
            ip & 0xFF);
    }
    
    /**
     * Provides a string representation of the IP packet, including source and destination IPs,
     * protocol number, and total length.
     *
     * @return A {@code String} describing the IP packet.
     */
    @Override
    public String toString() {
        return String.format("IP[%s -> %s, proto=%d, len=%d]",
            formatIP(getSourceIP()),
            formatIP(getDestinationIP()),
            getProtocol(),
            packet.limit());
    }
}
