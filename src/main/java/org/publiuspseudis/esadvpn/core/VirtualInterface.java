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

import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code VirtualInterface} class represents a virtual network interface that operates entirely in userspace.
 * It manages the sending and receiving of network packets through designated ingress and egress queues,
 * utilizing a pool of pre-allocated buffers to optimize performance and resource usage.
 * </p>
 * 
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Efficient management of network buffers to handle high-throughput packet processing.</li>
 *   <li>Thread-safe operations for sending and receiving packets without data races.</li>
 *   <li>Integration with network stacks through packet injection and retrieval mechanisms.</li>
 *   <li>Monitoring and control of the interface's operational state.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Initialize the virtual interface with an IP address and MTU
 * VirtualInterface vInterface = new VirtualInterface("192.168.1.100", 1500);
 * 
 * // Create a packet to send
 * ByteBuffer packet = ByteBuffer.allocateDirect(1500);
 * packet.put("Hello, Virtual Network!".getBytes());
 * packet.flip();
 * 
 * // Write the packet to the virtual interface
 * vInterface.write(packet);
 * 
 * // Read a packet from the virtual interface
 * ByteBuffer receivedPacket = vInterface.read();
 * if (receivedPacket != null) {
 *     byte[] data = new byte[receivedPacket.remaining()];
 *     receivedPacket.get(data);
 *     System.out.println("Received: " + new String(data));
 * }
 * 
 * // Inject a packet into the network stack
 * ByteBuffer injectPacket = ByteBuffer.allocateDirect(1500);
 * injectPacket.put("Injected Packet".getBytes());
 * injectPacket.flip();
 * vInterface.injectPacket(injectPacket);
 * 
 * // Close the virtual interface when done
 * vInterface.close();
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>
 * </p>
 * <p>
 * The {@code VirtualInterface} class is designed to be thread-safe. It utilizes concurrent data structures
 * such as {@code ConcurrentHashMap} and {@code LinkedBlockingQueue} to manage buffers and packet queues.
 * Additionally, atomic variables like {@code AtomicBoolean} ensure that the interface's running state
 * is consistently maintained across multiple threads.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>SLF4J Logging Framework: Used for logging informational, debug, and error messages.</li>
 * </ul>
 * 
 * @author 
 * Publius Pseudis
 */
public class VirtualInterface implements AutoCloseable {
    
    /**
     * Logger instance from SLF4J for logging informational, debug, and error messages.
     * Utilized throughout the class to trace execution flow and record significant events.
     */
    private static final Logger log = LoggerFactory.getLogger(VirtualInterface.class);
    
    /**
     * A thread-safe set containing buffers that are currently in use.
     * Utilizes a concurrent hash map to allow safe access across multiple threads.
     */
    private final Set<ByteBuffer> inUseBuffers = Collections.newSetFromMap(new ConcurrentHashMap<>());
    
    /**
     * The IP address assigned to this virtual interface.
     * Represented as a {@code String} in standard dotted-decimal notation.
     */
    private final String address;
    
    /**
     * The Maximum Transmission Unit (MTU) size for this virtual interface.
     * Determines the largest packet size that can be transmitted without fragmentation.
     */
    private final int mtu;
    
    /**
     * Queue for incoming packets destined for this virtual interface.
     * Utilizes a blocking queue to handle packet ingress in a thread-safe manner.
     */
    private final BlockingQueue<ByteBuffer> ingressQueue;
    
    /**
     * Queue for outgoing packets originating from this virtual interface.
     * Utilizes a blocking queue to handle packet egress in a thread-safe manner.
     */
    private final BlockingQueue<ByteBuffer> egressQueue;
    
    /**
     * Atomic boolean flag indicating whether the virtual interface is currently running.
     * Ensures visibility and atomicity across multiple threads.
     */
    private final AtomicBoolean running;
    
    /**
     * Array representing the pool of pre-allocated direct byte buffers.
     * Each buffer is sized according to the MTU and is reused to minimize memory allocations.
     */
    private final ByteBuffer[] bufferPool;
    
    /**
     * The total number of buffers in the buffer pool.
     * Determines the maximum number of packets that can be handled concurrently.
     */
    private static final int BUFFER_POOL_SIZE = 1024;
    
    /**
     * Constructs a new {@code VirtualInterface} with the specified IP address and MTU.
     * 
     * <p>
     * Initializes the ingress and egress queues, sets the running flag to {@code true},
     * and pre-allocates a pool of direct byte buffers for efficient packet handling.
     * </p>
     * 
     * @param address The IP address to assign to this virtual interface.
     * @param mtu The Maximum Transmission Unit size for this interface.
     */
    public VirtualInterface(String address, int mtu) {
        this.address = address;
        this.mtu = mtu;
        this.ingressQueue = new LinkedBlockingQueue<>();
        this.egressQueue = new LinkedBlockingQueue<>();
        this.running = new AtomicBoolean(true);
        
        // Pre-allocate buffer pool
        this.bufferPool = new ByteBuffer[BUFFER_POOL_SIZE];
        for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
            this.bufferPool[i] = ByteBuffer.allocateDirect(mtu);
        }
    }
    
    /**
     * Writes a packet to the virtual interface's ingress queue.
     * 
     * <p>
     * Attempts to retrieve a buffer from the pool, copies the packet data into it,
     * and enqueues it for processing. If the buffer pool is exhausted, the packet is dropped
     * and a warning is logged.
     * </p>
     * 
     * @param packet The {@link ByteBuffer} containing the packet data to be written.
     */
    public void write(ByteBuffer packet) throws InterruptedException {
        if (!running.get() || packet == null || !packet.hasRemaining()) {
            return;
        }

        // Try to write to the egress queue with a timeout
        if (!egressQueue.offer(packet, 100, TimeUnit.MILLISECONDS)) {
            log.warn("Write operation timed out after 100ms");
        }
    }

    /**
     * Reads a packet from the virtual interface's egress queue.
     * 
     * <p>
     * Retrieves and returns a packet from the egress queue if available. If no packet is present,
     * returns {@code null}.
     * </p>
     * 
     * @return A {@link ByteBuffer} containing the packet data, or {@code null} if no packet is available.
     * @throws java.lang.InterruptedException
     */
    public ByteBuffer read() throws InterruptedException {
        if (!running.get()) {
            return null;
        }

        // Try to read from the ingress queue with a timeout
        ByteBuffer buffer = ingressQueue.poll(100, TimeUnit.MILLISECONDS);
        if (buffer != null && buffer.hasRemaining()) {
            return buffer;
        }
        return null;
    }

    /**
     * Injects a packet into the network stack for processing.
     * 
     * <p>
     * Allocates a buffer from the pool, copies the packet data into it, and enqueues it for network processing.
     * If buffer allocation fails, the packet is silently dropped.
     * </p>
     * 
     * @param packet The {@link ByteBuffer} containing the packet data to be injected.
     */
    public void injectPacket(ByteBuffer packet) {
        if (!running.get() || packet == null || !packet.hasRemaining()) {
            return;
        }

        try {
            ByteBuffer buffer = getBuffer();
            if (buffer == null) {
                return;
            }

            buffer.clear();
            buffer.put(packet);
            buffer.flip();

            egressQueue.offer(buffer);
        } catch (Exception e) {
            log.error("Failed to inject packet: {}", e.getMessage());
        }
    }

    /**
     * Retrieves an available buffer from the buffer pool.
     * 
     * <p>
     * Iterates through the buffer pool and returns the first buffer that is not currently in use.
     * Marks the buffer as in use by adding it to the {@code inUseBuffers} set.
     * </p>
     * 
     * @return A {@link ByteBuffer} from the pool if available, or {@code null} if all buffers are in use.
     */
    private ByteBuffer getBuffer() {
        for (ByteBuffer buffer : bufferPool) {
            if (buffer != null && !inUseBuffers.contains(buffer)) {
                inUseBuffers.add(buffer);
                return buffer;
            }
        }
        return null;
    }

    /**
     * Releases a buffer back to the buffer pool.
     * 
     * <p>
     * Clears the buffer and removes it from the {@code inUseBuffers} set, making it available for reuse.
     * </p>
     * 
     * @param buffer The {@link ByteBuffer} to be released.
     */
    public void releaseBuffer(ByteBuffer buffer) {
        if (buffer != null) {
            buffer.clear();
            inUseBuffers.remove(buffer);
        }
    }

    /**
     * Retrieves the IP address assigned to this virtual interface.
     * 
     * @return A {@code String} representing the IP address.
     */
    public String getAddress() {
        return address;
    }

    /**
     * Retrieves the Maximum Transmission Unit (MTU) size for this virtual interface.
     * 
     * @return An {@code int} representing the MTU size in bytes.
     */
    public int getMTU() {
        return mtu;
    }

    /**
     * Checks whether the virtual interface is currently running.
     * 
     * @return {@code true} if the interface is running; {@code false} otherwise.
     */
    public boolean isRunning() {
        return running.get();
    }

    /**
     * Closes the virtual interface, terminating all ongoing operations and releasing resources.
     * 
     * <p>
     * Sets the running flag to {@code false}, clears both ingress and egress queues,
     * and effectively stops the interface from processing any further packets.
     * </p>
     */
    @Override
    public void close() {
        running.set(false);
        ingressQueue.clear();
        egressQueue.clear();
    }
}
