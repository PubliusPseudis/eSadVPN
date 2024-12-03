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
package org.publiuspseudis.pheromesh.proxy;

import org.publiuspseudis.pheromesh.network.UDPHandler;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.concurrent.*;
import org.publiuspseudis.pheromesh.core.NetworkStack;
import org.publiuspseudis.pheromesh.network.IPPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code SocksProxy} class implements a SOCKS5 proxy server that facilitates secure and efficient
 * routing of TCP and UDP traffic through the peer-to-peer (P2P) VPN network. It listens for incoming
 * SOCKS5 client connections, handles the SOCKS5 handshake and connection requests, and manages the
 * forwarding of traffic between clients and destination servers.
 * </p>
 * 
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Listening for and accepting incoming SOCKS5 client connections.</li>
 *   <li>Performing the SOCKS5 handshake and authenticating clients.</li>
 *   <li>Handling TCP connection requests to target servers.</li>
 *   <li>Managing UDP traffic through the VPN network via the {@link UDPHandler}.</li>
 *   <li>Ensuring concurrent handling of multiple client connections using thread pools.</li>
 *   <li>Gracefully shutting down the proxy server and releasing resources.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Initialize UDPHandler instance
 * UDPHandler udpHandler = new UDPHandler();
 * 
 * // Start the SOCKS proxy on port 1080
 * try (SocksProxy proxy = new SocksProxy(udpHandler, 1080)) {
 *     // The proxy runs and handles client connections
 *     // Add additional logic or monitoring as needed
 * } catch (IOException e) {
 *     e.printStackTrace();
 * }
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>
 * </p>
 * <p>
 * The {@code SocksProxy} class is designed to handle multiple client connections concurrently. It uses
 * an {@link ExecutorService} to manage a pool of threads, ensuring that each client connection is handled
 * in a separate thread. The class maintains thread safety by ensuring that shared resources are
 * appropriately synchronized or are thread-safe by design.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>{@link UDPHandler}: Manages UDP traffic routing through the VPN network.</li>
 *   <li>SLF4J Logging Framework: Used for logging informational, debug, and error messages.</li>
 * </ul>
 * 
 * @author
 * Publius Pseudis
 */
public class SocksProxy implements AutoCloseable {
    /**
     * Logger instance for logging informational, debug, and error messages.
     */
    private static final Logger log = LoggerFactory.getLogger(SocksProxy.class);
    
    /**
     * The server socket that listens for incoming SOCKS5 client connections.
     */
    private final ServerSocket serverSocket;

    
    /**
     * Executor service for handling client connections concurrently using a cached thread pool.
     */
    private final ExecutorService executor;
    
    /**
     * A flag indicating whether the SOCKS proxy server is currently running.
     */
    private volatile boolean running;
    
    
    private final NetworkStack networkStack;  // Added NetworkStack reference    
    
    // SOCKS protocol constants
    
    /**
     * SOCKS protocol version (0x05 for SOCKS5).
     */
    private static final byte SOCKS_VERSION = 0x05;
    
    /**
     * Authentication method identifier for "No Authentication" (0x00).
     */
    private static final byte AUTH_METHOD_NONE = 0x00;
    
    /**
     * Command identifier for "Connect" (0x01).
     */
    private static final byte CMD_CONNECT = 0x01;
    
    /**
     * Address type identifier for IPv4 addresses (0x01).
     */
    private static final byte ADDR_TYPE_IPV4 = 0x01;
    
    /**
     * Address type identifier for domain names (0x03).
     */
    private static final byte ADDR_TYPE_DOMAIN = 0x03;
    
    /**
     * Constructs a new {@code SocksProxy} instance, initializes the server socket on the specified port,
     * and starts the client acceptance loop.
     *
     * @param networkStack The {@link NetworkStack} instance for managing network traffic through the VPN.
     * @param port       The port number on which the SOCKS proxy will listen for incoming connections.
     * @throws IOException If an I/O error occurs when opening the server socket.
     */
    public SocksProxy(NetworkStack networkStack, int port) throws IOException {
        this.networkStack = networkStack;
        this.serverSocket = new ServerSocket(port);
        this.executor = Executors.newCachedThreadPool();
        this.running = true;
        
        log.info("SOCKS proxy listening on port {}", port);
        startAcceptLoop();
    }
    
    /**
     * Starts the loop that continuously accepts incoming client connections and delegates them
     * to the executor service for handling.
     */
    private void startAcceptLoop() {
        executor.submit(() -> {
            while (running) {
                try {
                    Socket client = serverSocket.accept();
                    executor.submit(() -> handleClient(client));
                } catch (IOException e) {
                    if (running) {
                        log.error("Error accepting client: {}", e.getMessage());
                    }
                }
            }
        });
    }
    
    /**
     * Handles an individual SOCKS5 client connection by performing the handshake, processing
     * the connection request, and managing the forwarding of traffic.
     *
     * @param client The {@link Socket} representing the connected SOCKS5 client.
     */
    private void handleClient(Socket client) {
       try {
           InputStream in = client.getInputStream();
           OutputStream out = client.getOutputStream();

           // Handle SOCKS5 handshake
           if (!handleHandshake(in, out)) {
               log.error("SOCKS5 handshake failed");
               return;
           }

           // Read connection request
           byte[] requestHeader = new byte[4];
           if (in.read(requestHeader) != 4) {
               log.error("Failed to read SOCKS5 request header");
               sendError(out, (byte) 0x01);
               return;
           }

           if (requestHeader[0] != SOCKS_VERSION || requestHeader[1] != CMD_CONNECT) {
               log.error("Invalid SOCKS5 request or unsupported command");
               sendError(out, (byte) 0x07);
               return;
           }

           // Parse destination address
           byte addrType = requestHeader[3];
           String destAddr;
           int destPort;

           try {
               switch (addrType) {
                   case ADDR_TYPE_IPV4 -> {
                       byte[] addr = new byte[4];
                       if (in.read(addr) != 4) throw new IOException("Failed to read IPv4 address");
                       destAddr = InetAddress.getByAddress(addr).getHostAddress();
                   }
                   case ADDR_TYPE_DOMAIN -> {
                       int len = in.read();
                       if (len <= 0) throw new IOException("Invalid domain name length");
                       byte[] domain = new byte[len];
                       if (in.read(domain) != len) throw new IOException("Failed to read domain name");
                       destAddr = new String(domain);
                   }
                   default -> {
                       log.error("Unsupported address type: {}", addrType);
                       sendError(out, (byte) 0x08);
                       return;
                   }
               }

               byte[] portBytes = new byte[2];
               if (in.read(portBytes) != 2) throw new IOException("Failed to read port");
               destPort = ((portBytes[0] & 0xFF) << 8) | (portBytes[1] & 0xFF);

               log.info("SOCKS5 connection request to {}:{}", destAddr, destPort);

               // Connect to destination
               Socket target = new Socket(destAddr, destPort);
               target.setKeepAlive(true);
               target.setTcpNoDelay(true);

               // Send success response
               byte[] response = {
                   SOCKS_VERSION,
                   0x00, // Success
                   0x00, // Reserved
                   ADDR_TYPE_IPV4,
                   0, 0, 0, 0, // Bind address (0.0.0.0)
                   0, 0       // Bind port
               };
               out.write(response);
               out.flush();

               log.info("Established connection from {}:{} to {}:{}",
                   client.getInetAddress().getHostAddress(),
                   client.getPort(),
                   destAddr,
                   destPort);

               // Start forwarding data
               forwardTraffic(client, destAddr,destPort);

           } catch (IOException e) {
               log.error("Error handling SOCKS5 connection: {}", e.getMessage());
               sendError(out, (byte) 0x04);
           }

       } catch (IOException e) {
           log.error("Error handling client: {}", e.getMessage());
       } finally {
           try {
               client.close();
           } catch (IOException e) {
               log.debug("Error closing client socket: {}", e.getMessage());
           }
       }
   }
    
    /**
     * Handles the SOCKS5 handshake by negotiating the authentication method with the client.
     *
     * @param in  The {@link InputStream} from the client.
     * @param out The {@link OutputStream} to the client.
     * @return {@code true} if the handshake was successful and "No Authentication" was selected; {@code false} otherwise.
     * @throws IOException If an I/O error occurs during the handshake.
     */
    private boolean handleHandshake(InputStream in, OutputStream out) throws IOException {
        // Read SOCKS version
        int version = in.read();
        if (version != SOCKS_VERSION) {
            log.warn("Unsupported SOCKS version: {}", version);
            return false;
        }
        
        // Read number of authentication methods
        int methodCount = in.read();
        if (methodCount <= 0) {
            log.warn("No authentication methods provided by client.");
            return false;
        }
        
        // Read authentication methods
        byte[] methods = new byte[methodCount];
        if (in.read(methods) != methodCount) {
            log.warn("Failed to read authentication methods.");
            return false;
        }
        
        // Check if "No Authentication" is supported
        boolean noAuthSupported = false;
        for (byte method : methods) {
            if (method == AUTH_METHOD_NONE) {
                noAuthSupported = true;
                break;
            }
        }
        
        if (!noAuthSupported) {
            // No acceptable authentication methods
            out.write(new byte[]{SOCKS_VERSION, (byte) 0xFF});
            log.warn("Client does not support 'No Authentication' method.");
            return false;
        }
        
        // Respond with "No Authentication" selected
        out.write(new byte[]{SOCKS_VERSION, AUTH_METHOD_NONE});
        return true;
    }
    
    /**
     * Sends an error response to the client with the specified error code.
     *
     * @param out   The {@link OutputStream} to the client.
     * @param error The error code to send, as defined by the SOCKS5 protocol.
     * @throws IOException If an I/O error occurs while sending the error response.
     */
    private void sendError(OutputStream out, byte error) throws IOException {
        byte[] response = {
            SOCKS_VERSION,
            error,
            0x00, // Reserved
            ADDR_TYPE_IPV4,
            0, 0, 0, 0, // Bind address (0.0.0.0)
            0, 0       // Bind port
        };
        out.write(response);
    }
    
    /**
     * Forwards traffic between two sockets by continuously reading from the input socket and writing to the output socket.
     *
     * @param client  The {@link Socket} to read data from.
     * @param destAddr The address {@link String} to send data to.
     * @param destPort The {@int Port} to send the data to
     */
private void forwardTraffic(Socket client, String destAddr, int destPort) {
    log.debug("Starting traffic forwarding through VPN to {}:{}", destAddr, destPort);

    // Create queues for response handling
    BlockingQueue<ByteBuffer> responseQueue = new LinkedBlockingQueue<>();
    
    // Register response handler with NetworkStack
    UDPHandler.PacketHandler responseHandler = (payload, sourceIP, sourcePort) -> {
        try {
            // Skip port headers in payload (4 bytes)
            payload.position(4);
            ByteBuffer data = ByteBuffer.allocate(payload.remaining());
            data.put(payload);
            data.flip();
            responseQueue.put(data);
        } catch (InterruptedException e) {
            log.warn("Response handler interrupted");
            Thread.currentThread().interrupt();
        }
    };

    // Bind to client's local port to receive responses
    networkStack.getUDPHandler().bind(client.getLocalPort(), responseHandler);

    Thread clientToTarget = new Thread(() -> {
        try {
            InputStream in = client.getInputStream();
            byte[] buffer = new byte[8192];
            int bytesRead;

            while ((bytesRead = in.read(buffer)) != -1) {
                log.debug("Client -> Target: {} bytes", bytesRead);
                
                // Resolve domain name to IP if needed
                InetAddress destAddress;
                try {
                    // Try parsing as IP first
                    String[] parts = destAddr.split("\\.");
                    if (parts.length == 4) {
                        byte[] addr = new byte[4];
                        for (int i = 0; i < 4; i++) {
                            addr[i] = (byte)Integer.parseInt(parts[i]);
                        }
                        destAddress = InetAddress.getByAddress(addr);
                    } else {
                        // If not IP format, resolve domain name
                        destAddress = InetAddress.getByName(destAddr);
                    }
                } catch (NumberFormatException | UnknownHostException e) {
                    log.error("Failed to resolve address {}: {}", destAddr, e.getMessage());
                    return;
                }
                
                // Convert IP to int for NetworkStack
                byte[] addr = destAddress.getAddress();
                int destIP = ((addr[0] & 0xFF) << 24) | 
                           ((addr[1] & 0xFF) << 16) | 
                           ((addr[2] & 0xFF) << 8) | 
                           (addr[3] & 0xFF);

                // Create UDP packet with ports and data
                ByteBuffer packet = ByteBuffer.allocate(bytesRead + 4);
                packet.putShort((short)client.getLocalPort());  // Source port
                packet.putShort((short)destPort);              // Destination port
                packet.put(buffer, 0, bytesRead);              // Data
                packet.flip();

                // Forward through NetworkStack
                networkStack.sendPacket(IPPacket.PROTO_UDP, destIP, packet);
            }
        } catch (IOException e) {
            log.debug("Client -> Target stream closed: {}", e.getMessage());
        } finally {
            // Remove UDP handler when done
            networkStack.getUDPHandler().unbind(client.getLocalPort());
        }
    });

    Thread targetToClient = new Thread(() -> {
        try {
            OutputStream out = client.getOutputStream();

            while (!Thread.currentThread().isInterrupted()) {
                try {
                    // Wait for response with timeout
                    ByteBuffer response = responseQueue.poll(5, TimeUnit.SECONDS);
                    if (response != null) {
                        byte[] data = new byte[response.remaining()];
                        response.get(data);
                        log.debug("Target -> Client: {} bytes", data.length);
                        out.write(data);
                        out.flush();
                    }
                } catch (InterruptedException e) {
                    log.debug("Response wait interrupted");
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        } catch (IOException e) {
            log.debug("Target -> Client stream closed: {}", e.getMessage());
        }
    });

    // Set threads as daemon to ensure they don't prevent JVM shutdown
    clientToTarget.setDaemon(true);
    targetToClient.setDaemon(true);

    // Start both threads
    clientToTarget.start();
    targetToClient.start();

    // Monitor threads and cleanup on exit
    try {
        clientToTarget.join();
        // Interrupt response handler thread since client is done sending
        targetToClient.interrupt();
        targetToClient.join(1000); // Wait up to 1 second for cleanup
    } catch (InterruptedException e) {
        log.warn("Thread monitoring interrupted");
        Thread.currentThread().interrupt();
    } finally {
        // Cleanup
        networkStack.getUDPHandler().unbind(client.getLocalPort());
        try {
            if (!client.isClosed()) {
                client.close();
            }
        } catch (IOException e) {
            log.debug("Error closing client socket: {}", e.getMessage());
        }
    }
}
    private int ipToInt(String ipAddress) {
        String[] parts = ipAddress.split("\\.");
        int result = 0;
        for (int i = 0; i < 4; i++) {
            result = (result << 8) | Integer.parseInt(parts[i]);
        }
        return result;
    }
    /**
     * Closes the SOCKS proxy server by stopping the acceptance loop, closing the server socket,
     * shutting down the executor service, and releasing all associated resources.
     */
    @Override
    public void close() {
        running = false;
        try {
            serverSocket.close();
        } catch (IOException ignored) {}
        executor.shutdownNow();
        log.info("SOCKS proxy has been shut down.");
    }
}
