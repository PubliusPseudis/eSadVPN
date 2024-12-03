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
package org.publiuspseudis.pheromesh.crypto;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.publiuspseudis.pheromesh.routing.RouteInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code SecureChannel} class implements the {@link SecureChannelHandler} interface to manage
 * secure, encrypted communication channels between peers within the peer-to-peer (P2P) VPN network.
 * It leverages Elliptic Curve Diffie-Hellman (ECDH) for key agreement and Advanced Encryption
 * Standard (AES) in Galois/Counter Mode (GCM) for encrypting and decrypting messages.
 * </p>
 * 
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Generating an elliptic curve (EC) key pair for secure key exchange.</li>
 *   <li>Establishing a shared secret using ECDH key agreement with a peer's public key.</li>
 *   <li>Encrypting plaintext messages using AES-GCM for confidentiality and integrity.</li>
 *   <li>Decrypting ciphertext messages using the established shared secret.</li>
 *   <li>Managing the state of the secure channel to determine if encryption/decryption is possible.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * try {
 *     // Initialize SecureChannel
 *     SecureChannel secureChannel = new SecureChannel();
 *     
 *     // Retrieve and share public key with peer
 *     byte[] localPublicKey = secureChannel.getPublicKey();
 *     // Send localPublicKey to peer through a secure out-of-band channel
 *     
 *     // Assume peerPublicKey is received from the peer
 *     byte[] peerPublicKey = ...;
 *     
 *     // Establish secure channel with peer
 *     secureChannel.establishSecureChannel(peerPublicKey);
 *     
 *     if (secureChannel.isEstablished()) {
 *         // Encrypt a message to send to the peer
 *         String message = "Hello, secure peer!";
 *         byte[] encryptedMessage = secureChannel.encryptMessage(message.getBytes(StandardCharsets.UTF_8));
 *         
 *         // Send encryptedMessage to peer
 *         
 *         // Receive encrypted response from peer
 *         byte[] receivedEncryptedResponse = ...;
 *         byte[] decryptedResponse = secureChannel.decryptMessage(receivedEncryptedResponse);
 *         
 *         String response = new String(decryptedResponse, StandardCharsets.UTF_8);
 *         System.out.println("Decrypted response: " + response);
 *     }
 * } catch (Exception e) {
 *     e.printStackTrace();
 * }
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>
 * </p>
 * <p>
 * The {@code SecureChannel} class is designed to be thread-safe. The fields `sharedSecret` and `established`
 * are marked as `volatile` to ensure visibility across threads. The class does not expose mutable internal
 * state that could be altered concurrently, and cryptographic operations are performed in a thread-safe
 * manner provided by the underlying Java Cryptography Architecture (JCA).
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>Java Cryptography Architecture (JCA): Utilized for cryptographic operations such as key generation,
 *       key agreement, encryption, and decryption.</li>
 *   <li>SLF4J Logging Framework: Employed for logging informational, debug, and error messages.</li>
 * </ul>
 * 
 * @author 
 * Publius Pseudis
 */
public class SecureChannel implements SecureChannelHandler {
    /**
     * Logger instance for logging debug and informational messages.
     */
    private static final Logger log = LoggerFactory.getLogger(RouteInfo.class);
    /**
     * The transformation string specifying the encryption algorithm, mode, and padding scheme.
     * Uses AES encryption in Galois/Counter Mode (GCM) with no padding.
     */
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    
    private final boolean isServer;
     private volatile byte[] localNonce;
    
    private static final byte[] CONTEXT = "channel_key_v1".getBytes(StandardCharsets.UTF_8);
    /**
    * The offset position in the public key byte array where the nonce is stored.
    * This value is based on the typical length of an EC public key in X.509 format.
    */
    private static final int NONCE_OFFSET = 91;  // Offset where nonce is stored in public key
       private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;  // GCM authentication tag length in bits
    /**
     * The elliptic curve (EC) key pair used for ECDH key agreement. Contains both the public and private keys.
     */
    private final KeyPair keyPair;
    
    /**
     * The shared secret derived from ECDH key agreement with a peer. Used as the symmetric key for AES encryption.
     */
    private volatile SecretKey sharedSecret;
    
    /**
     * A secure random number generator instance used for generating initialization vectors (IVs) for AES-GCM.
     */
    private final SecureRandom random;
    
    /**
     * A flag indicating whether the secure channel has been successfully established.
     * Once set to {@code true}, the channel is ready for encrypting and decrypting messages.
     */
    private volatile boolean established = false;

    /**
     * The session identifier used as additional authenticated data (AAD) in the encryption process.
     * This helps prevent message replay attacks between different sessions.
     */    
    private volatile byte[] sessionId;

    /**
     * Timestamp of the last key rotation (rekeying) operation.
     * Used to determine when the next rekey should occur.
     */
    private volatile long lastRekeyed;

    /**
     * The interval between key rotation operations, set to 1 hour.
     * Regular key rotation helps maintain forward secrecy.
     */
    private static final long REKEY_INTERVAL = TimeUnit.HOURS.toMillis(1);

    /**
    * The size of the cryptographic nonce in bytes.
    * A 32-byte (256-bit) nonce provides strong uniqueness guarantees for session establishment.
    */
    private static final int NONCE_SIZE = 32;

    /**
     * Constructs a new {@code SecureChannel} instance by generating an EC key pair using the
     * "secp256r1" curve.This key pair is used for establishing a shared secret with a peer.
     *
     * @param isServer
     * @throws Exception If an error occurs during key pair generation, such as the specified algorithm
     *                   or curve being unavailable.
     */
    public SecureChannel(boolean isServer) throws Exception {
        this.isServer = isServer;
        // Initialize SecureRandom instance for IV generation
        this.random = new SecureRandom();        
        // Initialize KeyPairGenerator for Elliptic Curve (EC) algorithm
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        
        // Specify the EC curve to use
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(spec);
        
        // Generate the EC key pair
        this.keyPair = keyGen.generateKeyPair();
       
    }
    
    /**
     * Extracts the cryptographic nonce from a public key byte array.
     * The nonce is stored at a specific offset in the key data and is used
     * for ensuring unique session establishment.
     *
     * @param publicKey The public key byte array containing the embedded nonce
     * @return The extracted nonce as a byte array
     */
private byte[] extractNonceFromKey(byte[] publicKey) {
    // Check minimum size
    if (publicKey.length <= NONCE_SIZE) {
        log.warn("Public key data too short: {} bytes", publicKey.length);
        throw new IllegalArgumentException("Invalid public key format");
    }
    
    log.debug("Extracting nonce from key - total length: {}, expected last {} bytes", 
        publicKey.length, NONCE_SIZE);

    // Extract last NONCE_SIZE bytes as nonce
    byte[] nonce = Arrays.copyOfRange(publicKey, publicKey.length - NONCE_SIZE, publicKey.length);
    
    // Validate size
    if (nonce.length != NONCE_SIZE) {
        throw new IllegalArgumentException("Invalid nonce size");
    }
    
    // Add more verification in case the array copy failed
    log.debug("Extracted nonce bytes - start: {}, end: {}", 
        bytesToHex(Arrays.copyOf(nonce, 4)), 
        bytesToHex(Arrays.copyOfRange(nonce, nonce.length-4, nonce.length)));
    
    return nonce;
}


private byte[] extractECKey(byte[] publicKey) {
    if (publicKey.length < NONCE_OFFSET + NONCE_SIZE) {
        log.warn("Public key data too short: {} bytes", publicKey.length);
        throw new IllegalArgumentException("Invalid public key format");
    }
    return Arrays.copyOfRange(publicKey, 0, publicKey.length - NONCE_SIZE);
}
    /**
     * Compares two node IDs for consistent ordering in key establishment.
     * This ensures both peers will generate identical shared secrets by
     * consistently ordering the key material regardless of which peer
     * initiates the connection.
     *
     * @param key1 First key containing node ID
     * @param key2 Second key containing node ID
     * @return Negative if key1 < key2, positive if key1 > key2, 0 if equal
     */
    private int compareNodeIds(byte[] key1, byte[] key2) {
        // Extract actual key material without nonce
        byte[] id1 = Arrays.copyOfRange(key1, 0, Math.min(32, key1.length - NONCE_SIZE));
        byte[] id2 = Arrays.copyOfRange(key2, 0, Math.min(32, key2.length - NONCE_SIZE));
        return ByteBuffer.wrap(id1).compareTo(ByteBuffer.wrap(id2));
    }
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }
    /**
     * Establishes a secure communication channel with a peer by performing ECDH key agreement using the
     * peer's public key. The method ensures consistent key derivation between peers by:
     * <ul>
     *   <li>Performing ECDH key agreement with the peer's public key</li>
     *   <li>Generating and exchanging cryptographic nonces</li>
     *   <li>Ordering key material consistently based on node IDs</li>
     *   <li>Deriving a shared secret and session ID from the combined material</li>
     * </ul>
     *
     * @param peerPublicKey A {@code byte[]} containing both the peer's public key and nonce in a
     *                      combined format. The public key should be in X.509 encoded format.
     * @throws IOException If an error occurs during channel establishment, such as invalid key format,
     *                     key agreement failure, or cryptographic operation errors.
     */
    @Override
    public void establishSecureChannel(byte[] peerPublicKey) throws IOException {
        try {
            // Extract peer's nonce (no need to generate new one)
            byte[] peerNonce = extractNonceFromKey(peerPublicKey);
            byte[] peerECKey = extractECKey(peerPublicKey);

            // Convert peer's EC key
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(peerECKey);
            PublicKey peerKey = keyFactory.generatePublic(keySpec);

            // ECDH key agreement
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(keyPair.getPrivate());
            keyAgreement.doPhase(peerKey, true);
            byte[] sharedSecret_ = keyAgreement.generateSecret();

            // Combine material using request-response ordering
            ByteBuffer material = ByteBuffer.allocate(sharedSecret_.length + 2 * NONCE_SIZE + CONTEXT.length);
            material.put(sharedSecret_);
            
            // First nonce is always from the initial connection request
            // Second nonce is always from the response
            if (isServer) {
                material.put(peerNonce).put(this.localNonce);
                log.debug("Server using request-response order: peer -> local");
            } else {
                material.put(this.localNonce).put(peerNonce);
                log.debug("Client using request-response order: local -> peer");
            }
        
        log.debug("Material components:");
        log.debug("  Shared secret: {}", bytesToHex(sharedSecret_));
        log.debug("  First nonce:   {}", bytesToHex(material.array(), sharedSecret_.length, NONCE_SIZE));
        log.debug("  Second nonce:  {}", bytesToHex(material.array(), sharedSecret_.length + NONCE_SIZE, NONCE_SIZE));
        
        // Add context to prevent key reuse
        material.put(CONTEXT);

        // Generate final key and session ID
        MessageDigest hash = MessageDigest.getInstance("SHA-256");
        byte[] digestedSecret = hash.digest(material.array());
        
        // Split into key and session ID
        byte[] keyBytes = Arrays.copyOfRange(digestedSecret, 0, 16);
        this.sessionId = Arrays.copyOfRange(digestedSecret, 16, 32);
        this.sharedSecret = new SecretKeySpec(keyBytes, "AES");
        this.lastRekeyed = System.currentTimeMillis();
        this.established = true;

        log.debug("Final key hash: {}, session ID hash: {}", 
            Arrays.hashCode(keyBytes), Arrays.hashCode(this.sessionId));
        log.debug("Secure channel established with peer. Session ID created.");

    } catch (IllegalStateException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
        this.established = false;
        throw new IOException("Failed to establish secure channel", e);
    }
}

public byte[] getSessionId() {
    return sessionId;
}
    /**
     * Retrieves the local public key used for establishing secure channels with peers.
     * The returned data includes both the public key and a cryptographic nonce combined
     * into a single byte array. The nonce is appended at a specific offset after the
     * key data.
     *
     * @return A {@code byte[]} containing the combined public key and nonce data. The public
     *         key is in X.509 encoded format.
     */
    @Override
    public byte[] getPublicKey() {
        // Generate nonce when creating public key
        this.localNonce = new byte[NONCE_SIZE];
        random.nextBytes(this.localNonce);
        log.debug("Generated nonce for public key: {}", bytesToHex(this.localNonce));

        // Combine key and nonce
        byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
        byte[] combined = new byte[publicKeyBytes.length + NONCE_SIZE];
        System.arraycopy(publicKeyBytes, 0, combined, 0, publicKeyBytes.length);
        System.arraycopy(this.localNonce, 0, combined, publicKeyBytes.length, NONCE_SIZE);
        
        return combined;
    }

    /**
     * Encrypts the provided plaintext data using AES-GCM encryption with the established shared secret.
     * Generates a random initialization vector (IV) for each encryption operation to ensure security.
     *
     * @param data A {@code byte[]} containing the plaintext data to be encrypted.
     * @return A {@code byte[]} containing the encrypted data, prefixed with the IV for use in decryption.
     * @throws Exception If an error occurs during the encryption process, such as cipher initialization
     *                   failures or encryption algorithm issues.
     */
    @Override
    public byte[] encryptMessage(byte[] data) throws Exception {
        if (!established || data == null) {
            throw new IllegalArgumentException("Invalid message format or secure channel not established.");
        }
        
        log.debug("Encrypting message length: {}, key hash: {}, key: {}", 
            data.length, sharedSecret.hashCode(), bytesToHex(sharedSecret.getEncoded()));

        // Generate IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        random.nextBytes(iv);
        log.debug("Generated IV: {}", bytesToHex(iv));

        // Get cipher instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, sharedSecret, parameterSpec);
        
        // Add sessionId as AAD if available
        if (sessionId != null) {
            cipher.updateAAD(sessionId);
            log.debug("Added AAD (sessionId): {}", bytesToHex(sessionId));
        }

        // Perform encryption
        byte[] ciphertext = cipher.doFinal(data);
        log.debug("Encrypted data length: {}, data: {}", 
            ciphertext.length, bytesToHex(ciphertext));

        // Combine IV and ciphertext
        ByteBuffer output = ByteBuffer.allocate(iv.length + ciphertext.length);
        output.put(iv);
        output.put(ciphertext);
        log.debug("Final encrypted message length: {}, full message: {}", 
            output.limit(), bytesToHex(output.array()));
        return output.array();
    }


    /**
     * Decrypts the provided ciphertext data using AES-GCM decryption with the established shared secret.Expects the ciphertext to be prefixed with the IV used during encryption.
     *
     * @param encryptedData A {@code byte[]} containing the encrypted data to be decrypted. The first 12 bytes should
     *             represent the IV, followed by the actual ciphertext.
     * @return A {@code byte[]} containing the decrypted plaintext data.
     * @throws Exception If an error occurs during the decryption process, such as invalid ciphertext format,
     *                   decryption algorithm issues, or authentication tag verification failures.
     */
    @Override
    public byte[] decryptMessage(byte[] encryptedData) throws Exception {
        // Add special case for pings - they're too small to be encrypted messages
        if (encryptedData != null && encryptedData.length == 1) {
            log.debug("Received unencrypted ping message");
            return encryptedData;  // Return as-is
        }

        // Normal message handling for everything else
        if (!established || encryptedData == null || encryptedData.length < GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Invalid message format or secure channel not established.");
        }

        log.debug("Decrypting message length: {}, key hash: {}, key: {}", 
            encryptedData.length, sharedSecret.hashCode(), bytesToHex(sharedSecret.getEncoded()));
        log.debug("Full encrypted message: {}", bytesToHex(encryptedData));

        // Extract IV and ciphertext
        ByteBuffer buffer = ByteBuffer.wrap(encryptedData);
        byte[] iv = new byte[GCM_IV_LENGTH];
        buffer.get(iv);
        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        log.debug("Extracted IV: {}", bytesToHex(iv));
        log.debug("Extracted ciphertext length: {}, data: {}", 
            ciphertext.length, bytesToHex(ciphertext));

        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, sharedSecret, parameterSpec);

        // Add sessionId as AAD if available
        if (sessionId != null) {
            cipher.updateAAD(sessionId);
            log.debug("Added AAD (sessionId): {}", bytesToHex(sessionId));
        }

        // Perform decryption
        try {
            byte[] decrypted = cipher.doFinal(ciphertext);
            log.debug("Successfully decrypted to length: {}, data: {}", 
                decrypted.length, bytesToHex(decrypted));
            return decrypted;
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            log.error("Decryption failed: {}\nShared Secret: {}\nIV: {}\nCiphertext: {}\nSession ID: {}", 
                e.getMessage(),
                bytesToHex(sharedSecret.getEncoded()),
                bytesToHex(iv),
                bytesToHex(ciphertext),
                sessionId != null ? bytesToHex(sessionId) : "null");
            throw e;
        }
    }

private static String bytesToHex(byte[] bytes, int offset, int length) {
    StringBuilder sb = new StringBuilder();
    for (int i = offset; i < offset + length; i++) {
        sb.append(String.format("%02x", bytes[i] & 0xFF));
    }
    return sb.toString();
}
    /**
     * Checks whether the secure communication channel has been successfully established. Returns {@code true}
     * if the channel is active and ready for encrypted communication; otherwise, returns {@code false}.
     *
     * @return {@code true} if the secure channel is established and active; {@code false} otherwise.
     */
    @Override
    public boolean isEstablished() {
        return established;
    }
}
