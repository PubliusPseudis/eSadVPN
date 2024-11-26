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
package org.publiuspseudis.esadvpn.crypto;

import java.io.IOException;
import java.nio.ByteBuffer;
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
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.publiuspseudis.esadvpn.routing.RouteInfo;
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

    
    private volatile byte[] sessionId;
    private volatile long lastRekeyed;
    private static final long REKEY_INTERVAL = TimeUnit.HOURS.toMillis(1);
    private static final int NONCE_SIZE = 32;
    
    /**
     * Constructs a new {@code SecureChannel} instance by generating an EC key pair using the
     * "secp256r1" curve. This key pair is used for establishing a shared secret with a peer.
     *
     * @throws Exception If an error occurs during key pair generation, such as the specified algorithm
     *                   or curve being unavailable.
     */
    public SecureChannel() throws Exception {
        // Initialize KeyPairGenerator for Elliptic Curve (EC) algorithm
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        
        // Specify the EC curve to use
        ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
        keyGen.initialize(spec);
        
        // Generate the EC key pair
        this.keyPair = keyGen.generateKeyPair();
        
        // Initialize SecureRandom instance for IV generation
        this.random = new SecureRandom();
    }

    /**
     * Establishes a secure communication channel with a peer by performing ECDH key agreement using the
     * peer's public key. Upon successful key agreement, a shared secret is derived and used as the
     * symmetric key for AES-GCM encryption and decryption.
     *
     * @param peerPublicKey A {@code byte[]} representing the peer's public key in X.509 encoded format.
     *                      This key should be obtained through a secure exchange mechanism to prevent
     *                      man-in-the-middle attacks.
     * @throws IOException If an error occurs during the establishment of the secure channel, such as
     *                     failures in key agreement or cryptographic operations.
     */
    @Override
    public void establishSecureChannel(byte[] peerPublicKey) throws IOException {
       try {
           // Generate session nonce
           byte[] localNonce = new byte[NONCE_SIZE];
           random.nextBytes(localNonce);

           // Convert peer's public key
           KeyFactory keyFactory = KeyFactory.getInstance("EC");
           X509EncodedKeySpec keySpec = new X509EncodedKeySpec(peerPublicKey);
           PublicKey peerKey = keyFactory.generatePublic(keySpec);

           // Initialize KeyAgreement for ECDH
           KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
           keyAgreement.init(keyPair.getPrivate());

           // Perform the key agreement phase with the peer's public key
           keyAgreement.doPhase(peerKey, true);

           // Generate the shared secret
           byte[] sharedSecretBytes = keyAgreement.generateSecret();

           // Combine secret with nonce
           ByteBuffer material = ByteBuffer.allocate(sharedSecretBytes.length + localNonce.length);
           material.put(sharedSecretBytes).put(localNonce).flip();

           // Derive key and session ID
           MessageDigest hash = MessageDigest.getInstance("SHA-256");
           byte[] digestedSecret = hash.digest(material.array());

           byte[] keyBytes = Arrays.copyOfRange(digestedSecret, 0, 16);
           this.sessionId = Arrays.copyOfRange(digestedSecret, 16, 32);
           this.sharedSecret = new SecretKeySpec(keyBytes, "AES");
           this.lastRekeyed = System.currentTimeMillis();

           this.established = true;

       } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
           throw new IOException("Failed to establish secure channel", e);
       }
   }

    /**
     * Retrieves the local public key used for establishing secure channels with peers. This key should be
     * shared with peers through a secure out-of-band channel to facilitate the key agreement process.
     *
     * @return A {@code byte[]} containing the local public key in X.509 encoded format.
     */
    @Override
    public byte[] getPublicKey() {
        return keyPair.getPublic().getEncoded();
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
        if (!established) {
            return data;
        }

        // Check if rekey needed
        if (System.currentTimeMillis() - lastRekeyed > REKEY_INTERVAL) {
            byte[] newNonce = new byte[NONCE_SIZE];
            random.nextBytes(newNonce);
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(sharedSecret.getEncoded());
            hash.update(newNonce);
            byte[] newSecret = hash.digest();
            this.sharedSecret = new SecretKeySpec(newSecret, "AES");
            this.lastRekeyed = System.currentTimeMillis();
        }

        // Generate IV for AES-GCM
        byte[] iv = new byte[12];
        random.nextBytes(iv);

        // Initialize cipher for encryption
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, sharedSecret, new GCMParameterSpec(128, iv));

        // Add session ID as additional authenticated data
        if (sessionId != null) {
            cipher.updateAAD(sessionId);
        }

        // Perform encryption
        byte[] encrypted = cipher.doFinal(data);

        // Combine IV and encrypted data
        ByteBuffer result = ByteBuffer.allocate(iv.length + encrypted.length);
        result.put(iv).put(encrypted);
        return result.array();
    }

    /**
     * Decrypts the provided ciphertext data using AES-GCM decryption with the established shared secret.
     * Expects the ciphertext to be prefixed with the IV used during encryption.
     *
     * @param data A {@code byte[]} containing the encrypted data to be decrypted. The first 12 bytes should
     *             represent the IV, followed by the actual ciphertext.
     * @return A {@code byte[]} containing the decrypted plaintext data.
     * @throws Exception If an error occurs during the decryption process, such as invalid ciphertext format,
     *                   decryption algorithm issues, or authentication tag verification failures.
     */
    @Override
    public byte[] decryptMessage(byte[] data) throws Exception {
        if (!established || data == null || data.length < 12) {
            throw new IllegalArgumentException("Invalid message format or secure channel not established.");
        }

        // Extract the IV (first 12 bytes)
        ByteBuffer buffer = ByteBuffer.wrap(data);
        byte[] iv = new byte[12];
        buffer.get(iv);

        // Extract the actual encrypted data
        byte[] encrypted = new byte[buffer.remaining()];
        buffer.get(encrypted);

        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, sharedSecret, new GCMParameterSpec(128, iv));

        // Add session ID as additional authenticated data
        if (sessionId != null) {
            cipher.updateAAD(sessionId);
        }

        // Perform decryption
        return cipher.doFinal(encrypted);
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
