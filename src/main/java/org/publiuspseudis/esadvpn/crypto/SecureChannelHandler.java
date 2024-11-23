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

/**
 * <p>
 * The {@code SecureChannelHandler} interface defines the contract for establishing and managing
 * secure communication channels between peers within the peer-to-peer (P2P) VPN network. Implementations
 * of this interface are responsible for handling the setup of encrypted connections, ensuring data
 * confidentiality and integrity during transmission.
 * </p>
 * 
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Establishing a secure communication channel using the peer's public key.</li>
 *   <li>Providing access to the handler's public key for peer identification and encryption.</li>
 *   <li>Encrypting outgoing messages to ensure data confidentiality.</li>
 *   <li>Decrypting incoming messages to retrieve original data.</li>
 *   <li>Monitoring the establishment status of the secure channel.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Assume SecureChannelHandlerImpl is a concrete implementation of SecureChannelHandler
 * SecureChannelHandler secureHandler = new SecureChannelHandlerImpl();
 * 
 * // Establish a secure channel with a peer using their public key
 * byte[] peerPublicKey = ...; // Obtain the peer's public key through a secure exchange
 * try {
 *     secureHandler.establishSecureChannel(peerPublicKey);
 * } catch (IOException e) {
 *     // Handle exception during secure channel establishment
 * }
 * 
 * // Encrypt a message before sending
 * byte[] plainMessage = "Hello, Peer!".getBytes(StandardCharsets.UTF_8);
 * byte[] encryptedMessage;
 * try {
 *     encryptedMessage = secureHandler.encryptMessage(plainMessage);
 * } catch (Exception e) {
 *     // Handle encryption errors
 * }
 * 
 * // Decrypt a received message
 * byte[] receivedEncryptedMessage = ...; // Received encrypted data
 * byte[] decryptedMessage;
 * try {
 *     decryptedMessage = secureHandler.decryptMessage(receivedEncryptedMessage);
 * } catch (Exception e) {
 *     // Handle decryption errors
 * }
 * 
 * // Check if the secure channel is established
 * if (secureHandler.isEstablished()) {
 *     // Proceed with secure communication
 * }
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>
 * </p>
 * <p>
 * Implementations of the {@code SecureChannelHandler} interface should ensure thread safety, especially
 * if the handler is accessed by multiple threads concurrently. Synchronization mechanisms or thread-safe
 * data structures should be employed to prevent race conditions and ensure consistent state management.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>Java Cryptography Architecture (JCA): Utilized for cryptographic operations such as encryption and decryption.</li>
 *   <li>SLF4J Logging Framework: Recommended for logging informational, debug, and error messages.</li>
 * </ul>
 * 
 * @author 
 * Publius Pseudis
 */
public interface SecureChannelHandler {
    /**
     * Establishes a secure communication channel with a peer using the provided public key. This method
     * initiates the process of setting up encrypted communication, ensuring that subsequent messages
     * exchanged with the peer are confidential and tamper-proof.
     *
     * @param peerPublicKey A {@code byte[]} representing the peer's public key used for establishing
     *                      the secure channel. This key should be obtained through a secure exchange
     *                      mechanism to prevent man-in-the-middle attacks.
     * @throws IOException If an I/O error occurs during the establishment of the secure channel, such as
     *                     failures in cryptographic operations or network disruptions.
     */
    void establishSecureChannel(byte[] peerPublicKey) throws IOException;
    
    /**
     * Retrieves the public key associated with this secure channel handler. The public key is used by
     * peers to encrypt messages intended for this handler, ensuring that only the intended recipient
     * can decrypt and access the message content.
     *
     * @return A {@code byte[]} representing the public key of this handler.
     */
    byte[] getPublicKey();
    
    /**
     * Encrypts the provided plaintext data to ensure secure transmission over the network. The encryption
     * process transforms the data into an unreadable format, which can only be decrypted by the intended
     * recipient possessing the corresponding private key.
     *
     * @param data A {@code byte[]} containing the plaintext data to be encrypted.
     * @return A {@code byte[]} containing the encrypted data, ready for secure transmission.
     * @throws Exception If an error occurs during the encryption process, such as issues with the cryptographic
     *                   algorithm or invalid input data.
     */
    byte[] encryptMessage(byte[] data) throws Exception;
    
    /**
     * Decrypts the provided ciphertext data to retrieve the original plaintext. The decryption process
     * reverses the encryption, making the data readable and usable by the recipient.
     *
     * @param data A {@code byte[]} containing the encrypted data to be decrypted.
     * @return A {@code byte[]} containing the decrypted plaintext data.
     * @throws Exception If an error occurs during the decryption process, such as invalid ciphertext or
     *                   issues with the cryptographic algorithm.
     */
    byte[] decryptMessage(byte[] data) throws Exception;
    
    /**
     * Checks whether the secure communication channel has been successfully established. This method
     * returns {@code true} if the channel is active and secure, allowing for encrypted communication
     * between peers. Otherwise, it returns {@code false}, indicating that the secure channel is not
     * yet established or has been terminated.
     *
     * @return {@code true} if the secure channel is established and active; {@code false} otherwise.
     */
    boolean isEstablished();
}
