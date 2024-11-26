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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;
import java.nio.ByteBuffer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * The {@code ProofOfWork} class encapsulates the functionality required to generate and verify
 * proofs of work (PoW) within the peer-to-peer (P2P) VPN network. Proofs of work are essential
 * for securing the network by ensuring that peers perform computationally intensive tasks
 * before being allowed to join or maintain their presence in the network.
 * </p>
 * 
 * <p>
 * <strong>Key Functionalities:</strong></p>
 * <ul>
 *   <li>Generating a valid proof of work by finding a nonce that satisfies the difficulty criteria.</li>
 *   <li>Verifying the validity of a given proof of work.</li>
 *   <li>Managing proof-related metadata such as timestamps to ensure freshness and prevent replay attacks.</li>
 * </ul>
 * 
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Initialize ProofOfWork with a unique node ID
 * byte[] nodeId = ...; // 32-byte unique identifier
 * ProofOfWork pow = new ProofOfWork(nodeId);
 * 
 * // Solve for a valid proof
 * boolean solved = pow.solve();
 * if (solved) {
 *     byte[] proof = pow.getCurrentProof();
 *     long timestamp = pow.getTimestamp();
 *     // Broadcast proof to peers or use in handshake
 * }
 * 
 * // Verify a received proof
 * boolean isValid = pow.verify(receivedProofData, receivedTimestamp);
 * if (isValid) {
 *     // Accept the peer or update network state
 * }
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>
 * </p>
 * <p>
 * The {@code ProofOfWork} class is designed to be thread-safe. The `currentProof` and `timestamp` fields
 * are marked as `volatile` to ensure visibility across threads. Additionally, the `solve` and `verify`
 * methods handle their operations in a manner that prevents race conditions, allowing concurrent attempts
 * to solve proofs or verify received proofs without compromising data integrity.
 * </p>
 * 
 * <p>
 * <strong>Dependencies:</strong>
 * </p>
 * <ul>
 *   <li>{@link MessageDigest}: Utilized for hashing operations using the SHA-256 algorithm.</li>
 *   <li>SLF4J Logging Framework: Employed for logging informational, debug, and error messages.</li>
 * </ul>
 * 
 * @author 
 * Publius Pseudis
 */
public class ProofOfWork {
    /**
     * Logger instance for logging information, warnings, and errors.
     */
    private static final Logger log = LoggerFactory.getLogger(ProofOfWork.class);

    /**
     * The number of leading zero bits required in the hash to consider a proof as valid.
     */
    private static final int DIFFICULTY = 20; // Number of leading zero bits required

    /**
     * The unique node ID associated with this proof of work instance.
     */
    private final byte[] nodeId;

    /**
     * The current valid proof of work. This includes the node ID, timestamp, and nonce.
     *
     * <p>
     * Once a valid proof is found using the {@link #solve()} method, this field stores the proof data
     * that satisfies the difficulty requirement. It is used for verifying the legitimacy of the node
     * within the network.
     * </p>
     */
    private volatile byte[] currentProof;

    /**
     * The timestamp indicating when the current proof of work was generated.
     *
     * <p>
     * This timestamp is used to ensure the freshness of the proof and to prevent replay attacks
     * by associating the proof with a specific moment in time.
     * </p>
     */
    private volatile long timestamp;

    /**
     * Constructs a new {@code ProofOfWork} instance with the specified node ID.
     *
     * <p>
     * Initializes the proof of work with the provided unique node identifier. The constructor sets
     * the initial timestamp to the current system time to ensure the proof's validity period.
     * </p>
     *
     * @param nodeId The unique node ID for which the proof of work is to be generated and verified.
     *               Must be a non-null byte array of a specific length (e.g., 32 bytes).
     * @throws IllegalArgumentException If {@code nodeId} is {@code null} or does not meet the required criteria.
     */
    public ProofOfWork(byte[] nodeId) {
        if (nodeId == null) {
            throw new IllegalArgumentException("nodeId cannot be null");
        }
        this.nodeId = nodeId;
        this.timestamp = System.currentTimeMillis();
    }

    /**
     * Attempts to solve the proof of work by finding a nonce that, when combined with the node ID and timestamp,
     * produces a SHA-256 hash with the required number of leading zero bits.
     *
     * @return {@code true} if a valid proof is found; {@code false} otherwise.
     */
    public boolean solve() {
        long nonce = 0;
        timestamp = System.currentTimeMillis(); // Update timestamp before solving
        byte[] attempt = new byte[nodeId.length + 8 + 8]; // nodeId + timestamp + nonce
        System.arraycopy(nodeId, 0, attempt, 0, nodeId.length);
        ByteBuffer.wrap(attempt, nodeId.length, 8).putLong(timestamp);

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            while (!Thread.currentThread().isInterrupted()) {
                // Insert nonce into the attempt array
                ByteBuffer.wrap(attempt, nodeId.length + 8, 8).putLong(nonce);
                byte[] hash = digest.digest(attempt);

                if (isValidProof(hash)) {
                    currentProof = Arrays.copyOf(attempt, attempt.length);
                    log.info("Found valid proof of work after {} attempts", nonce);
                    return true;
                }
                nonce++;
            }
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA-256 not available", e);
        }
        return false;
    }

    /**
     * Checks whether the provided hash satisfies the difficulty requirement by having the requisite number of
     * leading zero bits.
     *
     * @param hash The SHA-256 hash to validate.
     * @return {@code true} if the hash meets the difficulty criteria; {@code false} otherwise.
     */
    private boolean isValidProof(byte[] hash) {
        int leadingZeros = 0;
        for (byte b : hash) {
            int bits = Integer.numberOfLeadingZeros(b & 0xFF) - 24;
            leadingZeros += bits;
            if (bits < 8) {
                break;
            }
        }
        return leadingZeros >= DIFFICULTY;
    }

    /**
     * Retrieves the current valid proof of work.
     *
     * @return A byte array representing the current proof of work, including node ID, timestamp, and nonce.
     */
    public byte[] getCurrentProof() {
        return currentProof;
    }

    /**
     * Retrieves the timestamp associated with the current proof of work.
     *
     * @return The timestamp in milliseconds since the epoch.
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     * Verifies the validity of a received proof of work by ensuring it meets the difficulty criteria
     * and that its timestamp is within acceptable bounds.
     *
     * <p>
     * This method checks that the proof's timestamp is neither too old nor set in the future,
     * preventing replay attacks and ensuring proof freshness. It then validates the proof by
     * hashing the provided proof data and confirming that the resulting hash has the required
     * number of leading zero bits as defined by the {@link #DIFFICULTY} constant.
     * </p>
     *
     * @param proofData      The byte array containing the proof of work data (node ID + timestamp + nonce).
     *                       Must be structured correctly to match the hashing criteria.
     * @param proofTimestamp The timestamp associated with the proof of work in milliseconds since the epoch.
     *                       This should closely align with the current system time to be considered valid.
     * @return {@code true} if the proof is valid and meets all criteria; {@code false} otherwise.
     */
    public boolean verify(byte[] proofData, long proofTimestamp) {
      // Check timestamp bounds to ensure proof freshness
      long now = System.currentTimeMillis();
      log.debug("Verifying proof - Current time: {}, Proof time: {}, Delta: {}ms", 
          now, proofTimestamp, now - proofTimestamp);

      if (now - proofTimestamp > TimeUnit.DAYS.toMillis(1)) {
          log.warn("Proof expired. Current time: {}, Proof time: {}", now, proofTimestamp);
          return false;
      }
      if (proofTimestamp > now + TimeUnit.MINUTES.toMillis(5)) {
          log.warn("Proof from future. Current time: {}, Proof time: {}", now, proofTimestamp);
          return false;
      }

      try {
          // Extract nodeId and timestamp
          log.debug("Proof data length: {}, content: {}", 
              proofData.length, bytesToHex(proofData));

          // Calculate hash
          MessageDigest digest = MessageDigest.getInstance("SHA-256");
          byte[] hash = digest.digest(proofData);

          log.debug("Calculated hash: {}", bytesToHex(hash));

          int leadingZeros = countLeadingZeros(hash);
          log.debug("Leading zeros required: {}, found: {}", 
              DIFFICULTY, leadingZeros);

          return leadingZeros >= DIFFICULTY;

      } catch (NoSuchAlgorithmException e) {
          log.error("Failed to verify proof: {}", e.getMessage(), e);
          return false;
      }
  }
    /**
     * Converts an array of bytes into its corresponding hexadecimal string representation.
     *
     * <p>
     * This utility method is useful for logging binary data in a human-readable hexadecimal format,
     * aiding in debugging and monitoring network messages or cryptographic operations.
     * </p>
     *
     * @param bytes The array of bytes to convert.
     * @return A {@code String} representing the hexadecimal values of the input bytes.
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }

    /**
     * Counts the number of leading zero bits in a given SHA-256 hash.
     *
     * <p>
     * This method iterates through the bytes of the hash, counting the number of consecutive zero bits
     * from the start. The count is used to determine if the hash meets the required difficulty level
     * for a valid proof of work.
     * </p>
     *
     * @param hash The byte array representing the SHA-256 hash to evaluate.
     * @return The total number of leading zero bits in the hash.
     */
    private int countLeadingZeros(byte[] hash) {
        int leadingZeros = 0;
        for (byte b : hash) {
            if (b == 0) {
                leadingZeros += 8;
            } else {
                leadingZeros += Integer.numberOfLeadingZeros(b & 0xFF);
                break;
            }
        }
        return leadingZeros;
    }
}
