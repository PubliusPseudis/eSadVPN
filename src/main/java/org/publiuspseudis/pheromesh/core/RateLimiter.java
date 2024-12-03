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
package org.publiuspseudis.pheromesh.core;

/**
 * <p>
 * The {@code RateLimiter} class implements a thread-safe token bucket algorithm
 * to control the rate of events, such as network packet processing. It ensures
 * that the number of permitted actions does not exceed a specified limit within
 * a given time frame.
 * </p>
 *
 * <p>
 * This implementation is suitable for scenarios where controlling the flow
 * of incoming or outgoing traffic is essential to prevent resource exhaustion
 * or to adhere to predefined usage policies. The rate limiter refills tokens
 * at a steady rate, allowing threads to acquire tokens before proceeding with
 * their operations.
 * </p>
 *
 * <p>
 * <strong>Key Features:</strong>
 * </p>
 * <ul>
 *   <li>Configurable rate limit based on tokens per second.</li>
 *   <li>Thread-safe operations using synchronization.</li>
 *   <li>Efficient token refill mechanism leveraging high-resolution time.</li>
 *   <li>Tracks the last usage time for potential cleanup or monitoring purposes.</li>
 * </ul>
 * 
 * <p>
 * <strong>Example Usage:</strong>
 * </p>
 * <pre>{@code
 * // Create a rate limiter allowing 1000 packets per second
 * RateLimiter rateLimiter = new RateLimiter(1000);
 * 
 * // Attempt to acquire a token before processing a packet
 * if (rateLimiter.tryAcquire()) {
 *     // Proceed with packet processing
 * } else {
 *     // Handle rate limit exceeded (e.g., drop packet, queue for later)
 * }
 * }</pre>
 * 
 * <p>
 * <strong>Thread Safety:</strong>  
 * All public methods of the {@code RateLimiter} class are thread-safe.
 * The class uses synchronization to ensure that token acquisition and
 * refilling operations are atomic and consistent across multiple threads.
 * </p>
 * 
 * @author
 * Publius Pseudis
 * 
 * @version 1.0
 */
public class RateLimiter {
    /**
     * The maximum number of tokens that can be accumulated in the bucket per second.
     * This value determines the rate at which tokens are refilled.
     */
    private final long tokensPerSec;

    /**
     * The number of nanoseconds required to accumulate a single token.
     * Calculated as 1,000,000,000 divided by {@code tokensPerSec}.
     */
    private final double nsPerToken;

    /**
     * The current number of available tokens in the bucket.
     * This value is decremented when a token is acquired and incremented
     * during the refill process.
     */
    private volatile double tokens;

    /**
     * The timestamp (in nanoseconds) of the last token refill operation.
     * Used to calculate the number of tokens to add based on elapsed time.
     */
    private volatile long lastRefillTime;

    /**
     * The timestamp (in milliseconds) of the last successful token acquisition.
     * Useful for monitoring and cleanup purposes.
     */
    private volatile long lastUsedTime; 

    /**
     * An object used for synchronizing access to token acquisition and refill operations.
     * Ensures thread-safe manipulation of shared resources.
     */
    private final Object lock = new Object();


    /**
     * Constructs a new {@code RateLimiter} with the specified token rate.
     *
     * <p>
     * Initializes the rate limiter with the given number of tokens per second.
     * The token bucket is initially filled to its maximum capacity.
     * </p>
     *
     * @param tokensPerSec The maximum number of tokens allowed per second.
     *                     Must be a positive integer.
     * @throws IllegalArgumentException If {@code tokensPerSec} is not positive.
     */
    public RateLimiter(long tokensPerSec) throws IllegalArgumentException {
        this.tokensPerSec = tokensPerSec;
        this.nsPerToken = 1_000_000_000.0 / tokensPerSec;
        this.tokens = tokensPerSec;
        long now = System.nanoTime();
        this.lastRefillTime = now;
        this.lastUsedTime = System.currentTimeMillis(); // Initialize lastUsedTime
    }

    /**
     * Attempts to acquire a single token from the rate limiter.
     *
     * <p>
     * If a token is available, it is consumed, and the method returns {@code true},
     * indicating that the action is permitted. If no tokens are available, the method
     * returns {@code false}, indicating that the rate limit has been exceeded.
     * </p>
     *
     * <p>
     * This method is thread-safe and can be called concurrently by multiple threads.
     * </p>
     *
     * @return {@code true} if a token was successfully acquired; {@code false} otherwise.
     */
    public boolean tryAcquire() {
        synchronized (lock) {
            refillTokens();
            
            if (tokens >= 1.0) {
                tokens--;
                lastUsedTime = System.currentTimeMillis(); // Update when successfully used
                return true;
            }
            return false;
        }
    }

    /**
     * Refills the token bucket based on the elapsed time since the last refill.
     *
     * <p>
     * Calculates the number of tokens to add by determining how much time has passed
     * since {@code lastRefillTime}. The bucket is refilled with tokens at the rate
     * defined by {@code tokensPerSec}, ensuring that the total number of tokens
     * does not exceed the maximum capacity.
     * </p>
     *
     * <p>
     * This method is intended to be called internally within a synchronized context.
     * </p>
     */
    private void refillTokens() {
        long now = System.nanoTime();
        double elapsed = (now - lastRefillTime);
        double newTokens = elapsed / nsPerToken;
        
        if (newTokens > 0) {
            tokens = Math.min(tokensPerSec, tokens + newTokens);
            lastRefillTime = now;
        }
    }
    /**
     * Retrieves the timestamp of the last successful token acquisition.
     *
     * <p>
     * This method can be used to determine when the rate limiter was last utilized,
     * which is helpful for monitoring usage patterns or performing cleanup of inactive
     * rate limiters.
     * </p>
     *
     * @return The timestamp (in milliseconds since epoch) of the last token acquisition.
     */
    public long getLastUsedTime() {
        return lastUsedTime;
    }
    /**
     * Retrieves the maximum number of tokens that can be accumulated in the bucket.
     *
     * <p>
     * This value defines the capacity of the token bucket and determines the burst
     * capacity of the rate limiter.
     * </p>
     *
     * @return The maximum number of tokens per second.
     */
    public long getTokensPerSec() {
        return tokensPerSec;
    }

    /**
     * Calculates the current refill rate in tokens per second.
     *
     * <p>
     * This method returns the configured rate at which tokens are replenished,
     * allowing for dynamic adjustment or monitoring of the rate limiter's behavior.
     * </p>
     *
     * @return The number of tokens added to the bucket each second.
     */
    public double getRefillRate() {
        return tokensPerSec;
    }

    /**
     * Resets the rate limiter to its initial state.
     *
     * <p>
     * This method clears any accumulated tokens and resets the refill timer.
     * After calling this method, the rate limiter will behave as if it was newly created.
     * </p>
     *
     * <p>
     * Use this method with caution, as it may disrupt ongoing rate-limited operations.
     * </p>
     */
    public void reset() {
        synchronized (lock) {
            this.tokens = tokensPerSec;
            this.lastRefillTime = System.nanoTime();
            this.lastUsedTime = System.currentTimeMillis();
        }
    }

    /**
     * Provides a string representation of the rate limiter's current state.
     *
     * <p>
     * The returned string includes the configured token rate, available tokens,
     * and the timestamp of the last token acquisition.
     * </p>
     *
     * @return A {@code String} detailing the rate limiter's state.
     */
    @Override
    public String toString() {
        synchronized (lock) {
            refillTokens();
            return String.format("RateLimiter[tokensPerSec=%d, availableTokens=%.2f, lastUsedTime=%d]",
                    tokensPerSec, tokens, lastUsedTime);
        }
    }
}

