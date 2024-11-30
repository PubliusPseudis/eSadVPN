# Overview

**PH3R0M35H (Everyday Swarm Assisted Decentralized VPN)** is a
peer-to-peer, decentralized Virtual Private Network (VPN) designed to
provide secure, scalable, and resilient internet access. It leverages
swarm intelligence for routing and a gossip-based protocol for efficient
network synchronization, eliminating the need for centralized
infrastructure. The integration of a SOCKS proxy ensures seamless
compatibility with local applications.

# Key Features

  - **SOCKS Proxy for Local Use:** Routes application traffic through
    the VPN, intended for local or trusted LAN connections. Users must
    ensure application-level encryption for sensitive data (e.g.,
    HTTPS).

  - **Peer-to-Peer Architecture:** Operates without reliance on
    centralized servers, ensuring maximum resilience.

  - **Swarm Intelligence Routing:** Implements pheromone-based
    algorithms for adaptive and efficient packet forwarding.

  - **Dynamic Proof-of-Work (PoW):** Adjusts difficulty dynamically to
    balance resource usage and prevent Sybil attacks.

  - **Gossip Protocol with Anti-Replay Protection:** Synchronizes the
    network state incrementally using nonces and timestamps to prevent
    replay attacks.

  - **Rate Limiting and Reputation Scoring:** Penalizes malicious nodes
    while rewarding reliable peers for a healthy network ecosystem.

  - **Buffer Pooling:** Efficient memory management ensures smooth
    performance under high packet loads.

# Technical Highlights

## Architecture Overview

  - **Swarm Router:** Utilizes pheromone-based path selection for
    efficient and scalable routing.

  - **Gossip Protocol:** Reduces bandwidth usage by propagating
    incremental updates rather than full state synchronization.

  - **Virtual Network Interface:** Injects and processes IP packets
    seamlessly for local application compatibility.

  - **Dynamic Rate Limiting:** Employs per-peer rate limits to ensure
    fair resource usage and mitigate abuse.

  - **Anti-Replay Mechanism:** Nonces and timestamps validate incoming
    messages to prevent replay attacks.

  - **Exit Node Monitoring:** Reputation-based scoring and rate limiting
    prevent misuse and ensure network integrity.

# Strengths

  - **Decentralization:** Fully peer-to-peer architecture eliminates
    reliance on centralized infrastructure, enhancing privacy and
    resilience.

  - **Efficient Routing:** Swarm intelligence algorithms ensure
    low-latency and adaptive load balancing across the network.

  - **Scalability:** Gossip-based peer synchronization minimizes
    bandwidth usage and supports large-scale networks.

  - **Security:** Integration of dynamic PoW, anti-replay measures, and
    rate limiting safeguards the network’s integrity.

# Weaknesses

  - **Exit Node Risks:** While exit nodes are monitored, they still pose
    potential risks, especially if users fail to encrypt their traffic.

  - **Latency Sensitivity:** High-latency environments may impact the
    performance of swarm-based routing.

  - **Proof-of-Work Overheads:** Dynamic PoW can introduce computational
    overhead, especially for low-resource devices.

  - **Initial Peer Discovery:** Dependence on user-provided peer
    information for bootstrapping can be a hurdle for non-technical
    users.

# Areas for Improvement

  - **Improved Exit Node Transparency:** Introduce mechanisms to audit
    and verify exit node behavior.

  - **Simplified Onboarding:** Develop a user-friendly interface for
    easier configuration and initial peer discovery.

  - **Energy Efficiency:** Optimize the dynamic PoW algorithm to reduce
    energy consumption on resource-constrained devices.

  - **Enhanced Metadata Protection:** Incorporate additional measures to
    minimize metadata leaks, such as randomized traffic padding.

  - **Real-Time Monitoring:** Provide tools for users to visualize
    network performance and the trustworthiness of connected peers.

# Quick Start

## Prerequisites

  - Java 17 or later.

  - Maven for building dependencies.

## Building the Project

Clone the repository and build the application:

    git clone https://github.com/publiuspseudis/esadvpn.git
    cd esadvpn
    mvn clean package

## Running ESADVPN

**P2P Mode (First Node):**

    java -jar target/esadvpn.jar p2p [port]

\*Example:\* Start the first node on port 8942. The SOCKS proxy will
listen on port 8943.

**Connect Mode (Join Existing Network):**

    java -jar target/esadvpn.jar connect [local-port] [peer-host] [peer-port]

\*Example:\* Join a network via localhost on port 8942. Start the VPN on
port 8944 and the SOCKS proxy on port 8945.

# Security Notes

  - **Local SOCKS Proxy Use:** The SOCKS proxy is designed for local or
    trusted LAN connections. It does not encrypt traffic by itself.
    Users should ensure that routed traffic is encrypted at the
    application level (e.g., HTTPS).

  - **End-to-End Encryption:** Traffic leaving the VPN exit node is
    vulnerable to interception unless encrypted. Always use
    application-layer security for sensitive data.

  - **Replay Attack Prevention:** Gossip messages use nonces and
    timestamps to prevent replay attacks, maintaining network integrity.

# License

This project is licensed under the **GNU General Public License v3**.
See the `LICENSE` file for details.

# Contact

For issues, suggestions, or inquiries, visit the repository at [GitHub
Repository](https://github.com/publiuspseudis/esadvpn) or contact
*Publius Pseudis* on Nostr.
