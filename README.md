Overview 
========

**ESADVPN (Everyday Swarm Assisted Decentralized VPN)** is a
peer-to-peer, decentralized Virtual Private Network designed to provide
secure, scalable, and resilient internet access. Built around a swarm
intelligence-based routing system, it ensures efficient peer discovery
and data relay without relying on centralized infrastructure. ESADVPN
integrates a TLS-enabled SOCKS proxy and advanced protocols like dynamic
proof-of-work and gossip-based peer synchronization for robust network
operation.

Key Features 
============

-   **TLS-Enabled SOCKS Proxy:** Securely routes encrypted traffic
    through the VPN, preventing plaintext data leaks.

-   **Swarm-Based Peer Discovery:** Uses a gossip protocol with
    anti-replay protection to synchronize network state efficiently.

-   **Dynamic Proof-of-Work (PoW):** Adapts difficulty dynamically to
    prevent Sybil attacks while maintaining network performance.

-   **Decentralized Routing:** Implements swarm intelligence algorithms
    for efficient packet forwarding and low-latency routes.

-   **Rate Limiting and Reputation Scoring:** Protects against abuse by
    monitoring and penalizing malicious peers while rewarding reliable
    nodes.

Quick Start 
===========

Prerequisites 
-------------

-   Java 17 or later.

-   Maven for dependency management.

-   Optional: A valid TLS certificate for production environments.

Building the Project 
--------------------

Clone the repository and build the project:

    git clone https://github.com/publiuspseudis/esadvpn.git
    cd esadvpn
    mvn clean package

Running ESADVPN 
---------------

Start ESADVPN in one of the following modes:

#### P2P Mode (First Node):

    java -jar target/esadvpn.jar p2p [port]

*Example: Start the first node on port 8942. SOCKS proxy will start on
port 8943.*

#### Connect Mode (Join Existing Network):

    java -jar target/esadvpn.jar connect [local-port] [peer-host] [peer-port]

*Example: Join an existing network via localhost on port 8942 and start
a SOCKS proxy on port 8945.*

Security Notes 
==============

-   All traffic routed through the SOCKS proxy must use encryption
    (e.g., HTTPS or TLS tunnels).

-   Peers must validate gossip messages using nonces and timestamps to
    prevent replay attacks.

-   Exit nodes are monitored for abuse with rate limiting and reputation
    scoring mechanisms.

Architecture Highlights 
=======================

-   **Swarm Router:** Ensures optimized routing using pheromone-based
    path selection.

-   **Gossip Protocol:** Synchronizes network state incrementally to
    reduce bandwidth usage.

-   **Virtual Network Interface:** Processes and injects IP packets for
    seamless integration with local applications.

-   **Buffer Pooling:** High-efficiency buffer management for packet
    processing under load.

Contributing 
============

We welcome contributions to ESADVPN! Follow these steps:

1.  Fork the repository on GitHub.

2.  Create a feature branch (`git checkout -b feature-name`).

3.  Commit your changes and open a pull request.

License 
=======

This project is licensed under the **GNU General Public License v3**.
See the `LICENSE` file for more details.

Contact
=======

For issues, suggestions, or inquiries, visit the repository at [GitHub
Repository](https://github.com/publiuspseudis/esadvpn) or contact
publius on nostr.
