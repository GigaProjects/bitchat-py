# bitchat-py (Python 3 Client)

A cross-platform, command-line implementation of the **Bitchat decentralized, peer-to-peer (P2P) mesh chat protocol** over Bluetooth Low Energy (BLE).

This client has limited capabilities (public chat only) but is **protocol-compatible** with the official Bitchat mobile apps. It is ideal for scripting, testing, and running as a dedicated relay node.

## Features

* **Language:** Pure Python 3 for scripting and easy extension.
* **Interface:** Simple, asynchronous command-line interface (CLI).
* **Use Case:** Ideal for **headless relay nodes** on Single Board Computers (SBCs) like Raspberry Pi.

## Installation

### Prerequisites

You need **Python 3.8+** and a system with native Bluetooth Low Energy support enabled.

### Dependencies

Install the required Python libraries using `pip`:

```bash
pip install bleak pynacl lz4
````

## Usage

Run the client with a nickname:

```bash
python bitchat_client.py "YourNickname"
```

Type your message and press **Enter** to broadcast to the public channel. Press **Ctrl+C** to quit.

## Note

This is a reference/testing client with limited capabilities (public chat only). **Do not use for highly sensitive communications.**

```
```
