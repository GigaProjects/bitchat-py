# bitchat-py (Lightweight Bitchat Client)

A minimal, single-file Python 3 client for the **Bitchat** decentralized BLE mesh protocol.

Designed to be lightweight and "hackable," this script is ideal for testing and automation. It allows you to broadcast and receive public messages without a heavy UI or complex installation.

## Quick Start

### 1. Setup Virtual Environment
It is recommended to run this in a dedicated virtual environment to keep dependencies clean.

```bash
# Create the virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate

# Install dependencies
pip install bleak pynacl lz4
```

### 2. Run the Client

You can run the client directly using the venv python executable, or after activating the environment.

```bash
# Syntax: ./venv/bin/python3 bitchat-client.py <YourNickname>
./venv/bin/python3 bitchat-client.py Alice
```

## Troubleshooting

Since this script interacts directly with low-level Bluetooth adapters, the hardware can sometimes get stuck. Use these commands to reset the state.

If you see connection errors or scanning hangs:

**Kill "zombie" processes:** If the script didn't exit cleanly, background processes might be holding the adapter.

```bash
pkill -f "python.*bitchat-client"
```

**Hard Reset Bluetooth:** If the adapter is completely unresponsive, restart the system service (requires sudo).
```bash
sudo systemctl restart bluetooth
```

## Alternatives

*   **This Project (bitchat-py):** Best for scripting, minimal resources, and creating bots/relays.
*   **[bitchat-python](https://github.com/kaganisildak/bitchat-python):** A fully-featured terminal application with a rich UI and more complex architecture.

## Note

This is a reference implementation. Capabilities are limited to public chat.
