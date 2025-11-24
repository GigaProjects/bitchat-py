#!/usr/bin/env python3
"""
Bitchat Terminal Chat Client
Based strictly on mesh-bit2.py logic for compatibility.
"""

import asyncio
import logging
import sys
import time
import struct
import hashlib
import signal
from typing import Dict, Optional, Set

# Cryptography
import nacl.signing
import nacl.encoding
import nacl.bindings

# Compression
try:
    import lz4.block
except ImportError:
    lz4 = None

# BLE
from bleak import BleakScanner, BleakClient
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

# --- CONFIGURATION ---
BITCHAT_SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"
BITCHAT_RX_CHAR_UUID = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d" 
BITCHAT_TX_CHAR_UUID = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"

# Protocol Constants
PACKET_VERSION = 0x01
PACKET_TYPE_ANNOUNCE = 0x01
PACKET_TYPE_MESSAGE = 0x02
PACKET_TTL = 0x07
FLAG_HAS_RECIPIENT = 0x01
FLAG_HAS_SIGNATURE = 0x02
FLAG_IS_COMPRESSED = 0x04
CANONICAL_TTL_FOR_SIGNING = 0x00
HEADER_SIZE = 14

# Logging setup - minimal for chat
logging.basicConfig(level=logging.ERROR, format="%(message)s")
logger = logging.getLogger("BitchatChat")

class BitchatBLEHandler:
    def __init__(self, loop: asyncio.AbstractEventLoop, nickname: str = "Anonymous"):
        self.connected_clients: Dict[str, BleakClient] = {}
        self.connecting_devices = set()
        self.seen_devices: Set[str] = set()
        self.peer_nicknames: Dict[str, str] = {}
        self.loop = loop
        self._stopping = False
        self.nickname = nickname
        self.scanner_task = None  # Track scanner task for cleanup
        
        # --- IDENTITY SETUP (Exact match to mesh-bit2.py) ---
        self.signing_key = nacl.signing.SigningKey.generate() 
        self.verify_key = self.signing_key.verify_key
        self.public_key_bytes = self.verify_key.encode(encoder=nacl.encoding.RawEncoder)
        
        self.x25519_private = nacl.bindings.crypto_box_keypair()[1]
        self.x25519_public = nacl.bindings.crypto_scalarmult_base(self.x25519_private)
        
        self.my_id = hashlib.sha256(self.public_key_bytes).digest()[:8]
        
        print(f"\n╔══════════════════════════════════════════════════════════════╗")
        print(f"║  Bitchat Terminal Chat - Connected as: {self.nickname:<22} ║")
        print(f"║  Your ID: {self.my_id.hex():<46} ║")
        print(f"╚══════════════════════════════════════════════════════════════╝\n")
        print("Scanning for peers...")

    def _pad_data(self, data: bytearray) -> bytearray:
        """PKCS7-style padding to optimal block size (matches MessagePadding.kt)"""
        block_sizes = [256, 512, 1024, 2048]
        target_size = len(data)
        for size in block_sizes:
            if len(data) + 16 <= size:
                target_size = size
                break
        
        if len(data) >= target_size:
            return data
            
        padding_needed = target_size - len(data)
        if padding_needed > 255:
            return data
            
        padding = bytes([padding_needed] * padding_needed)
        padded = bytearray(data)
        padded.extend(padding)
        return padded

    def _build_packet(self, type_byte, payload, recipient_id=None):
        """Builds a signed packet compliant with BinaryProtocol.kt"""
        header = bytearray()
        header.append(PACKET_VERSION)
        header.append(type_byte)
        header.append(PACKET_TTL)
        
        timestamp_ms = int(time.time() * 1000)
        header.extend(struct.pack('>Q', timestamp_ms))
        
        flags = FLAG_HAS_SIGNATURE
        if recipient_id:
            flags |= FLAG_HAS_RECIPIENT
        header.append(flags)
        
        header.extend(struct.pack('>H', len(payload)))
        
        # Build UNSIGNED packet (for signing)
        signing_header = bytearray(header)
        signing_header[2] = CANONICAL_TTL_FOR_SIGNING
        signing_flags = flags & ~FLAG_HAS_SIGNATURE
        signing_header[11] = signing_flags
        
        unsigned_packet = bytearray()
        unsigned_packet.extend(signing_header)
        unsigned_packet.extend(self.my_id)
        if recipient_id:
            unsigned_packet.extend(recipient_id[:8])
        unsigned_packet.extend(payload)
        
        # CRITICAL: Pad the unsigned packet BEFORE signing
        unsigned_packet_padded = self._pad_data(unsigned_packet)
        
        # Sign the PADDED unsigned packet
        signature = self.signing_key.sign(bytes(unsigned_packet_padded)).signature
        
        # Assemble Final Packet
        final = bytearray()
        final.extend(header)
        final.extend(self.my_id)
        if recipient_id:
            final.extend(recipient_id[:8])
        final.extend(payload)
        final.extend(signature)
        
        # Apply Padding to final packet
        final_padded = self._pad_data(final)
        
        return bytes(final_padded)

    async def connect_client(self, device: BLEDevice):
        """Connect to a BLE device with retry logic"""
        MAX_RETRIES = 3
        RETRY_DELAY = 2.0
        
        for attempt in range(MAX_RETRIES):
            client = BleakClient(device)
            try:
                await client.connect()
                if client.is_connected:
                    self.connected_clients[device.address] = client
                    print(f"[SYSTEM] Connected to peer at {device.address}")
                    
                    # Send Handshake (ANNOUNCE)
                    handshake_payload = bytearray()
                    # Tag 1: Name (Nickname)
                    handshake_payload.extend(b'\x01')
                    handshake_payload.append(len(self.nickname))
                    handshake_payload.extend(self.nickname.encode('utf-8'))
                    
                    # Tag 2: Noise Public Key
                    handshake_payload.extend(b'\x02')
                    handshake_payload.append(len(self.x25519_public))
                    handshake_payload.extend(self.x25519_public)
                    
                    # Tag 3: Signing Public Key
                    handshake_payload.extend(b'\x03')
                    handshake_payload.append(len(self.public_key_bytes))
                    handshake_payload.extend(self.public_key_bytes)
                    
                    packet = self._build_packet(PACKET_TYPE_ANNOUNCE, handshake_payload, recipient_id=b'\xff'*8)
                    await client.write_gatt_char(BITCHAT_RX_CHAR_UUID, packet, response=True)
                    
                    # Setup notification handler
                    await client.start_notify(BITCHAT_TX_CHAR_UUID, self._create_notification_handler(device.address))
                    
                    return
                    
            except Exception as e:
                try:
                    if client.is_connected:
                        await client.disconnect()
                except:
                    pass
                
                if attempt < MAX_RETRIES - 1:
                    delay = RETRY_DELAY * (2 ** attempt)
                    await asyncio.sleep(delay)
                    continue
                else:
                    break
        
        self.connecting_devices.discard(device.address)

    def _create_notification_handler(self, address):
        def handler(sender_handle: int, data: bytearray):
            try:
                if len(data) < HEADER_SIZE: return
                
                packet_type = data[1]
                flags = data[11]
                payload_len = struct.unpack('>H', data[12:14])[0]
                
                has_recipient = (flags & FLAG_HAS_RECIPIENT) != 0
                is_compressed = (flags & FLAG_IS_COMPRESSED) != 0
                
                offset = HEADER_SIZE
                
                # Sender ID
                sender_id = data[offset : offset+8]
                offset += 8
                short_id = sender_id.hex()[-8:]
                sender_hex = sender_id.hex()
                
                sender_nick = self.peer_nicknames.get(sender_hex, short_id)

                if has_recipient:
                    offset += 8 # Skip recipient ID
                    
                # Extract Payload
                raw_payload = data[offset : offset + payload_len]
                
                # Decompression
                final_text = ""
                if is_compressed and lz4:
                    try:
                        compressed_data = bytes(raw_payload[2:]) 
                        uncompressed_data = lz4.block.decompress(compressed_data, uncompressed_size=65536)
                        final_text = uncompressed_data.decode('utf-8', errors='ignore')
                    except Exception:
                        return 
                else:
                    final_text = raw_payload.decode('utf-8', errors='ignore')

                if packet_type == PACKET_TYPE_MESSAGE:
                    if final_text:
                        print(f"{sender_nick}: {final_text}")
                        sys.stdout.flush()
                
                elif packet_type == PACKET_TYPE_ANNOUNCE:
                    # Parse TLV to extract nickname
                    try:
                        tlv_offset = 0
                        while tlv_offset < len(raw_payload):
                            if tlv_offset + 2 > len(raw_payload): break
                            tag = raw_payload[tlv_offset]
                            length = raw_payload[tlv_offset + 1]
                            tlv_offset += 2
                            if tlv_offset + length > len(raw_payload): break
                            value = raw_payload[tlv_offset:tlv_offset + length]
                            tlv_offset += length
                            
                            if tag == 0x01: # Nickname
                                nickname = value.decode('utf-8', errors='ignore')
                                # Only announce if it's a new nickname for this peer
                                if self.peer_nicknames.get(sender_hex) != nickname:
                                    self.peer_nicknames[sender_hex] = nickname
                                    print(f"[SYSTEM] {nickname} ({short_id}) joined")
                                break
                    except:
                        pass

            except Exception as e:
                pass
        return handler

    async def send_message(self, message: str):
        """Send a message to all connected peers"""
        if not self.connected_clients:
            return
        
        try:
            packet = self._build_packet(PACKET_TYPE_MESSAGE, message.encode('utf-8'), b'\xff' * 8)
            
            disconnected_addrs = []
            sent_count = 0
            for addr, client in list(self.connected_clients.items()):
                try:
                    if not client.is_connected:
                        disconnected_addrs.append(addr)
                        continue
                    
                    await client.write_gatt_char(BITCHAT_RX_CHAR_UUID, packet, response=True)
                    sent_count += 1
                except Exception:
                    disconnected_addrs.append(addr)
            
            for addr in disconnected_addrs:
                if addr in self.connected_clients:
                    del self.connected_clients[addr]
            
            if sent_count > 0:
                print(f"{self.nickname} (you): {message}")
            
        except Exception:
            pass

    async def run_scanner(self):
        """Continuously scan for Bitchat devices using callback (Exact match to mesh-bit2.py)"""
        print("[SYSTEM] Scanning for Bitchat devices...")
        
        def detection_callback(device: BLEDevice, advertisement_data: AdvertisementData):
            if self._stopping: return
            
            # Filter by Service UUID exactly like mesh-bit2.py
            if BITCHAT_SERVICE_UUID.lower() in advertisement_data.service_uuids:
                if (device.address not in self.connected_clients and 
                    device.address not in self.connecting_devices):
                    
                    if device.address not in self.seen_devices:
                        self.seen_devices.add(device.address)
                        # print(f"[SYSTEM] Found peer: {device.address}")
                    
                    self.connecting_devices.add(device.address)
                    asyncio.create_task(self.connect_client(device))
        
        scanner = BleakScanner(detection_callback)
        await scanner.start()
        try:
            while not self._stopping:
                await asyncio.sleep(1)
        finally:
            await scanner.stop()

    async def monitor_connections(self):
        """Periodically check connection status to handle disconnects"""
        while not self._stopping:
            await asyncio.sleep(5)
            disconnected_addrs = []
            for addr, client in list(self.connected_clients.items()):
                if not client.is_connected:
                    disconnected_addrs.append(addr)
            
            for addr in disconnected_addrs:
                if addr in self.connected_clients:
                    del self.connected_clients[addr]
                    self.connecting_devices.discard(addr)
                    # print(f"[SYSTEM] Peer {addr} disconnected (detected by monitor)")

    async def input_loop(self):
        """Read messages from stdin"""
        print("\nType your messages and press Enter to send. Ctrl+C to exit.\n")
        while not self._stopping:
            try:
                line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
                line = line.strip()
                if line:
                    await self.send_message(line)
            except Exception:
                break

    async def stop(self):
        self._stopping = True
        print("\n[SYSTEM] Disconnecting...")
        
        # Cancel scanner immediately
        if self.scanner_task:
            self.scanner_task.cancel()
            try:
                await self.scanner_task
            except asyncio.CancelledError:
                pass
        
        tasks = []
        for client in list(self.connected_clients.values()):
            try:
                tasks.append(asyncio.create_task(client.disconnect()))
            except:
                pass
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self.connected_clients.clear()

async def main():
    loop = asyncio.get_event_loop()
    nickname = sys.argv[1] if len(sys.argv) > 1 else "Anonymous"
    
    chat = BitchatBLEHandler(loop, nickname=nickname)
    
    def signal_handler():
        asyncio.create_task(chat.stop())
        # Force exit if stuck
        asyncio.get_event_loop().call_later(2, sys.exit, 0)
    
    loop.add_signal_handler(signal.SIGINT, signal_handler)
    
    try:
        # Track the scanner task
        chat.scanner_task = asyncio.create_task(chat.run_scanner())
        
        await asyncio.gather(
            chat.scanner_task,
            chat.input_loop(),
            chat.monitor_connections()
        )
    except asyncio.CancelledError:
        pass
    finally:
        await chat.stop()
        print("[SYSTEM] Goodbye!")

if __name__ == "__main__":
    asyncio.run(main())
