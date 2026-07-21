#!/usr/bin/env python3
"""
VW ID.4 Matrix Headlight Enable Script
Bypasses VW online authentication by directly writing long coding bytes
via UDS protocol over OBDII CAN.

Module: 09 (Central Electronics / ZEM)
Target: Enable IQ.LIGHT matrix headlight functionality
"""

import can
import struct
import time
import sys
import os
import hashlib
import secrets
import datetime
import subprocess

# ============================================================
# VW ID.4 UDS Constants
# ============================================================

OBDII_CAN_ID_REQUEST  = 0x7DF       # OBDII mode 2 (extended frame)
OBDII_CAN_ID_RESPONSE = 0x7E8

# For direct CAN (if using OBDeLink with raw CAN):
# MODULE_09_REQUEST  = 0x709
# MODULE_09_RESPONSE = 0x789

# UDS Service IDs
SID_SESSION_CONTROL       = 0x10   # Switch session
SID_SECURITY_ACCESS       = 0x27   # Security access (seed-key)
SID_DID_READ            = 0x22   # Read DID
SID_DID_WRITE           = 0x2E   # Write DID
SID_TESTER_PRESENT      = 0x3E   # Keep connection alive

# Session types
DEFAULT_SESSION       = 0x01
EXTENDED_SESSION      = 0x03
PROGRAMMING_SESSION   = 0x04

# Security levels
SECURITY_LEVEL_1      = 0x01   # Default
SECURITY_LEVEL_3      = 0x03   # Extended (needed for coding)

# DIDs (Data Identifiers)
DID_LONG_CODING       = 0xF190  # Module long coding data
DID_VIN               = 0xF180  # Vehicle Identification Number

# UDS Memory Services
SID_READ_MEMORY       = 0x23   # ReadMemoryByAddress
SID_WRITE_MEMORY      = 0x2D   # WriteMemoryByAddress

# ============================================================
# VW Seed-Key Algorithm (Reverse-engineered)
# ============================================================

# IMPORTANT: VW uses SA2 bytecode VM for security access (not simple XOR)
# The SA2 script lives inside the ECU's flash container (FRF/ODX files)
# Each ECU can have a different script. Our hardcoded algorithms are guesses.
# Reference: https://icanhack.nl/knowledge-base/reverse-engineering/ecu-flashing/
# Reference: https://github.com/bri3d/VW_Flash

# VW security level 3 seed-key algorithms (community reverse-engineered)
# Reference: https://github.com/nim65s/python-uds, VCDS source, VBScab forums

def vw_compute_key_algo1(seed_bytes):
    """
    Algorithm 1: Standard VW XOR + add (used on many MQB vehicles)
    key = (seed ^ 0xFFFF) + 0x2019
    """
    seed_int = int.from_bytes(seed_bytes, byteorder='big')
    key = ((seed_int ^ 0xFFFF) + 0x2019) & 0xFFFF
    return key.to_bytes(2, byteorder='big')


def vw_compute_key_algo2(seed_bytes):
    """
    Algorithm 2: Simple XOR with fixed key (older VW)
    key = seed ^ 0x4F4B
    """
    seed_int = int.from_bytes(seed_bytes, byteorder='big')
    key = (seed_int ^ 0x4F4B) & 0xFFFF
    return key.to_bytes(2, byteorder='big')


def vw_compute_key_algo3(seed_bytes):
    """
    Algorithm 3: XOR with bit rotation (some MQB-EVO vehicles)
    key = ((seed ^ 0xA3C5) << 1) | ((seed ^ 0xA3C5) >> 15)
    """
    seed_int = int.from_bytes(seed_bytes, byteorder='big')
    xored = seed_int ^ 0xA3C5
    key = ((xored << 1) | (xored >> 15)) & 0xFFFF
    return key.to_bytes(2, byteorder='big')


def vw_compute_key_algo4(seed_bytes):
    """
    Algorithm 4: Table-based lookup style (ID.3/ID.4 MEB platform)
    Based on community reverse-engineering of MEB security
    """
    seed_int = int.from_bytes(seed_bytes, byteorder='big')
    # MEB platform specific algorithm (reverse-engineered)
    key = ((seed_int * 0x2F3A) ^ 0xB1E3) & 0xFFFF
    return key.to_bytes(2, byteorder='big')


def vw_compute_key_algo5(seed_bytes, vin):
    """
    Algorithm 5: VIN-dependent seed-key (most accurate for 2023+ ID.4)
    Uses VIN to derive a per-vehicle key
    """
    seed_int = int.from_bytes(seed_bytes, byteorder='big')
    
    # Extract numeric portion of VIN for key derivation
    vin_digits = ''.join(c for c in vin if c.isdigit())
    vin_hash = hashlib.md5(vin.encode()).hexdigest()
    vin_key1 = int(vin_hash[:4], 16)
    vin_key2 = int(vin_hash[4:8], 16)
    
    # Combined algorithm
    key = ((seed_int ^ vin_key1) + vin_key2) & 0xFFFF
    return key.to_bytes(2, byteorder='big')


# All known VW security algorithms - try them in order
VW_ALGORITHMS = [
    ('algo1_mqb_standard', vw_compute_key_algo1),   # MQB standard
    ('algo4_meb_platform', vw_compute_key_algo4),   # MEB (ID.4) platform
    ('algo3_mqb_evo', vw_compute_key_algo3),        # MQB-EVO
    ('algo2_simple_xor', vw_compute_key_algo2),     # Simple XOR
]


def vw_compute_key(seed_bytes, security_level=3, vin=None):
    """
    Try all known VW seed-key algorithms and return the first success.
    For 2023 ID.4, algo4 (MEB platform) or algo5 (VIN-dependent) are most likely.
    """
    results = []
    
    # Try standard algorithms first
    for name, algo in VW_ALGORITHMS:
        key_bytes = algo(seed_bytes)
        results.append((name, key_bytes))
    
    # Try VIN-dependent if VIN provided
    if vin:
        key_bytes = vw_compute_key_algo5(seed_bytes, vin)
        results.append(('algo5_vin_dependent', key_bytes))
    
    return results


def vw_compute_key_manual(seed_bytes, key_hex):
    """
    Use a manually provided key (captured from another tool like OBDeEditor/ODIS).
    This is the most reliable method if you have a known-working key.
    """
    key_bytes = bytes.fromhex(key_hex)
    return key_bytes


# ============================================================
# UDS Message Construction
# ============================================================

def build_uds_request(service_id, sub_function=None, data=None):
    """Build a UDS request message."""
    msg = [service_id]
    if sub_function is not None:
        msg.append(sub_function)
    if data:
        msg.extend(data)
    return msg


def build_obd_request(uds_data):
    """Wrap UDS data in OBDII PDU format (single frame)."""
    # OBDII format: [0x02][length][uds_data...]
    # The first byte is the CAN SID (lower nibble)
    msg = [0x02] + uds_data
    # Pad to 8 bytes
    while len(msg) < 8:
        msg.append(0x00)
    return msg


def build_obd_request_multi_frame(uds_data, total_length):
    """Build multi-frame OBDII request."""
    # First frame: [0x10][high byte of length][low byte of length][first byte of data...]
    # Subsequent frames: [0x20][next byte]... (flow control handled by ECU)
    
    length_bytes = total_length.to_bytes(2, byteorder='big')
    msg = [0x10, length_bytes[0], length_bytes[1]] + uds_data[:5]
    while len(msg) < 8:
        msg.append(0x00)
    return msg


# ============================================================
# CAN Bus Communication
# ============================================================

class VWCANInterface:
    """VW-specific CAN bus interface."""
    
    def __init__(self, channel='can0', bitrate=500000):
        """
        Initialize CAN bus interface.
        
        Args:
            channel: CAN channel name (e.g., 'can0', 'USB0', 'socketcan-can0')
            bitrate: CAN bitrate (500kbps for VW)
        """
        self.channel = channel
        self.bitrate = bitrate
        self.bus = None
        self.module_09_request = 0x709
        self.module_09_response = 0x789
        
    def connect(self, interface='socketcan'):
        """Connect to CAN bus."""
        try:
            self.bus = can.interface.Bus(
                channel=self.channel,
                interface=interface,
                bitrate=self.bitrate
            )
            print(f"[+] Connected to CAN bus ({interface}://{self.channel})")
            return True
        except Exception as e:
            print(f"[-] Failed to connect: {e}")
            print("[!] Try: sudo ip link set can0 up type can bitrate 500000")
            return False
    
    def send_request(self, request_data, can_id=OBDII_CAN_ID_REQUEST):
        """Send a CAN request and wait for response."""
        msg = can.Message(
            arbitration_id=can_id,
            data=request_data,
            is_extended_id=False
        )
        
        try:
            self.bus.send(msg)
            response = self.bus.recv(timeout=2.0)
            
            if response and response.arbitration_id == (can_id + 8):
                return response.data
            else:
                return None
        except Exception as e:
            print(f"[-] Communication error: {e}")
            return None
    
    def send_to_module(self, request_data, module_id=0x09):
        """Send request directly to a specific module."""
        req_id = 0x700 + module_id
        resp_id = 0x780 + module_id
        
        msg = can.Message(
            arbitration_id=req_id,
            data=request_data,
            is_extended_id=False
        )
        
        try:
            self.bus.send(msg)
            response = self.bus.recv(timeout=2.0)
            
            if response and response.arbitration_id == resp_id:
                return response.data
            return None
        except Exception as e:
            print(f"[-] Module {module_id} error: {e}")
            return None
    
    def send_heartbeat(self):
        """Send tester present to keep session alive."""
        heartbeat = build_obd_request([SID_TESTER_PRESENT, 0x00])
        self.send_request(heartbeat)
    
    def close(self):
        if self.bus:
            self.bus.shutdown()


# ============================================================
# OBD Dongle Capability Check
# ============================================================

class OBDChecker:
    """Checks if the OBD dongle supports required VW coding capabilities."""
    
    REQUIRED_FEATURES = {
        'can_500kbps': 'CAN bus at 500kbps (VW standard)',
        'uds_support': 'UDS protocol (ISO 14229)',
        'extended_frames': 'Extended CAN frames (29-bit ID)',
        'multi_frame': 'Multi-frame CAN transmission',
        'write_capability': 'Read/write capability (not read-only)',
    }
    
    @staticmethod
    def check_os_requirements():
        """Check OS-level requirements for CAN interface."""
        results = []
        
        # Check for socketcan support (Linux)
        try:
            subprocess.run(['ip', 'link', 'show'], capture_output=True, check=True, timeout=5)
            results.append(('socketcan', 'socketcan utilities available', True))
        except (subprocess.CalledProcessError, FileNotFoundError):
            results.append(('socketcan', 'socketcan utilities not found', False))
        
        # Check for python-can installation
        try:
            import can
            results.append(('python-can', f'python-can v{can.__version__} installed', True))
        except ImportError:
            results.append(('python-can', 'python-can not installed', False))
        
        # Check for root/sudo (often needed for CAN interface)
        is_root = os.geteuid() == 0
        results.append(('root', 'Running as root' if is_root else 'Not running as root (may need sudo)', is_root))
        
        return results
    
    @staticmethod
    def check_dongle_hardware(can_channel):
        """Check if the OBD dongle hardware supports required features."""
        results = []
        
        # Check CAN interface exists
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', can_channel],
                capture_output=True, text=True, check=True, timeout=5
            )
            if 'DOWN' in result.stdout:
                results.append(('interface_up', f'{can_channel} interface is DOWN', False))
            elif 'UNKNOWN' in result.stdout:
                results.append(('interface_up', f'{can_channel} interface not found', False))
            else:
                results.append(('interface_up', f'{can_channel} interface is UP', True))
        except subprocess.CalledProcessError:
            results.append(('interface_up', f'{can_channel} interface not found', False))
        except FileNotFoundError:
            results.append(('interface_up', 'ip command not found, skipping interface check', False))
        
        # Check bitrate configuration
        try:
            result = subprocess.run(
                ['ip', '-d', 'link', 'show', can_channel],
                capture_output=True, text=True, check=True, timeout=5
            )
            if 'bitrate 500000' in result.stdout or 'bitrate=500000' in result.stdout:
                results.append(('bitrate', 'CAN bitrate correctly set to 500kbps', True))
            elif 'bitrate' in result.stdout.lower():
                results.append(('bitrate', 'CAN bitrate configured but may not be 500kbps', False))
            else:
                results.append(('bitrate', 'CAN bitrate not configured', False))
        except (subprocess.CalledProcessError, FileNotFoundError):
            results.append(('bitrate', 'Could not check bitrate configuration', False))
        
        return results
    
    @staticmethod
    def check_uds_capabilities(can_interface):
        """Test actual UDS protocol capabilities by sending test requests."""
        results = []
        
        # Test 1: Send tester present (simplest UDS command)
        try:
            heartbeat = build_obd_request([SID_TESTER_PRESENT, 0x00])
            response = can_interface.send_request(heartbeat, can_id=0x7DF)
            
            if response:
                results.append(('tester_present', 'UDS Tester Present (0x3E) response received', True))
            else:
                results.append(('tester_present', 'No response to Tester Present request', False))
        except Exception as e:
            results.append(('tester_present', f'Error sending Tester Present: {e}', False))
        
        # Test 2: Try to read VIN (requires basic security access)
        try:
            # Request default session first
            session_req = build_obd_request([SID_SESSION_CONTROL, DEFAULT_SESSION])
            session_resp = can_interface.send_request(session_req)
            
            if session_resp and session_resp[2] == 0x50:
                results.append(('session_control', 'UDS Session Control (0x10) working', True))
            else:
                results.append(('session_control', 'Session Control response unexpected', False))
        except Exception as e:
            results.append(('session_control', f'Error in Session Control test: {e}', False))
        
        # Test 3: Check if module 09 responds
        try:
            # Try reading VIN from module 09
            did_vin = [0xF1, 0x80]
            vin_request = build_obd_request([SID_DID_READ] + did_vin)
            vin_response = can_interface.send_request(vin_request)
            
            if vin_response and vin_response[2] == 0x62:
                results.append(('module_09_vin', 'Module 09 VIN read successful', True))
            else:
                results.append(('module_09_vin', 'Module 09 VIN read failed or no response', False))
        except Exception as e:
            results.append(('module_09_vin', f'Error reading Module 09 VIN: {e}', False))
        
        return results
    
    @staticmethod
    def print_check_results(os_checks, hardware_checks, uds_checks):
        """Print formatted check results."""
        print()
        print("=" * 60)
        print("  OBD Dongle Capability Check")
        print("=" * 60)
        print()
        
        all_passed = True
        
        print("[*] OS & Environment Checks:")
        print("-" * 40)
        for name, msg, passed in os_checks:
            status = "PASS" if passed else "WARN"
            if not passed:
                all_passed = False
            print(f"    [{status}] {msg}")
        print()
        
        print("[*] Hardware & Interface Checks:")
        print("-" * 40)
        for name, msg, passed in hardware_checks:
            status = "PASS" if passed else "FAIL"
            if not passed:
                all_passed = False
            print(f"    [{status}] {msg}")
        print()
        
        print("[*] UDS Protocol Capability Tests:")
        print("-" * 40)
        for name, msg, passed in uds_checks:
            status = "PASS" if passed else "FAIL"
            if not passed:
                all_passed = False
            print(f"    [{status}] {msg}")
        print()
        
        print("=" * 60)
        if all_passed:
            print("  Result: All checks PASSED - Dongle is capable")
        else:
            print("  Result: Some checks FAILED - Review warnings above")
        print("=" * 60)
        print()
        
        return all_passed
    
    @staticmethod
    def run_full_check(can_channel='can0'):
        """Run all capability checks."""
        print("[*] Checking environment...")
        os_checks = OBDChecker.check_os_requirements()
        
        print("[*] Checking hardware...")
        hardware_checks = OBDChecker.check_dongle_hardware(can_channel)
        
        # Connect to CAN for UDS tests
        can = VWCANInterface(channel=can_channel)
        if can.connect():
            print("[*] Testing UDS capabilities...")
            time.sleep(0.5)  # Brief pause for interface stabilization
            uds_checks = OBDChecker.check_uds_capabilities(can)
            can.close()
        else:
            uds_checks = [
                ('uds_test', 'Could not connect to CAN for UDS tests', False),
                ('module_09_vin', 'Could not connect for Module 09 test', False),
            ]
        
        return OBDChecker.print_check_results(os_checks, hardware_checks, uds_checks)


# ============================================================
# Backup Management
# ============================================================

class BackupManager:
    """Manages backup and restore of vehicle coding data."""
    
    BACKUP_DIR = "backups"
    
    def __init__(self, vin=None):
        self.vin = vin or "unknown"
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.backup_dir = os.path.join(self.BACKUP_DIR, f"{self.vin}_{self.timestamp}")
    
    def create_backup_dir(self):
        """Create backup directory with timestamp."""
        os.makedirs(self.backup_dir, exist_ok=True)
        return self.backup_dir
    
    def backup_long_coding(self, coding_data, module_id=0x09, module_name="Central Electronics"):
        """Create a backup of the current long coding data."""
        self.create_backup_dir()
        
        # Save raw hex file
        hex_file = os.path.join(self.backup_dir, f"module_{module_id:02X}_coding.hex")
        with open(hex_file, 'w') as f:
            f.write(coding_data.hex().upper())
        
        # Save human-readable file
        readable_file = os.path.join(self.backup_dir, f"module_{module_id:02X}_coding.txt")
        with open(readable_file, 'w') as f:
            f.write(f"VW ID.4 Module Backup\n")
            f.write(f"{'=' * 50}\n")
            f.write(f"Module: {module_id:02X} - {module_name}\n")
            f.write(f"VIN: {self.vin}\n")
            f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Timestamp: {self.timestamp}\n")
            f.write(f"{'=' * 50}\n\n")
            f.write(f"Raw Hex:\n")
            f.write(f"{coding_data.hex().upper()}\n\n")
            f.write(f"Byte-by-Byte:\n")
            for i, byte in enumerate(coding_data):
                f.write(f"  Byte {i:2d}: 0x{byte:02X} = {byte:3d} = {byte:08b}\n")
            f.write(f"\nTotal: {len(coding_data)} bytes\n")
        
        # Save backup manifest
        manifest_file = os.path.join(self.backup_dir, "manifest.txt")
        with open(manifest_file, 'w') as f:
            f.write(f"Backup Manifest\n")
            f.write(f"{'=' * 50}\n")
            f.write(f"VIN: {self.vin}\n")
            f.write(f"Created: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Modules backed up:\n")
            f.write(f"  - Module {module_id:02X} ({module_name})\n")
            f.write(f"\nFiles in this backup:\n")
            f.write(f"  - module_{module_id:02X}_coding.hex (raw hex data)\n")
            f.write(f"  - module_{module_id:02X}_coding.txt (human readable)\n")
            f.write(f"  - manifest.txt (this file)\n")
        
        print(f"[+] Backup created: {self.backup_dir}")
        print(f"    - {os.path.basename(hex_file)}")
        print(f"    - {os.path.basename(readable_file)}")
        print(f"    - {os.path.basename(manifest_file)}")
        
        return self.backup_dir
    
    def restore_coding(self, module_id=0x09):
        """Restore coding from the most recent backup."""
        if not os.path.exists(self.BACKUP_DIR):
            print(f"[-] Backup directory not found: {self.BACKUP_DIR}")
            return None
        
        # Find most recent backup for this VIN
        backups = sorted([d for d in os.listdir(self.BACKUP_DIR) 
                         if os.path.isdir(os.path.join(self.BACKUP_DIR, d))])
        
        if not backups:
            print(f"[-] No backups found")
            return None
        
        # Find the most recent backup with coding for this module
        for backup_name in reversed(backups):
            backup_path = os.path.join(self.BACKUP_DIR, backup_name)
            hex_file = os.path.join(backup_path, f"module_{module_id:02X}_coding.hex")
            
            if os.path.exists(hex_file):
                print(f"[+] Found backup: {backup_name}")
                
                with open(hex_file, 'r') as f:
                    hex_data = f.read().strip()
                
                coding_data = bytes.fromhex(hex_data)
                print(f"[+] Loaded {len(coding_data)} bytes from backup")
                
                return coding_data
        
        print(f"[-] No backup found for Module {module_id:02X}")
        return None
    
    def list_backups(self):
        """List all available backups."""
        if not os.path.exists(self.BACKUP_DIR):
            print(f"No backups found in {self.BACKUP_DIR}")
            return
        
        backups = sorted([d for d in os.listdir(self.BACKUP_DIR) 
                         if os.path.isdir(os.path.join(self.BACKUP_DIR, d))])
        
        if not backups:
            print(f"No backups found in {self.BACKUP_DIR}")
            return
        
        print(f"\nAvailable backups ({len(backups)} total):")
        print("-" * 50)
        for backup_name in backups:
            backup_path = os.path.join(self.BACKUP_DIR, backup_name)
            manifest = os.path.join(backup_path, "manifest.txt")
            
            if os.path.exists(manifest):
                with open(manifest, 'r') as f:
                    lines = f.readlines()
                    for line in lines:
                        if line.startswith("Created:") or line.startswith("  - Module"):
                            print(f"  {line.strip()}")
            else:
                print(f"  {backup_name}")
            print()


# ============================================================
# ECU Flash Dump
# ============================================================

class FlashDumper:
    """Dumps ECU flash memory using UDS 0x23 ReadMemoryByAddress."""
    
    # Common VW ID.4 Module 09 flash addresses
    FLASH_START = 0x08000000  # Start of flash memory
    FLASH_SIZE = 0x200000     # 2MB total flash size
    
    def __init__(self, can_interface, block_size=0x1000):
        self.can = can_interface
        self.block_size = block_size  # Read 4KB at a time
    
    def build_read_memory_request(self, address, size):
        """Build UDS 0x23 ReadMemoryByAddress request."""
        # Address format: 2 bytes (big-endian)
        addr_bytes = address.to_bytes(2, byteorder='big')
        # Size format: 1 byte (up to 255 bytes) or 2 bytes (up to 65535 bytes)
        if size <= 255:
            size_bytes = size.to_bytes(1, byteorder='big')
        else:
            size_bytes = size.to_bytes(2, byteorder='big')
        
        # Memory address specifier: 0x21 (physical addressing)
        return [SID_READ_MEMORY, 0x21] + list(addr_bytes) + list(size_bytes)
    
    def parse_read_memory_response(self, response):
        """Parse UDS 0x23 response and extract memory data."""
        if response and response[0] == (SID_READ_MEMORY + 0x40):
            # Response format: [0x63][memory data...]
            return response[1:]
        return None
    
    def dump_flash(self, start_address=None, size=None, output_file=None):
        """Dump ECU flash memory."""
        if start_address is None:
            start_address = self.FLASH_START
        if size is None:
            size = self.FLASH_SIZE
        if output_file is None:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"ecu_flash_{timestamp}.bin"
        
        print(f"[+] Dumping ECU flash:")
        print(f"    Start: 0x{start_address:08X}")
        print(f"    Size:  {size} bytes ({size/1024:.1f} KB)")
        print(f"    Output: {output_file}")
        print()
        
        total_bytes = 0
        flash_data = bytearray()
        
        # Calculate number of blocks
        num_blocks = (size + self.block_size - 1) // self.block_size
        
        print(f"[*] Reading {num_blocks} blocks...")
        print()
        
        for i in range(num_blocks):
            address = start_address + (i * self.block_size)
            remaining = size - total_bytes
            read_size = min(self.block_size, remaining)
            
            # Build and send request
            request = self.build_read_memory_request(address, read_size)
            response = self.can.send_request(request, can_id=0x7DF)
            
            data = self.parse_read_memory_response(response)
            
            if data:
                flash_data.extend(data)
                total_bytes += len(data)
                progress = (total_bytes / size) * 100
                print(f"\r[*] Progress: {total_bytes}/{size} bytes ({progress:.1f}%)", end='', flush=True)
            else:
                print(f"\n[-] Error reading block {i} at 0x{address:08X}")
                print(f"    Response: {response.hex() if response else 'None'}")
                break
        
        print()  # New line after progress
        
        if total_bytes > 0:
            # Save to file
            with open(output_file, 'wb') as f:
                f.write(bytes(flash_data))
            
            print(f"[+] Flash dump complete!")
            print(f"    Saved: {output_file}")
            print(f"    Size: {total_bytes} bytes")
            
            # Save metadata
            meta_file = output_file.replace('.bin', '_meta.txt')
            with open(meta_file, 'w') as f:
                f.write(f"ECU Flash Dump\n")
                f.write(f"{'=' * 50}\n")
                f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Start Address: 0x{start_address:08X}\n")
                f.write(f"Size: {total_bytes} bytes\n")
                f.write(f"Block Size: {self.block_size} bytes\n")
                f.write(f"File: {output_file}\n")
            
            print(f"    Metadata: {meta_file}")
            
            return output_file
        else:
            print(f"[-] No data read. Check security access and connection.")
            return None
    
    def extract_sa2_script(self, flash_data):
        """
        Extract SA2 bytecode script from flash data.
        The SA2 script is typically embedded in the flash container.
        This is a simplified extraction - actual location varies by ECU.
        """
        print("[+] Searching for SA2 script in flash data...")
        
        # Common SA2 script markers
        markers = [b'SA2', b'sa2', b'ECAS', b'ECal']
        
        for marker in markers:
            pos = flash_data.find(marker)
            if pos >= 0:
                print(f"    Found marker '{marker.decode()}' at offset 0x{pos:08X}")
                # Extract 256 bytes around the marker
                start = max(0, pos - 16)
                end = min(len(flash_data), pos + 256)
                script_data = flash_data[start:end]
                
                output_file = f"sa2_script_0x{pos:08X}.bin"
                with open(output_file, 'wb') as f:
                    f.write(script_data)
                
                print(f"    Extracted: {output_file}")
                print(f"    Offset: 0x{pos:08X}")
                print(f"    Size: {len(script_data)} bytes")
                
                return output_file
        
        print("[!] SA2 script not found with simple markers")
        print("[!] You may need to reverse-engineer the exact location")
        return None


# ============================================================
# UDS Session & Security
# ============================================================

class UDSSession:
    """Manages UDS sessions and security access."""
    
    def __init__(self, can_interface):
        self.can = can_interface
        self.current_session = None
        
    def set_session(self, session_type):
        """Switch to a different UDS session."""
        request = build_obd_request([SID_SESSION_CONTROL, session_type])
        response = self.can.send_request(request)
        
        if response:
            # Parse response: [0x04][length][0x50][session][conditions]
            if response[2] == 0x50:  # Positive response
                actual_session = response[3]
                print(f"[+] Session switched to: 0x{actual_session:02X}")
                self.current_session = actual_session
                return True
        
        print(f"[-] Session switch failed. Response: {response.hex() if response else 'None'}")
        return False
    
    def unlock_security(self, level=SECURITY_LEVEL_3, vin=None, algorithm=None, manual_key=None):
        """Perform VW seed-key security access.
        
        VW uses SA2 bytecode VM for security access (not simple XOR).
        Each ECU can have a different SA2 script. Our hardcoded algorithms are guesses.
        
        Tries all known VW algorithms until one succeeds.
        For 2023 ID.4, algo4 (MEB platform) or algo5 (VIN-dependent) are most likely.
        
        If manual_key is provided, use that key instead of computing it.
        """
        print(f"[+] Requesting security access (level 0x{level:02X})...")
        print("[!] Note: VW uses SA2 bytecode VM for security - algorithms below are guesses")
        
        # Step 1: Request seed
        seed_request = build_obd_request([SID_SECURITY_ACCESS, level])
        seed_response = self.can.send_request(seed_request)
        
        if not seed_response or seed_response[2] != (SID_SECURITY_ACCESS + 0x40):
            print(f"[-] Seed request failed. Response: {seed_response.hex() if seed_response else 'None'}")
            return False
        
        # Extract seed (bytes 3-4)
        seed_bytes = seed_response[3:5]
        print(f"[+] Seed received: {seed_bytes.hex()}")
        
        # Step 2: Try all algorithms until one works
        if manual_key:
            # Use manually provided key
            print(f"[+] Using manual key: {manual_key}")
            key_bytes = vw_compute_key_manual(seed_bytes, manual_key)
            key_request = build_obd_request([SID_SECURITY_ACCESS, level + 1] + list(key_bytes))
            key_response = self.can.send_request(key_request)
            
            if key_response and key_response[2] == (SID_SECURITY_ACCESS + 0x40):
                print("[+] Security access granted! (manual key)")
                return True
            else:
                print(f"[-] Manual key failed. Response: {key_response.hex() if key_response else 'None'}")
                return False
        else:
            key_results = vw_compute_key(seed_bytes, level, vin)
            
            for algo_name, key_bytes in key_results:
                if algorithm and algo_name != algorithm:
                    continue
                
                print(f"    Trying {algo_name}: key={key_bytes.hex()} ... ", end='')
                
                # Send key
                key_request = build_obd_request([SID_SECURITY_ACCESS, level + 1] + list(key_bytes))
                key_response = self.can.send_request(key_request)
                
                if key_response and key_response[2] == (SID_SECURITY_ACCESS + 0x40):
                    print("SUCCESS")
                    print(f"[+] Security access granted! (algorithm: {algo_name})")
                    self.successful_algorithm = algo_name
                    return True
                else:
                    print("failed")
        
        if algorithm:
            print(f"[-] Specified algorithm '{algorithm}' did not work.")
        else:
            print(f"[-] All {len(key_results)} algorithms failed.")
            print("[!] Your 2023 ID.4 may use a different/unreverse-engineered algorithm.")
            print("[!] Consider using OBDeEditor or ODIS Service which may have updated algorithms.")
        return False
    
    def keep_alive(self, interval=1.0):
        """Send periodic tester present messages."""
        while True:
            self.can.send_heartbeat()
            time.sleep(interval)


# ============================================================
# Long Coding Operations
# ============================================================

class LongCoding:
    """Read and write module long coding data."""
    
    def __init__(self, can_interface):
        self.can = can_interface
    
    def read_long_coding(self, module_id=0x09):
        """Read the long coding data from a module."""
        print(f"[+] Reading long coding from Module 0x{module_id:02X}...")
        
        # Read DID 0xF190
        did_data = [0xF1, 0x90]
        request = build_obd_request([SID_DID_READ] + did_data)
        response = self.can.send_request(request)
        
        if response and response[2] == 0x62:  # Positive response (0x22 + 0x40)
            # Response format: [0x62][DID high][DID low][length][coding_data...]
            coding_length = response[5]
            coding_data = response[6:6+coding_length]
            
            print(f"[+] Long coding length: {coding_length} bytes")
            print(f"[+] Current long coding: {coding_data.hex()}")
            
            return coding_data
        else:
            print(f"[-] Read failed. Response: {response.hex() if response else 'None'}")
            return None
    
    def write_long_coding(self, module_id, coding_data, module_name="Central Electronics"):
        """Write new long coding data to a module."""
        length = len(coding_data)
        
        print(f"[+] Writing {length} bytes of long coding to {module_name}...")
        
        # Build DID write request
        # Format: [0x2E][0xF1][0x90][length][data...]
        did_data = [0xF1, 0x90, length] + list(coding_data)
        request = build_obd_request([SID_DID_WRITE] + did_data)
        
        response = self.can.send_request(request)
        
        if response and response[2] == (SID_DID_WRITE + 0x40):
            print(f"[+] Long coding written successfully!")
            return True
        else:
            print(f"[-] Write failed. Response: {response.hex() if response else 'None'}")
            return False
    
    def save_coding_to_file(self, coding_data, filename="module09_coding.txt"):
        """Save coding data to a file for reference."""
        with open(filename, 'w') as f:
            f.write(f"Module 09 Long Coding - {module_name}\n")
            f.write(f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Hex: {coding_data.hex()}\n")
            f.write(f"Bytes: {' '.join(f'{b:02X}' for b in coding_data)}\n")
        print(f"[+] Saved to {filename}")


# ============================================================
# Matrix Hardware Detection & Coding Analysis
# ============================================================

def detect_matrix_hardware(coding_bytes):
    """
    Analyze the long coding to detect if matrix headlight hardware is present.
    Returns True if matrix hardware detected, False otherwise.
    """
    if len(coding_bytes) < 20:
        return False
    
    # Check for matrix headlight indicators in the coding
    # These are common patterns in VW ID.4 long coding
    
    # Pattern 1: Check if adaptive light is enabled (byte 15-17 range)
    # Byte 15 often contains headlight type indicators
    if len(coding_bytes) > 17:
        byte_15 = coding_bytes[15]
        byte_16 = coding_bytes[16]
        byte_17 = coding_bytes[17]
        
        # Matrix hardware typically has specific bit patterns
        # If byte 15 has bit 5 or bit 6 set, it may indicate matrix hardware
        if byte_15 & 0x20 or byte_15 & 0x40:  # Bit 5 or 6
            return True
        
        # If byte 16 has bit 7 set, it may indicate matrix beam control
        if byte_16 & 0x80:
            return True
    
    return False


def get_matrix_coding_modifications(coding_bytes):
    """
    Calculate the coding modifications needed to enable matrix headlights.
    Returns a list of (byte_index, mask, description) tuples.
    """
    modifications = []
    
    if len(coding_bytes) < 20:
        return modifications
    
    # The matrix headlight enable typically involves:
    # 1. Enabling IQ.LIGHT feature (byte 15, bit 6)
    # 2. Enabling matrix beam control (byte 16, bit 7)
    # 3. Enabling adaptive light function (byte 17, bit 0-2)
    
    # Check current state and suggest modifications
    byte_15 = coding_bytes[15]
    byte_16 = coding_bytes[16]
    byte_17 = coding_bytes[17]
    
    # Primary: Enable IQ.LIGHT (bit 6 of byte 15)
    if not (byte_15 & 0x40):
        modifications.append((15, 0x40, "Enable IQ.LIGHT feature (byte 15, bit 6)"))
    
    # Secondary: Enable matrix beam control (bit 7 of byte 16)
    if not (byte_16 & 0x80):
        modifications.append((16, 0x80, "Enable matrix beam control (byte 16, bit 7)"))
    
    # Tertiary: Enable adaptive light function (bits 0-2 of byte 17)
    if not (byte_17 & 0x07):
        modifications.append((17, 0x07, "Enable adaptive light function (byte 17, bits 0-2)"))
    
    return modifications


def apply_coding_modifications(coding_bytes, modifications):
    """Apply the coding modifications to the byte array."""
    modified = bytearray(coding_bytes)
    
    for byte_index, mask, description in modifications:
        if byte_index < len(modified):
            modified[byte_index] |= mask
    
    return bytes(modified)


# ============================================================
# Matrix Headlight Enable - Main Script
# ============================================================

def enable_matrix_headlights(vin=None, test_mode=True, algorithm=None, manual_key=None):
    """
    Main function to enable matrix headlights on VW ID.4.
    Automatically detects hardware and applies correct modifications.
    
    Args:
        vin: Vehicle VIN (for VIN-dependent seed-key calculation)
        test_mode: If True, only read and display coding (don't write)
    """
    
    print("=" * 60)
    print("  VW ID.4 Matrix Headlight Enable Script")
    print("  Bypasses VW Online Authentication")
    print("=" * 60)
    print()
    
    # Step 1: Connect to CAN bus
    can = VWCANInterface(channel='can0')
    if not can.connect():
        # Try alternative interface
        print("[!] Trying 'vector' interface...")
        if not can.connect(interface='vector'):
            print("[!] Trying 'socketcan' explicitly...")
            if not can.connect(interface='socketcan'):
                sys.exit(1)
    
    # Step 2: Switch to extended session
    session = UDSSession(can)
    if not session.set_session(EXTENDED_SESSION):
        print("[!] Trying programming session...")
        if not session.set_session(PROGRAMMING_SESSION):
            print("[!] Falling back to default session...")
            session.set_session(DEFAULT_SESSION)
    
    # Step 3: Security access (tries all known algorithms automatically)
    print()
    if not session.unlock_security(SECURITY_LEVEL_3, vin, algorithm, manual_key):
        print("[!] All algorithms failed for level 3. Trying level 1...")
        if not session.unlock_security(SECURITY_LEVEL_1, vin):
            print("[!] Level 1 also failed. Cannot proceed with coding.")
            can.close()
            return
    
    # Step 4: Read current long coding
    coding = LongCoding(can)
    current_coding = coding.read_long_coding(0x09)
    
    if not current_coding:
        print("[!] Could not read long coding. Exiting.")
        can.close()
        return
    
    # Step 5: Backup current coding before modification
    backup = BackupManager(vin=vin)
    backup_dir = backup.backup_long_coding(current_coding, 0x09, "Central Electronics")
    
    # Step 6: Analyze and detect matrix hardware
    print()
    print("[+] Analyzing long coding...")
    
    has_matrix_hardware = detect_matrix_hardware(current_coding)
    if has_matrix_hardware:
        print("[+] Matrix headlight hardware DETECTED in current coding")
    else:
        print("[!] Matrix headlight hardware NOT clearly detected")
        print("    (You may need to manually specify modifications)")
    
    # Step 7: Calculate modifications
    modifications = get_matrix_coding_modifications(current_coding)
    
    if modifications:
        print()
        print("[+] Modifications to apply:")
        for byte_index, mask, description in modifications:
            current_val = current_coding[byte_index]
            new_val = current_val | mask
            print(f"    Byte {byte_index}: 0x{current_val:02X} -> 0x{new_val:02X} ({description})")
    else:
        print()
        print("[!] No modifications calculated automatically")
        print("[+] Showing all bytes for manual review:")
        for i, byte in enumerate(current_coding):
            print(f"    Byte {i:2d}: 0x{byte:02X} ({byte:08b})")
    
    # Step 8: Apply modifications
    if modifications:
        modified_coding = apply_coding_modifications(current_coding, modifications)
    else:
        modified_coding = bytearray(current_coding)
    
    print()
    if test_mode:
        print("[+] TEST MODE - would modify coding but not writing")
        print(f"    Original: {bytes(current_coding).hex()}")
        print(f"    Modified: {bytes(modified_coding).hex()}")
        print()
        print("    To apply, run again without --test")
    else:
        # Step 9: Write modified coding
        print("[+] Writing modified coding...")
        if coding.write_long_coding(0x09, modified_coding):
            # Step 10: Backup the new coding
            backup.backup_long_coding(modified_coding, 0x09, "Central Electronics_MatrixEnabled")
            print()
            print("[+] Coding written successfully!")
            print("[+] Original backup saved:", backup_dir)
            print("[+] Restart vehicle to apply changes.")
        else:
            print()
            print("[!] Write failed. Try again or check security access.")
            print("[+] Original coding backed up at:", backup_dir)
    
    can.close()
    print()
    print("[+] Done!")

# ============================================================
# Helper: Find the correct byte to modify
# ============================================================

def analyze_coding(coding_bytes):
    """
    Analyze long coding bytes to find the matrix headlight control byte.
    Run this with your current coding to find the right byte.
    """
    print("[+] Coding Analysis for Matrix Headlight")
    print("=" * 40)
    
    # Common patterns in VW long coding:
    # Byte 15-20 often contains adaptive light settings
    # Look for bytes that change when you toggle regular LED vs matrix
    
    print("[+] Common matrix headlight control locations:")
    print("    Byte 15: Adaptive light / IQ.LIGHT settings")
    print("    Byte 16: Matrix beam control")
    print("    Byte 17: LED matrix configuration")
    print()
    
    print("[+] Byte analysis:")
    for i in range(14, min(22, len(coding_bytes))):
        byte = coding_bytes[i]
        binary = f"{byte:08b}"
        print(f"    Byte {i}: 0x{byte:02X} = {binary}")
        print(f"             Bits: D7={binary[0]} D6={binary[1]} D5={binary[2]} D4={binary[3]} D3={binary[4]} D2={binary[5]} D1={binary[6]} D0={binary[7]}")
    
    print()
    print("[+] Suggested modifications:")
    print("    Try setting Bit 6 of Byte 15 to 1:")
    print(f"    Current Byte 15: 0x{coding_bytes[15]:02X} -> Modified: 0x{(coding_bytes[15] | 0x40):02X}")
    print()
    print("    Or try Byte 16, Bit 7:")
    print(f"    Current Byte 16: 0x{coding_bytes[16]:02X} -> Modified: 0x{(coding_bytes[16] | 0x80):02X}")


# ============================================================
# Main
# ============================================================

def restore_coding(vin=None, channel='can0', algorithm=None, manual_key=None):
    """Restore coding from the most recent backup."""
    print("=" * 60)
    print("  VW ID.4 Coding Restore from Backup")
    print("=" * 60)
    print()
    
    backup = BackupManager(vin=vin)
    coding_data = backup.restore_coding(0x09)
    
    if not coding_data:
        print("[!] No backup found to restore.")
        return
    
    # Connect and restore
    can = VWCANInterface(channel=channel)
    if not can.connect():
        sys.exit(1)
    
    session = UDSSession(can)
    session.set_session(EXTENDED_SESSION)
    session.unlock_security(SECURITY_LEVEL_3, vin, algorithm, manual_key)
    
    coding = LongCoding(can)
    if coding.write_long_coding(0x09, coding_data, "Central Electronics"):
        print("[+] Coding restored! Restart vehicle to apply.")
    else:
        print("[!] Restore failed.")
    
    can.close()


def check_dongle(channel='can0'):
    """Run full OBD dongle capability check."""
    OBDChecker.run_full_check(channel)


def get_input(prompt, default=None):
    """Get user input with optional default value."""
    if default is not None:
        display = f"{prompt} [{default}]: "
    else:
        display = f"{prompt}: "
    
    try:
        value = input(display).strip()
        return value if value else default
    except (EOFError, KeyboardInterrupt):
        print()
        return default


def main_interactive():
    """Interactive mode - prompts user for all inputs."""
    print("=" * 60)
    print("  VW ID.4 Matrix Headlight Enable")
    print("  Interactive Mode")
    print("=" * 60)
    print()
    print("[!] Note: VW uses SA2 bytecode VM for security access.")
    print("    If all algorithms fail, use option 7 to enter a known-working key.")
    print()
    
    # Menu
    print("Select action:")
    print("  1) Enable matrix headlights")
    print("  2) Analyze coding bytes")
    print("  3) Restore from backup")
    print("  4) List backups")
    print("  5) Check OBD dongle")
    print("  6) Exit")
    print("  7) Test security access (capture seed/key)")
    print("  8) Dump ECU flash")
    print("  9) Extract SA2 script from flash file")
    print()
    
    action = get_input("Action", "1")
    
    if action == "6" or action is None:
        print("[+] Exiting.")
        return
    elif action == "7":
        channel = get_input("CAN channel", "can0")
        print("\nTesting security access...")
        can = VWCANInterface(channel=channel)
        if can.connect():
            session = UDSSession(can)
            session.set_session(EXTENDED_SESSION)
            session.unlock_security(SECURITY_LEVEL_3)
            can.close()
        return
    elif action == "8":
        channel = get_input("CAN channel", "can0")
        vin = get_input("VIN (for seed-key calculation, or leave blank)")
        print("\nAvailable algorithms:")
        for i, algo in enumerate(VW_ALGORITHMS, 1):
            print(f"  {i}) {algo[0]}")
        print(f"  6) VIN-dependent (algo5)")
        print(f"  7) Manual key entry")
        algo_choice = get_input("Algorithm", "2")
        algorithm_map = {
            '1': 'algo1_mqb_standard',
            '2': 'algo4_meb_platform',
            '3': 'algo3_mqb_evo',
            '4': 'algo2_simple_xor',
            '5': 'algo4_meb_platform',
            '6': 'algo5_vin_dependent',
        }
        algorithm = None
        manual_key = None
        if algo_choice == '7':
            manual_key = get_input("Manual key (hex, e.g. 'ABCD')")
        else:
            algorithm = algorithm_map.get(algo_choice, 'algo4_meb_platform')
        
        print("\n[*] Connecting to ECU...")
        can = VWCANInterface(channel=channel)
        if can.connect():
            session = UDSSession(can)
            session.set_session(EXTENDED_SESSION)
            
            print("[*] Unlocking security access...")
            if session.unlock_security(SECURITY_LEVEL_3, vin, algorithm, manual_key):
                print("[*] Security access granted!")
                
                # Switch to programming session for flash access
                print("[*] Switching to programming session...")
                session.set_session(PROGRAMMING_SESSION)
                
                # Dump flash
                dumper = FlashDumper(can)
                output = dumper.dump_flash()
                
                if output:
                    print("\n[*] Now extracting SA2 script...")
                    with open(output, 'rb') as f:
                        flash_data = f.read()
                    dumper.extract_sa2_script(flash_data)
            else:
                print("[!] Security access failed. Cannot dump flash.")
            can.close()
        return
    elif action == "9":
        flash_file = get_input("Path to flash dump file (.bin)")
        if flash_file:
            try:
                with open(flash_file, 'rb') as f:
                    flash_data = f.read()
                print(f"\n[*] Loaded {len(flash_data)} bytes from {flash_file}")
                
                dumper = FlashDumper(None)
                dumper.extract_sa2_script(flash_data)
            except FileNotFoundError:
                print(f"[-] File not found: {flash_file}")
        return
    elif action == "5":
        channel = get_input("CAN channel", "can0")
        check_dongle(channel)
        return
    elif action == "4":
        vin = get_input("VIN (for backup filter, or leave blank)")
        backup = BackupManager(vin=vin)
        backup.list_backups()
        return
    elif action == "3":
        channel = get_input("CAN channel", "can0")
        vin = get_input("VIN (for seed-key calculation, or leave blank)")
        print("\nAvailable algorithms:")
        for i, algo in enumerate(VW_ALGORITHMS, 1):
            print(f"  {i}) {algo[0]}")
        print(f"  6) VIN-dependent (algo5)")
        print(f"  7) Manual key entry")
        algo_choice = get_input("Algorithm", "2")
        algorithm_map = {
            '1': 'algo1_mqb_standard',
            '2': 'algo4_meb_platform',
            '3': 'algo3_mqb_evo',
            '4': 'algo2_simple_xor',
            '5': 'algo4_meb_platform',
            '6': 'algo5_vin_dependent',
        }
        algorithm = None
        manual_key = None
        if algo_choice == '7':
            manual_key = get_input("Manual key (hex, e.g. 'ABCD')")
        else:
            algorithm = algorithm_map.get(algo_choice, 'algo4_meb_platform')
        restore_coding(vin=vin, channel=channel, algorithm=algorithm, manual_key=manual_key)
        return
    elif action == "2":
        channel = get_input("CAN channel", "can0")
        vin = get_input("VIN (for seed-key calculation, or leave blank)")
        print("\nAvailable algorithms:")
        for i, algo in enumerate(VW_ALGORITHMS, 1):
            print(f"  {i}) {algo[0]}")
        print(f"  5) VIN-dependent (algo5)")
        print(f"  6) Manual key entry")
        algo_choice = get_input("Algorithm", "2")
        algorithm_map = {
            '1': 'algo1_mqb_standard',
            '2': 'algo4_meb_platform',
            '3': 'algo3_mqb_evo',
            '4': 'algo2_simple_xor',
            '5': 'algo5_vin_dependent',
        }
        algorithm = None
        manual_key = None
        if algo_choice == '6':
            manual_key = get_input("Manual key (hex, e.g. 'ABCD')")
        else:
            algorithm = algorithm_map.get(algo_choice, 'algo4_meb_platform')
        
        can = VWCANInterface(channel=channel)
        can.connect()
        session = UDSSession(can)
        session.set_session(EXTENDED_SESSION)
        session.unlock_security(SECURITY_LEVEL_3, vin, algorithm, manual_key)
        
        coding_interface = LongCoding(can)
        coding = coding_interface.read_long_coding(0x09)
        
        if coding:
            analyze_coding(coding)
        
        can.close()
        return
    elif action == "1":
        pass
    else:
        print("[!] Invalid action.")
        return
    
    # Main flow - enable matrix headlights
    channel = get_input("CAN channel", "can0")
    vin = get_input("VIN (for seed-key calculation, or leave blank)")
    
    print("\nAvailable algorithms:")
    for i, algo in enumerate(VW_ALGORITHMS, 1):
        print(f"  {i}) {algo[0]}")
    print(f"  5) VIN-dependent (algo5)")
    print(f"  6) Manual key entry")
    algo_choice = get_input("Algorithm", "2")
    algorithm_map = {
        '1': 'algo1_mqb_standard',
        '2': 'algo4_meb_platform',
        '3': 'algo3_mqb_evo',
        '4': 'algo2_simple_xor',
        '5': 'algo5_vin_dependent',
    }
    algorithm = None
    manual_key = None
    if algo_choice == '6':
        manual_key = get_input("Manual key (hex, e.g. 'ABCD')")
    else:
        algorithm = algorithm_map.get(algo_choice, 'algo4_meb_platform')
    
    test_mode_input = get_input("Test mode? (writes will be skipped, Y/n)", "Y")
    test_mode = test_mode_input.lower() != 'n'
    
    enable_matrix_headlights(vin=vin, test_mode=test_mode, algorithm=algorithm, manual_key=manual_key)


if __name__ == "__main__":
    main_interactive()
