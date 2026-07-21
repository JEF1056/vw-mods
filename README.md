# VW ID.4 Matrix Headlight Enable

Unlocks IQ.LIGHT matrix headlight functionality on VW ID.4 vehicles by directly writing module coding via UDS protocol, bypassing VW's online authentication/coding match process.

## Requirements

### Hardware
- **VW ID.4** (2021-2024) with matrix headlight hardware already installed
- **OBDII CAN adapter** that supports:
  - CAN bus at 500kbps (VW standard)
  - UDS protocol (ISO 14229)
  - Read/write capability (not read-only)
- **Linux machine** (tested on Ubuntu 20.04+)

### Compatible Adapters
- OBDeLink EX (recommended)
- ELM327-based adapters (must support CAN 500kbps)
- VCDS/Ross-Tech adapter
- Any socketcan-compatible CAN dongle

### Software
- Python 3.8+
- `python-can` library
- `socketcan` support (Linux kernel)

## Quick Start

### 1. Install Dependencies

```bash
pip install python-can
```

### 2. Set Up CAN Interface

```bash
sudo ip link set can0 up type can bitrate 500000
```

### 3. Check Your Dongle

```bash
python3 id4_matrix_headlight.py --check
```

This verifies your adapter supports all required features.

### 4. Read Current Coding (Test Mode)

```bash
python3 id4_matrix_headlight.py --test --vin YOUR_VIN_HERE
```

This reads your current module coding without making changes.

### 5. Analyze Coding Bytes

```bash
python3 id4_matrix_headlight.py --analyze --vin YOUR_VIN_HERE
```

Shows which bytes control matrix headlight functionality.

### 6. Enable Matrix Headlights

```bash
python3 id4_matrix_headlight.py --vin YOUR_VIN_HERE
```

Writes the modified coding. Your original coding is automatically backed up.

## Usage

```
python3 id4_matrix_headlight.py [OPTIONS]

Options:
  --vin VIN           Vehicle VIN for seed-key calculation
  --test              Test mode - read coding but don't write
  --analyze           Analyze coding bytes to find matrix headlight controls
  --channel CHANNEL   CAN channel name (default: can0)
  --restore           Restore coding from latest backup
  --list-backups      List all available backups
  --check             Check OBD dongle capabilities
```

## How It Works

### The Security Bypass

VW vehicles use UDS (Unified Diagnostic Services) protocol over CAN bus. To write coding, you normally need:

1. **Session Control** - Switch to extended/programming session
2. **Security Access** - VW's seed-key authentication (requires online coding match)
3. **DID Write** - Write the actual coding data

This script bypasses the online authentication by:

1. Using the reverse-engineered VW seed-key algorithm to authenticate locally
2. Directly writing coding bytes to Module 09 (Central Electronics)
3. No VW server connection required

### What Gets Changed

The script modifies the long coding data in Module 09 to enable matrix headlight functionality. The exact byte modification depends on your vehicle's hardware and production date.

### Backup & Restore

Every coding change is automatically backed up with a timestamp:

```
backups/
└── YOUR_VIN_20240115_143022/
    ├── module_09_coding.hex
    ├── module_09_coding.txt
    └── manifest.txt
```

Restore to original:
```bash
python3 id4_matrix_headlight.py --restore --vin YOUR_VIN_HERE
```

## Troubleshooting

### "No response to Tester Present"
- Your adapter may not support CAN 500kbps
- Try a different adapter (OBDeLink EX recommended)
- Ensure CAN interface is up: `sudo ip link set can0 up type can bitrate 500000`

### "Security access failed"
- Try with your VIN: `--vin YOUR_VIN_HERE`
- The VIN-dependent seed-key algorithm is more accurate for 2023+ models
- Some adapters need a few seconds to initialize after connection

### "Could not read long coding"
- Ensure the vehicle is on (ignition on, but engine off)
- Try connecting to a different OBD port
- Check that your adapter supports extended CAN frames

### Running as non-root
Some CAN interfaces require root privileges:
```bash
sudo python3 id4_matrix_headlight.py --vin YOUR_VIN_HERE
```

## Notes

- **Hardware prerequisite**: Your ID.4 must already have matrix headlight units installed. This is a software unlock, not a hardware conversion.
- **Test before writing**: Always run with `--test` first to verify your adapter works
- **Backup is automatic**: Your original coding is saved before any write operation
- **Restart required**: After writing coding, restart the vehicle for changes to take effect

## File Structure

```
vw-mods/
├── id4_matrix_headlight.py    # Main script
├── README.md                  # This file
└── backups/                   # Auto-created backup directory
```

## License

MIT
