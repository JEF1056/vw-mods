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
pip install -r requirements.txt
```

### 2. Set Up CAN Interface

```bash
sudo ip link set can0 up type can bitrate 500000
```

### 3. Check Your Dongle

```bash
python3 id4_matrix_headlight.py
```

Select option `5` to verify your adapter supports all required features.

### 4. Run the Script

```bash
python3 id4_matrix_headlight.py
```

The interactive menu will guide you through:
1. **Enable matrix headlights** - Full automated enable with backup
2. **Analyze coding bytes** - See what changes would be made
3. **Restore from backup** - Revert to original coding
4. **List backups** - View all saved coding backups
5. **Check OBD dongle** - Verify adapter capabilities

### 5. Verify It Worked

After running and restarting your vehicle:
- Drive at night with **high beams enabled** (auto or manual)
- Matrix headlights will **dynamically carve out dark spots** around oncoming cars while keeping the rest illuminated
- Check headlight settings menu - should show "IQ.LIGHT" or "Matrix LED" option

## How It Works

### The Security Bypass

VW vehicles use UDS (Unified Diagnostic Services) protocol over CAN bus. To write coding, you normally need:

1. **Session Control** - Switch to extended/programming session
2. **Security Access** - VW's seed-key authentication (requires online coding match)
3. **DID Write** - Write the actual coding data

This script bypasses the online authentication by:

1. Using reverse-engineered VW seed-key algorithms to authenticate locally
2. Directly writing coding bytes to Module 09 (Central Electronics)
3. No VW server connection required

### What Gets Changed

The script:
1. Reads your current long coding from Module 09
2. Detects if matrix headlight hardware is present
3. Calculates exact modifications:
   - Byte 15, bit 6: Enable IQ.LIGHT feature
   - Byte 16, bit 7: Enable matrix beam control
   - Byte 17, bits 0-2: Enable adaptive light function
4. Writes the modified coding

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
python3 id4_matrix_headlight.py
# Select option 3: Restore from backup
```

## Troubleshooting

### "No response to Tester Present"
- Your adapter may not support CAN 500kbps
- Try a different adapter (OBDeLink EX recommended)
- Ensure CAN interface is up: `sudo ip link set can0 up type can bitrate 500000`

### "Security access failed"
- Try with your VIN (option 1 will prompt for it)
- The VIN-dependent seed-key algorithm is more accurate for 2023+ models
- Some adapters need a few seconds to initialize after connection

### "Could not read long coding"
- Ensure the vehicle is on (ignition on, but engine off)
- Try connecting to a different OBD port
- Check that your adapter supports extended CAN frames

### Running as non-root
Some CAN interfaces require root privileges:
```bash
sudo python3 id4_matrix_headlight.py
```

## Notes

- **Hardware prerequisite**: Your ID.4 must already have matrix headlight units installed. This is a software unlock, not a hardware conversion.
- **High beams required**: Matrix headlights only work when high beams are active (auto or manual)
- **Test before writing**: Run option 2 first to see what changes would be made
- **Backup is automatic**: Your original coding is saved before any write operation
- **Restart required**: After writing coding, restart the vehicle for changes to take effect

## File Structure

```
vw-mods/
├── id4_matrix_headlight.py    # Main script
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── backups/                   # Auto-created backup directory
```

## License

MIT
