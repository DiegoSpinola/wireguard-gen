# WireGuard User Generator

A robust bash script to automate WireGuard user/peer creation with comprehensive validation, backup management, and safety features.

## 🚀 Features

- ✅ **Automated user/peer creation** with key generation
- ✅ **Flag-based parameter system** for flexible configuration
- ✅ **Configuration validation** before and after modifications
- ✅ **Automatic backup system** with timestamped files
- ✅ **IP conflict detection** to prevent address collisions
- ✅ **QR code generation** for mobile clients
- ✅ **Rollback mechanism** if configuration fails
- ✅ **Comprehensive dependency checking**
- ✅ **Safe service reloading** with validation
- ✅ **Organized file structure** for backups and client configs

## 📋 Prerequisites

### Required Dependencies
- **wireguard-tools** (`wg`, `wg-quick`)
- **Root/sudo access** (to modify `/etc/wireguard/` files)

### Optional Dependencies
- **curl** (for automatic public IP detection)
- **qrencode** (for QR code generation)
- **systemctl** (for service management)

## 🔧 Installation

1. **Download the script:**
   ```bash
   wget https://raw.githubusercontent.com/yourusername/wireguard-gen/main/wireguard-gen.sh
   chmod +x wireguard-gen.sh
   ```

2. **Install dependencies:**
   ```bash
   # Debian/Ubuntu
   sudo apt-get install wireguard-tools qrencode curl

   # RHEL/CentOS/Fedora
   sudo yum install wireguard-tools qrencode curl

   # Arch Linux
   sudo pacman -S wireguard-tools qrencode curl
   ```

3. **Check dependencies:**
   ```bash
   sudo ./wireguard-gen.sh -C
   ```

## 📖 Usage

### Basic Syntax
```bash
sudo ./wireguard-gen.sh -c CONFIG_NAME -u USER_NAME -i CLIENT_IP -o OUTPUT_DIR [OPTIONS]
```

### Required Parameters
- `-c CONFIG_NAME` - WireGuard config name (e.g., 'wg0' for `/etc/wireguard/wg0.conf`)
- `-u USER_NAME` - Name for the new user/peer
- `-i CLIENT_IP` - IP address to assign (e.g., '10.0.0.5/32')
- `-o OUTPUT_DIR` - Directory to store client config file

### Optional Parameters
- `-e SERVER_ENDPOINT` - Server's public endpoint (e.g., 'vpn.example.com:51820')
- `-d DNS_SERVERS` - Custom DNS servers (DNS disabled by default)
- `-a ALLOWED_IPS` - Allowed IPs for client (default: '0.0.0.0/0, ::/0')
- `-k KEEPALIVE` - PersistentKeepalive seconds (default: 25, use 0 to disable)
- `-b BACKUP_DIR` - Custom backup directory (default: ~/wireguardbk/)
- `-D` - Enable DNS with default servers (1.1.1.1, 1.0.0.1)
- `-q` - Show QR code installation instructions if qrencode missing
- `-C` - Check dependencies and exit
- `-h` - Show help message

## 💡 Examples

### Basic Usage
```bash
# Simple user creation with auto-detection
sudo ./wireguard-gen.sh -c wg0 -u john_doe -i 10.252.1.100/32 -o ~/wireguard-clients

# Check dependencies first
./wireguard-gen.sh -C
```

### Advanced Configuration
```bash
# Custom server endpoint and DNS
sudo ./wireguard-gen.sh -c wg0 -u jane_doe -i 10.252.1.101/32 -o ~/wireguard-clients \
  -e vpn.example.com:51820 -d "8.8.8.8, 8.8.4.4"

# Split tunnel configuration (no DNS)
sudo ./wireguard-gen.sh -c wg0 -u bob -i 10.252.1.102/32 -o ~/wireguard-clients \
  -a "10.252.0.0/16, 192.168.1.0/24"

# Enable default DNS servers
sudo ./wireguard-gen.sh -c wg0 -u alice -i 10.252.1.103/32 -o ~/wireguard-clients -D

# Custom keepalive and backup location
sudo ./wireguard-gen.sh -c wg0 -u charlie -i 10.252.1.104/32 -o ~/wireguard-clients \
  -k 60 -b /backup/wireguard
```

## 📁 File Organization

The script creates an organized directory structure:

```
~/wireguardbk/                    (or custom backup directory)
├── server-configs/               # Timestamped server config backups
│   └── wg0.conf.20240322_143022.backup
└── peers/                        # Client configurations and QR codes
    ├── john_doe.conf            # Client config (mode 600)
    └── john_doe.png             # QR code for mobile import
```

## 🔒 Security Features

### Configuration Validation
- **Pre-modification validation** - Checks existing config before changes
- **Post-modification validation** - Verifies config after adding peer
- **Automatic rollback** - Restores backup if validation fails
- **Safe service reload** - Validates before attempting hot-reload

### IP Conflict Prevention
- **Duplicate IP detection** - Prevents assigning already-used IPs
- **User existence check** - Prevents duplicate usernames
- **Subnet validation** - Ensures IP fits within server's address space

### File Security
- **Secure permissions** - Client configs created with mode 600
- **Backup integrity** - Timestamped backups prevent overwrites
- **Safe failure** - Cleans up client files if server config fails

## 🛠️ Default Configuration

The script uses sensible defaults:
- **DNS**: Disabled (no DNS servers added to client config)
- **Keepalive**: 25 seconds (good for most NAT situations)
- **Allowed IPs**: 0.0.0.0/0, ::/0 (full tunnel)
- **Backup location**: ~/wireguardbk/
- **Base64 padding**: Automatically fixed for malformed keys

## 📱 QR Code Generation

When `qrencode` is installed, the script automatically generates QR codes for easy mobile client setup:
- **PNG format** for universal compatibility
- **Optimal size** for mobile scanning
- **Same filename** as config file with .png extension

## 🔄 Service Management

The script intelligently manages WireGuard service reloading:
- **Hot-reload** when possible using `wg syncconf`
- **Validation before reload** to prevent service disruption
- **Graceful fallback** with manual restart instructions
- **Service status detection** to avoid unnecessary operations

## 🚨 Error Handling & Recovery

### Automatic Rollback
If configuration validation fails after adding a peer:
1. **Immediate rollback** to previous working configuration
2. **Client config cleanup** (removes generated files)
3. **Clear error reporting** with actionable messages
4. **Backup preservation** for manual recovery if needed

### Common Issues & Solutions

#### "WireGuard tools not found"
```bash
# Install wireguard-tools
sudo apt-get install wireguard-tools  # Debian/Ubuntu
sudo yum install wireguard-tools      # RHEL/CentOS
```

#### "Could not determine server public IP"
```bash
# Manually specify server endpoint
sudo ./wireguard-gen.sh -c wg0 -u user -i 10.0.0.5/32 -o ~/clients -e your-server.com:51820
```

#### "IP address already allocated"
```bash
# Choose a different IP address
sudo ./wireguard-gen.sh -c wg0 -u user -i 10.0.0.6/32 -o ~/clients
```

#### "Configuration validation failed"
```bash
# Check your server config syntax
wg-quick strip wg0
# Fix any syntax errors, then try again
```

## 🔍 Troubleshooting

### Dependency Check
Always start troubleshooting with a dependency check:
```bash
./wireguard-gen.sh -C
```

### Manual Backup Restoration
If you need to restore from backup:
```bash
# List available backups
ls -la ~/wireguardbk/server-configs/

# Restore a specific backup
sudo cp ~/wireguardbk/server-configs/wg0.conf.20240322_143022.backup /etc/wireguard/wg0.conf
sudo systemctl restart wg-quick@wg0
```

### Configuration Testing
Test configuration syntax without applying:
```bash
# Test server config
sudo wg-quick strip wg0

# Test client config
sudo wg-quick strip /path/to/client.conf
```

## 🤝 Contributing

Contributions are welcome! Please:
1. **Fork the repository**
2. **Create a feature branch**
3. **Add tests** for new functionality
4. **Update documentation**
5. **Submit a pull request**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Important Notes

- **Always run with sudo** for server configuration modifications
- **Test in non-production** environments first
- **Keep backups** of working configurations
- **Verify client connectivity** after peer creation
- **Monitor log files** for connection issues

## 🔗 Related Documentation

- [WireGuard Official Documentation](https://www.wireguard.com/)
- [WireGuard Quick Start](https://www.wireguard.com/quickstart/)
- [WireGuard Configuration Reference](https://manpages.debian.org/testing/wireguard-tools/wg.8.en.html)