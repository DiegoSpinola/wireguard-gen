#!/bin/bash

set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_fail() {
    echo -e "${RED}[✗]${NC} $1"
}

validate_config() {
    local config_file="$1"
    local config_name="$2"

    if [ ! -f "$config_file" ]; then
        log_error "Configuration file not found: $config_file"
        return 1
    fi

    log_info "Validating WireGuard configuration: $config_name"

    # Check if config can be parsed by wg-quick
    if wg-quick strip "$config_name" &>/dev/null; then
        log_success "Configuration syntax is valid"
        return 0
    else
        log_error "Configuration validation failed!"
        wg-quick strip "$config_name" 2>&1 | while IFS= read -r line; do
            log_error "  $line"
        done
        return 1
    fi
}

rollback_on_error() {
    local backup_file="$1"
    local server_config="$2"
    local config_name="$3"

    log_warning "Rolling back to previous configuration..."
    cp "$backup_file" "$server_config"

    if validate_config "$server_config" "$config_name"; then
        log_success "Rollback successful - configuration restored"
        return 0
    else
        log_error "CRITICAL: Rollback failed! Manual intervention required."
        log_error "Backup file: $backup_file"
        return 1
    fi
}

check_dependencies() {
    local check_only="$1"
    local all_good=true
    local missing_deps=""
    local optional_missing=""

    log_info "Checking dependencies..."
    echo ""

    # Required dependencies
    log_info "Required dependencies:"

    # Check for wg command
    if command -v wg &> /dev/null; then
        log_success "wireguard-tools (wg) is installed"
    else
        log_fail "wireguard-tools (wg) is NOT installed"
        missing_deps="${missing_deps}wireguard-tools "
        all_good=false
    fi

    # Check for wg-quick
    if command -v wg-quick &> /dev/null; then
        log_success "wg-quick is installed"
    else
        log_fail "wg-quick is NOT installed"
        missing_deps="${missing_deps}wg-quick "
        all_good=false
    fi

    # Check for systemctl
    if command -v systemctl &> /dev/null; then
        log_success "systemctl is installed"
    else
        log_warning "systemctl is NOT installed (service management will be limited)"
    fi

    # Check for curl (needed for auto-detection)
    if command -v curl &> /dev/null; then
        log_success "curl is installed"
    else
        log_warning "curl is NOT installed (auto endpoint detection will not work)"
        optional_missing="${optional_missing}curl "
    fi

    echo ""
    log_info "Optional dependencies:"

    # Check for qrencode
    if command -v qrencode &> /dev/null; then
        log_success "qrencode is installed (QR codes will be generated)"
    else
        log_warning "qrencode is NOT installed (QR codes will not be generated)"
        optional_missing="${optional_missing}qrencode "
    fi

    echo ""

    # Check WireGuard kernel module (if lsmod is available)
    if command -v lsmod &> /dev/null; then
        if lsmod | grep -q wireguard 2>/dev/null; then
            log_success "WireGuard kernel module is loaded"
        else
            if command -v modinfo &> /dev/null && modinfo wireguard &>/dev/null; then
                log_warning "WireGuard kernel module is available but not loaded"
                log_info "  To load: sudo modprobe wireguard"
            else
                log_fail "WireGuard kernel module is NOT available"
                all_good=false
            fi
        fi
    else
        log_warning "Cannot check kernel modules (lsmod not found)"
    fi

    # Check for write permissions to /etc/wireguard
    if [ -w "/etc/wireguard" ] 2>/dev/null; then
        log_success "Write access to /etc/wireguard"
    else
        if [ "$check_only" = "true" ]; then
            log_warning "No write access to /etc/wireguard (run with sudo for actual operations)"
        else
            log_fail "No write access to /etc/wireguard"
            all_good=false
        fi
    fi

    echo ""

    if [ "$all_good" = true ]; then
        log_success "All required dependencies are satisfied!"
        if [ -n "$optional_missing" ]; then
            echo ""
            log_info "To install optional dependencies:"
            log_info "  Debian/Ubuntu: sudo apt-get install $optional_missing"
            log_info "  RHEL/CentOS:   sudo yum install $optional_missing"
            log_info "  Arch Linux:    sudo pacman -S $optional_missing"
        fi
        return 0
    else
        log_error "Missing required dependencies!"
        echo ""
        log_info "To install required dependencies:"
        log_info "  Debian/Ubuntu: sudo apt-get install $missing_deps"
        log_info "  RHEL/CentOS:   sudo yum install $missing_deps"
        log_info "  Arch Linux:    sudo pacman -S $missing_deps"
        if [ -n "$optional_missing" ]; then
            echo ""
            log_info "Optional packages for full functionality: $optional_missing"
        fi
        return 1
    fi
}

usage() {
    cat << EOF
Usage: $SCRIPT_NAME -c CONFIG_NAME -u USER_NAME -i CLIENT_IP -o OUTPUT_DIR [OPTIONS]

Generate a new WireGuard user configuration and add it to the server config.

Required Arguments:
  -c CONFIG_NAME      Name of the WireGuard config (e.g., 'wg0' for /etc/wireguard/wg0.conf)
  -u USER_NAME        Name for the new user/peer
  -i CLIENT_IP        IP address to assign to the client (e.g., '10.0.0.5/32')
  -o OUTPUT_DIR       Directory to store the generated client config file

Optional Arguments:
  -e SERVER_ENDPOINT  Server's public endpoint (e.g., 'vpn.example.com:51820')
                      If not provided, will try to extract from existing config
  -d DNS_SERVERS      DNS servers for the client (by default DNS is not configured)
  -a ALLOWED_IPS      Allowed IPs for the client (default: '0.0.0.0/0, ::/0')
  -k KEEPALIVE        PersistentKeepalive value in seconds (default: 25, use 0 to disable)
  -b BACKUP_DIR       Custom backup directory (default: ~/wireguardbk/)
  -D                  Enable DNS with default servers (1.1.1.1, 1.0.0.1)
  -q                  Generate QR code even if qrencode needs to be installed
  -C                  Check dependencies and exit
  -h                  Show this help message

Examples:
  # Basic usage with auto-detection
  $SCRIPT_NAME -c wg0 -u john_doe -i 10.0.0.5/32 -o /home/admin/wg-clients

  # Specify server endpoint and custom DNS
  $SCRIPT_NAME -c wg0 -u jane_doe -i 10.0.0.6/32 -o /home/admin/wg-clients -e vpn.example.com:51820 -d "8.8.8.8, 8.8.4.4"

  # Split tunnel with specific allowed IPs (DNS disabled by default)
  $SCRIPT_NAME -c wg0 -u bob -i 10.0.0.7/32 -o /home/admin/wg-clients -a "10.0.0.0/24, 192.168.1.0/24"

  # Enable DNS with default servers
  $SCRIPT_NAME -c wg0 -u charlie -i 10.0.0.9/32 -o /home/admin/wg-clients -D

  # Custom keepalive and backup directory
  $SCRIPT_NAME -c wg0 -u alice -i 10.0.0.8/32 -o /home/admin/wg-clients -k 60 -b /backup/wireguard

  # Check dependencies without running
  $SCRIPT_NAME -C

EOF
    exit ${1:-1}
}

CONFIG_NAME=""
USER_NAME=""
CLIENT_IP=""
OUTPUT_DIR=""
SERVER_ENDPOINT=""
DNS_SERVERS=""
ALLOWED_IPS="0.0.0.0/0, ::/0"
KEEPALIVE="25"
BACKUP_DIR="${HOME}/wireguardbk"
NO_DNS=true
FORCE_QR=false
CHECK_DEPS=false

while getopts "c:u:i:o:e:d:a:k:b:DqCh" opt; do
    case ${opt} in
        c )
            CONFIG_NAME="$OPTARG"
            ;;
        u )
            USER_NAME="$OPTARG"
            ;;
        i )
            CLIENT_IP="$OPTARG"
            ;;
        o )
            OUTPUT_DIR="$OPTARG"
            ;;
        e )
            SERVER_ENDPOINT="$OPTARG"
            ;;
        d )
            DNS_SERVERS="$OPTARG"
            NO_DNS=false
            ;;
        a )
            ALLOWED_IPS="$OPTARG"
            ;;
        k )
            KEEPALIVE="$OPTARG"
            ;;
        b )
            BACKUP_DIR="$OPTARG"
            ;;
        D )
            NO_DNS=false
            if [ -z "$DNS_SERVERS" ]; then
                DNS_SERVERS="1.1.1.1, 1.0.0.1"
            fi
            ;;
        q )
            FORCE_QR=true
            ;;
        C )
            CHECK_DEPS=true
            ;;
        h )
            usage 0
            ;;
        \? )
            log_error "Invalid option: -$OPTARG"
            usage
            ;;
        : )
            log_error "Option -$OPTARG requires an argument"
            usage
            ;;
    esac
done

shift $((OPTIND -1))

# If checking dependencies only
if [ "$CHECK_DEPS" = true ]; then
    check_dependencies "true"
    exit $?
fi

if [ -z "$CONFIG_NAME" ] || [ -z "$USER_NAME" ] || [ -z "$CLIENT_IP" ] || [ -z "$OUTPUT_DIR" ]; then
    log_error "Missing required arguments"
    usage
fi

# Validate username for security (prevent path traversal)
validate_username() {
    local username="$1"

    # Check for path traversal characters
    if echo "$username" | grep -q '[/\\]'; then
        log_error "Username contains invalid path characters: $username"
        log_error "Usernames cannot contain '/' or '\\' characters for security reasons"
        return 1
    fi

    # Check for directory traversal patterns
    if echo "$username" | grep -q '\.\.'; then
        log_error "Username contains directory traversal pattern: $username"
        log_error "Usernames cannot contain '..' for security reasons"
        return 1
    fi

    # Check for other problematic characters
    if echo "$username" | grep -q '[<>:"|?*]'; then
        log_error "Username contains invalid characters: $username"
        log_error "Usernames cannot contain: < > : \" | ? *"
        return 1
    fi

    # Check length
    if [ ${#username} -gt 64 ]; then
        log_error "Username too long (max 64 characters): ${#username}"
        return 1
    fi

    # Check starts with valid character
    if echo "$username" | grep -qE '^[.-]'; then
        log_error "Username cannot start with '.' or '-'"
        return 1
    fi

    return 0
}

# Validate IP address format and content
validate_ip_address() {
    local ip="$1"
    local description="$2"

    # Check if CIDR notation is present
    if ! echo "$ip" | grep -q '/'; then
        log_error "$description must include CIDR notation (e.g., '10.0.0.5/32')"
        log_error "Provided: $ip"
        return 1
    fi

    # Split IP and CIDR
    local ip_only="${ip%/*}"
    local cidr_suffix="${ip#*/}"

    # Validate IPv4 format using regex
    if ! echo "$ip_only" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        log_error "$description has invalid IPv4 format: $ip_only"
        log_error "Expected format: xxx.xxx.xxx.xxx/xx"
        return 1
    fi

    # Validate each octet is 0-255
    local IFS='.'
    local octet_count=0
    for octet in $ip_only; do
        octet_count=$((octet_count + 1))

        # Check for leading zeros (except single zero)
        if [ "$octet" != "0" ] && echo "$octet" | grep -q '^0'; then
            log_error "$description has invalid octet with leading zero: $octet"
            return 1
        fi

        # Check numeric range
        if ! echo "$octet" | grep -qE '^[0-9]+$' || [ "$octet" -gt 255 ] 2>/dev/null || [ "$octet" -lt 0 ] 2>/dev/null; then
            log_error "$description has invalid IPv4 octet: $octet (must be 0-255)"
            return 1
        fi
    done

    # Ensure exactly 4 octets
    if [ "$octet_count" -ne 4 ]; then
        log_error "$description must have exactly 4 octets, found: $octet_count"
        return 1
    fi

    # Validate CIDR suffix
    if ! echo "$cidr_suffix" | grep -qE '^[0-9]+$' || [ "$cidr_suffix" -gt 32 ] || [ "$cidr_suffix" -lt 0 ]; then
        log_error "$description has invalid CIDR suffix: /$cidr_suffix (must be 0-32)"
        return 1
    fi

    # Check for reserved/problematic addresses and reject them
    case "$ip_only" in
        "0.0.0.0")
            log_error "$description cannot use network address: $ip_only"
            return 1
            ;;
        "255.255.255.255")
            log_error "$description cannot use broadcast address: $ip_only"
            return 1
            ;;
        127.*)
            log_error "$description cannot use loopback address: $ip_only"
            log_error "Loopback addresses (127.x.x.x) are reserved for local host"
            return 1
            ;;
        169.254.*)
            log_error "$description cannot use link-local address: $ip_only"
            log_error "Link-local addresses (169.254.x.x) are auto-assigned and should not be used"
            return 1
            ;;
        224.*|225.*|226.*|227.*|228.*|229.*|230.*|231.*|232.*|233.*|234.*|235.*|236.*|237.*|238.*|239.*)
            log_error "$description cannot use multicast address: $ip_only"
            log_error "Multicast addresses (224.0.0.0-239.255.255.255) are reserved"
            return 1
            ;;
        240.*|241.*|242.*|243.*|244.*|245.*|246.*|247.*|248.*|249.*|250.*|251.*|252.*|253.*|254.*|255.*)
            log_error "$description cannot use reserved address: $ip_only"
            log_error "Addresses 240.0.0.0-255.255.255.255 are reserved for future use"
            return 1
            ;;
    esac

    # Additional checks for common mistakes
    if [ "$cidr_suffix" -eq 0 ]; then
        log_warning "$description uses /0 CIDR which routes all traffic (0.0.0.0/0)"
    elif [ "$cidr_suffix" -lt 8 ]; then
        log_warning "$description uses very broad CIDR /$cidr_suffix - ensure this is intentional"
    fi

    return 0
}

# Validate the username
if ! validate_username "$USER_NAME"; then
    exit 1
fi

# Validate the client IP address
if ! validate_ip_address "$CLIENT_IP" "Client IP address"; then
    exit 1
fi

SERVER_CONFIG="/etc/wireguard/${CONFIG_NAME}.conf"
CLIENT_CONFIG="${OUTPUT_DIR}/${USER_NAME}.conf"

# Ensure OUTPUT_DIR is actually the peer configs directory in backup dir
if [ "$OUTPUT_DIR" = "" ]; then
    OUTPUT_DIR="${BACKUP_DIR}/peers"
fi

log_info "WireGuard User Generator Starting..."
log_info "Configuration: ${CONFIG_NAME}"
log_info "User: ${USER_NAME}"
log_info "Client IP: ${CLIENT_IP}"
log_info "Output Directory: ${OUTPUT_DIR}"
log_info "Backup Directory: ${BACKUP_DIR}"
if [ "$NO_DNS" = true ]; then
    log_info "DNS: Disabled (default)"
else
    log_info "DNS: ${DNS_SERVERS}"
fi
log_info "Allowed IPs: ${ALLOWED_IPS}"
log_info "Keepalive: ${KEEPALIVE} seconds"
if [ -n "$SERVER_ENDPOINT" ]; then
    log_info "Server Endpoint: ${SERVER_ENDPOINT}"
fi

# Run dependency check (will exit if missing required deps)
if ! check_dependencies "false"; then
    exit 1
fi
echo ""

if [ ! -f "$SERVER_CONFIG" ]; then
    log_error "Server configuration file not found: $SERVER_CONFIG"
    exit 1
fi

if [ ! -d "$BACKUP_DIR" ]; then
    log_info "Creating backup directory: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
fi

if [ ! -d "$OUTPUT_DIR" ]; then
    log_info "Creating output directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
fi

# Create subdirectories for organization
BACKUP_CONFIGS_DIR="${BACKUP_DIR}/server-configs"
if [ ! -d "$BACKUP_CONFIGS_DIR" ]; then
    mkdir -p "$BACKUP_CONFIGS_DIR"
fi

if [ -f "$CLIENT_CONFIG" ]; then
    log_error "Client configuration already exists: $CLIENT_CONFIG"
    log_error "Please choose a different user name or remove the existing file."
    exit 1
fi

if grep -q "# ${USER_NAME}$" "$SERVER_CONFIG"; then
    log_error "User '${USER_NAME}' already exists in the server configuration."
    exit 1
fi

CLIENT_IP_ONLY="${CLIENT_IP%/*}"
if grep -q "AllowedIPs = .*${CLIENT_IP_ONLY}" "$SERVER_CONFIG"; then
    log_error "IP address ${CLIENT_IP} is already allocated to another peer."
    exit 1
fi

if [ -z "$SERVER_ENDPOINT" ]; then
    log_info "Attempting to extract server endpoint from existing config..."

    LISTEN_PORT=$(grep "^ListenPort" "$SERVER_CONFIG" | cut -d'=' -f2 | tr -d ' ')
    if [ -z "$LISTEN_PORT" ]; then
        log_error "Could not extract ListenPort from server config. Please provide SERVER_ENDPOINT parameter."
        exit 1
    fi

    SERVER_PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s icanhazip.com 2>/dev/null || echo "")
    if [ -z "$SERVER_PUBLIC_IP" ]; then
        log_error "Could not determine server public IP. Please provide SERVER_ENDPOINT parameter."
        exit 1
    fi

    SERVER_ENDPOINT="${SERVER_PUBLIC_IP}:${LISTEN_PORT}"
    log_info "Using server endpoint: $SERVER_ENDPOINT"
fi

BACKUP_FILE="${BACKUP_CONFIGS_DIR}/${CONFIG_NAME}.conf.$(date +%Y%m%d_%H%M%S).backup"
log_info "Creating backup: $BACKUP_FILE"
cp "$SERVER_CONFIG" "$BACKUP_FILE"

# Validate existing configuration before making changes
if ! validate_config "$SERVER_CONFIG" "$CONFIG_NAME"; then
    log_error "Existing server configuration is invalid. Aborting."
    log_info "Please fix the configuration before adding new peers."
    exit 1
fi

log_info "Generating keys for user: $USER_NAME"
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
PRESHARED_KEY=$(wg genpsk)

SERVER_PRIVATE_KEY=$(grep "^PrivateKey" "$SERVER_CONFIG" | head -1 | cut -d'=' -f2 | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')

# Ensure the private key has the correct base64 padding
if [ ${#SERVER_PRIVATE_KEY} -eq 43 ]; then
    SERVER_PRIVATE_KEY="${SERVER_PRIVATE_KEY}="
fi

SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)

SERVER_NETWORK=$(grep -E "^Address" "$SERVER_CONFIG" | head -1 | cut -d'=' -f2 | tr -d ' ' | cut -d'/' -f1,2)
SERVER_NETWORK_PREFIX="${SERVER_NETWORK%.*}"

log_info "Adding peer to server configuration..."
cat >> "$SERVER_CONFIG" << EOF

[Peer]
# ${USER_NAME}
PublicKey = ${CLIENT_PUBLIC_KEY}
PresharedKey = ${PRESHARED_KEY}
AllowedIPs = ${CLIENT_IP}
EOF

log_info "Server configuration updated."

# Validate the new configuration
if ! validate_config "$SERVER_CONFIG" "$CONFIG_NAME"; then
    log_error "Configuration validation failed after adding new peer!"
    if rollback_on_error "$BACKUP_FILE" "$SERVER_CONFIG" "$CONFIG_NAME"; then
        log_error "Changes have been rolled back. Please check your input parameters."
        rm -f "$CLIENT_CONFIG"  # Remove the client config since we rolled back
        exit 1
    else
        log_error "CRITICAL: Unable to restore working configuration!"
        exit 1
    fi
fi

log_info "Server configuration validated successfully."

log_info "Creating client configuration: $CLIENT_CONFIG"

if [ "$NO_DNS" = true ]; then
    cat > "$CLIENT_CONFIG" << EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_IP}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
PresharedKey = ${PRESHARED_KEY}
AllowedIPs = ${ALLOWED_IPS}
Endpoint = ${SERVER_ENDPOINT}
EOF
else
    cat > "$CLIENT_CONFIG" << EOF
[Interface]
PrivateKey = ${CLIENT_PRIVATE_KEY}
Address = ${CLIENT_IP}
DNS = ${DNS_SERVERS}

[Peer]
PublicKey = ${SERVER_PUBLIC_KEY}
PresharedKey = ${PRESHARED_KEY}
AllowedIPs = ${ALLOWED_IPS}
Endpoint = ${SERVER_ENDPOINT}
EOF
fi

if [ "$KEEPALIVE" != "0" ]; then
    echo "PersistentKeepalive = ${KEEPALIVE}" >> "$CLIENT_CONFIG"
fi

chmod 600 "$CLIENT_CONFIG"

log_info "Client configuration created successfully."

if command -v systemctl &> /dev/null; then
    if systemctl is-active --quiet "wg-quick@${CONFIG_NAME}"; then
        log_info "Reloading WireGuard interface: ${CONFIG_NAME}"

        # Try to reload the configuration
        if wg syncconf "${CONFIG_NAME}" <(wg-quick strip "${CONFIG_NAME}" 2>/dev/null) 2>/dev/null; then
            log_success "WireGuard interface reloaded successfully."
        else
            # If syncconf fails, try to validate if the config would work
            if wg-quick strip "${CONFIG_NAME}" &>/dev/null; then
                log_warning "Could not hot-reload configuration. Manual restart required:"
                log_warning "  sudo systemctl restart wg-quick@${CONFIG_NAME}"
            else
                log_error "Configuration reload failed! Rolling back changes..."
                if rollback_on_error "$BACKUP_FILE" "$SERVER_CONFIG" "$CONFIG_NAME"; then
                    rm -f "$CLIENT_CONFIG"
                    exit 1
                fi
            fi
        fi
    else
        log_warning "WireGuard interface ${CONFIG_NAME} is not active."
        log_warning "To apply changes, start the service:"
        log_warning "  sudo systemctl start wg-quick@${CONFIG_NAME}"
    fi
else
    log_warning "systemctl not available. Please manually reload WireGuard."
fi

log_info "✅ User '${USER_NAME}' created successfully!"
log_info "Client configuration saved to: ${CLIENT_CONFIG}"
log_info ""
log_info "Client Details:"
log_info "  IP Address: ${CLIENT_IP}"
log_info "  Public Key: ${CLIENT_PUBLIC_KEY}"
log_info ""
log_info "To use this configuration on the client:"
log_info "  1. Copy ${CLIENT_CONFIG} to the client device"
log_info "  2. Import it into WireGuard client or use:"
log_info "     wg-quick up ${USER_NAME}"

if command -v qrencode &> /dev/null; then
    QR_FILE="${OUTPUT_DIR}/${USER_NAME}.png"
    log_info ""
    log_info "Generating QR code: ${QR_FILE}"
    qrencode -t png -o "$QR_FILE" < "$CLIENT_CONFIG"
    log_info "QR code saved for mobile clients."
elif [ "$FORCE_QR" = true ]; then
    log_warning "qrencode not found. Install it to generate QR codes:"
    log_warning "  apt-get install qrencode  # Debian/Ubuntu"
    log_warning "  yum install qrencode      # RHEL/CentOS"
fi