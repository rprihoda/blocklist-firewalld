# blocklist-firewalld
Create [ipset](https://ipset.netfilter.org/) lists from blocklists managed by [firewalld](https://firewalld.org/).

## Requirements

### System Requirements
- Python 3.7 or higher
- firewalld
- ipset
- curl
- sed

### Python Dependencies
No external Python packages required! This script uses only Python standard library.

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd blocklist-firewalld

# Make the script executable
chmod +x blocklist-firewalld.py

# Copy to your preferred location (optional)
sudo cp blocklist-firewalld.py /usr/local/bin/
```

## Manual

```
usage: blocklist-firewalld.py [-h] [--create] [--flush] [--populate] [--clean]

A script to load specified blocklist with firewalld using ipsets.

options:
  -h, --help  show this help message and exit
  --create    Create ipsets
  --flush     Flush existing ipsets
  --populate  Import list of IPs from files
  --clean     Remove existing ipset rich rules from firewalld
```

### Command Options

- `--create`: Creates ipsets and adds firewalld rich rules to block the IPs on specific ports
- `--flush`: Empties the ipsets (removes all IPs from them)
- `--populate`: Downloads blocklists and populates the ipsets with IPs
- `--clean`: Removes the rich rules from firewalld (useful before recreating)
- No arguments: Runs create, flush, and populate in sequence (full setup)

## Configuration

Create a JSON file called blocklist.json in one of the following locations:
 - /etc/blocklist/blocklist.json
 - $HOME/blocklist.json
 - "Right next to the script"

Its format is pretty simple. Key is the URL of the blocklist, the value is the name of the ipset it creates from the blocklist.

```json
{
    "https://lists.blocklist.de/lists/ssh.txt" : "blocklist-ssh",
    "https://lists.blocklist.de/lists/80.txt" : "blocklist-80",
    "https://lists.blocklist.de/lists/443.txt" : "blocklist-443"
}
```

You can find further readily available blocklists on the following sites.
 - https://lists.blocklist.de
 - https://www.ipdeny.com/ipblocks/

### Country-Based Blocking

The included `blocklist.json` contains IP blocks for **all countries except the United States**.
This is useful for blocking international traffic to services that should only be accessible domestically.

**⚠️ IMPORTANT WARNINGS:**

1. **This will block ALL traffic from non-US IP addresses** - including:
   - Legitimate international users
   - VPN users appearing to be from other countries
   - Cloud services hosted internationally
   - CDN endpoints
   - Your own traffic if traveling abroad

2. **System Resource Impact:**
   - **232 ipsets** will be created (one per country)
   - Each ipset can contain thousands of IP blocks
   - This uses significant system memory
   - Initial population can take 10-30 minutes
   - Recommended minimum: 4GB RAM

3. **Firewall Performance:**
   - More ipsets = slower firewall rule processing
   - May impact network performance on high-traffic systems
   - Consider blocking only high-risk countries instead of all countries

**Alternative Approach - Block Specific Countries:**

Instead of blocking all countries except US, consider blocking only high-risk countries:

```json
{
    "https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone": "country-cn",
    "https://www.ipdeny.com/ipblocks/data/aggregated/ru-aggregated.zone": "country-ru",
    "https://www.ipdeny.com/ipblocks/data/aggregated/kp-aggregated.zone": "country-kp",
    "https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone": "country-ir"
}
```

**Helper Script - `generate-blocklist.py`:**

Use the included helper script to easily switch between different blocklist configurations:

```bash
# Generate blocklist for only common threat countries (RECOMMENDED)
./generate-blocklist.py --mode block-threats

# Generate blocklist blocking all countries except US (current config)
./generate-blocklist.py --mode allow-us

# Generate blocklist for specific countries
./generate-blocklist.py --mode block-specific --countries cn,ru,ir,kp

# Revert to original blocklist.de configuration
./generate-blocklist.py --mode blocklist-de
```

**To restore the original blocklist.de configuration manually:**
```bash
cp blocklist.json.backup blocklist.json
```

### How It Works

The script automatically creates **firewalld rich rules** that apply ipsets to specific ports:

- `blocklist-ssh` → Blocks IPs on **port 22** (SSH)
- `blocklist-80` → Blocks IPs on **port 80** (HTTP)
- `blocklist-443` → Blocks IPs on **port 443** (HTTPS)

The rich rules are added to your **default zone** (usually `public`), so they work alongside your existing firewall configuration.

**Example rich rule created:**
```
rule source ipset=blocklist-ssh port port=22 protocol=tcp drop
```

If you add custom ipsets that don't match the naming pattern, they'll be added to the `drop` zone instead (blocking all traffic from those IPs).

## Usage

### Initial Setup

**IMPORTANT:** The current `blocklist.json` blocks ALL countries except the US (232 countries).
This may not be what you want! Consider using the threat-only mode instead:

```bash
# RECOMMENDED: Generate threat-only blocklist (6 countries)
./generate-blocklist.py --mode block-threats

# Then run the setup
sudo python3 blocklist-firewalld.py
```

**Or proceed with the full country block:**

```bash
# Run the full setup (create ipsets, flush, and populate)
# WARNING: This will block 232 countries and take 10-30 minutes
sudo python3 blocklist-firewalld.py
```

### Individual Commands

```bash
# Create ipsets and add firewalld rich rules
sudo python3 blocklist-firewalld.py --create

# Download blocklists and populate ipsets
sudo python3 blocklist-firewalld.py --populate

# Flush (empty) the ipsets
sudo python3 blocklist-firewalld.py --flush

# Remove firewalld rich rules
sudo python3 blocklist-firewalld.py --clean
```

### Verify Configuration

```bash
# Check if ipsets were created
sudo firewall-cmd --get-ipsets

# View rich rules in your default zone
sudo firewall-cmd --list-rich-rules

# Check ipset contents
sudo ipset list blocklist-ssh
```

### Automated Updates via Cron

Run the script as a cronjob to keep your blocklists updated. The following example runs the script at 3AM every day.

```bash
# Edit root's crontab
sudo crontab -e

# Add this line to update daily at 3AM
0 3 * * * /usr/bin/python3 /root/bin/blocklist-firewalld.py
```

**Note:** The default behavior (no arguments) will recreate ipsets, flush them, and repopulate with fresh data.
