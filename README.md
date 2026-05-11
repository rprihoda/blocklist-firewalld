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

```bash
# Run the full setup (create ipsets, flush, and populate)
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
