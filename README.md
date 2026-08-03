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

The tool is a single self-contained module. Pick whichever style you prefer.

**Option 1 - run it straight from the checkout:**

```bash
# Clone the repository
git clone <repository-url>
cd blocklist-firewalld

# Make the script executable
chmod +x blocklist_firewalld.py

# Copy to your preferred location (optional)
sudo cp blocklist-firewalld.py /usr/local/bin/
```

**Option 2 - install it as a command:**

```bash
# Installs a 'blocklist-firewalld' command onto PATH
sudo pip install .

# ...or, to keep it isolated from system packages
sudo pipx install .

blocklist-firewalld --help
```

When installed this way, put your configuration in `/etc/blocklist/blocklist.json`
(see [Configuration](#configuration)) - the script directory is inside
`site-packages` and is not a useful place for it.

> **Note:** `blocklist-firewalld.py` is a symlink to `blocklist_firewalld.py`.
> Python module names cannot contain hyphens, so the underscore name is the real
> file; the hyphenated symlink keeps `./blocklist-firewalld.py` (and existing cron
> entries) working. `cp` follows the symlink, so copying either name works.

## Manual

Everything lives in a single script driven by sub-commands.

```
usage: blocklist-firewalld.py [-h] [-c PATH] [-v] [-n] COMMAND ...

Load blocklists into firewalld using ipsets.

positional arguments:
  COMMAND
    setup               create + flush + populate (default)
    create              create ipsets and firewalld rules
    populate            download blocklists and load the IPs
    flush               empty the ipsets, keeping them in place
    clean               remove the firewalld rules, keep the ipsets
    revert              undo all firewall changes: remove rules and delete ipsets
    show                show the current ipsets and rules
    generate            write a blocklist.json configuration
    cloudflare          manage the Cloudflare allowlist (never block Cloudflare's own IPs)

options:
  -h, --help            show this help message and exit
  -c PATH, --config PATH
                        path to blocklist.json (default: search $HOME,
                        /etc/blocklist, script directory)
  -v, --verbose         show every command as it runs
  -n, --dry-run         show what would change without touching anything

Run without a sub-command to perform the full setup (create + flush + populate).
```

### Sub-commands

| Sub-command | What it does |
| --- | --- |
| `setup` | Runs `create`, `flush` and `populate` in sequence. This is the default when no sub-command is given. |
| `create` | Creates the ipsets and adds the firewalld rules that block them. Safe to re-run: existing ipsets and rules are left alone. |
| `populate` | Downloads the blocklists and loads the IPs into the ipsets. |
| `flush` | Empties the ipsets (removes all IPs) but keeps the ipsets and rules. |
| `clean` | Removes the firewalld rules but keeps the ipsets. Useful before recreating rules. |
| `revert` | **Full undo.** Removes the rules *and* deletes the ipsets, returning the firewall to its pre-setup state. |
| `show` | Prints the current ipsets, their entry counts, and the rules that reference them. |
| `generate` | Writes a `blocklist.json` configuration (replaces the old `generate-blocklist.py`). |
| `cloudflare` | Manages a safety-net allowlist so this tool can never block Cloudflare itself. See [Cloudflare Allowlist](#cloudflare-allowlist). |

### Global Options

These work before or after the sub-command (`-n revert` and `revert -n` are equivalent):

- `-c PATH`, `--config PATH`: use a specific `blocklist.json` instead of searching the default locations
- `-v`, `--verbose`: print every external command as it runs
- `-n`, `--dry-run`: print what *would* change without modifying the firewall. Read-only queries still run, so the output reflects the real current state. Works without root.

The old flags (`--create`, `--flush`, `--populate`, `--clean`) still work but are
deprecated; they are translated to the matching sub-command with a notice.

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

Besides the per-service [blocklist.de](https://lists.blocklist.de) lists, the `generate`
sub-command can build a configuration from the country IP blocks published by
[ipdeny.com](https://www.ipdeny.com/ipblocks/).

The `allow-us` mode blocks **all countries except the United States**, which is useful for
services that should only be reachable domestically.

**⚠️ Check which configuration is active before you run anything** - `blocklist.json`
may already have been switched to country mode:

```bash
./blocklist-firewalld.py -v show --no-counts | head -3
```

**⚠️ IMPORTANT WARNINGS (for `allow-us` mode):**

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

**The `generate` sub-command:**

Use `generate` to switch between blocklist configurations. It only writes
`blocklist.json` - it never touches the firewall, so it does not need root.

```bash
# Generate blocklist for only common threat countries (RECOMMENDED)
./blocklist-firewalld.py generate --mode block-threats

# Generate blocklist blocking all countries except US (232 ipsets)
./blocklist-firewalld.py generate --mode allow-us

# Generate blocklist for specific countries
./blocklist-firewalld.py generate --mode block-specific --countries cn,ru,ir,kp

# Restore the original blocklist.de configuration (the shipped default)
./blocklist-firewalld.py generate --mode blocklist-de

# Write somewhere else, or use the larger non-aggregated zone files
./blocklist-firewalld.py generate --mode block-threats --output /etc/blocklist/blocklist.json
./blocklist-firewalld.py generate --mode allow-us --no-aggregated
```

**⚠️ Changing the configuration does not change the firewall.** After generating a
new `blocklist.json`, the ipsets from the *previous* configuration are still in
place. Either `revert` first, or `revert` afterwards to clean up the leftovers
(it detects ipsets that are no longer in the config - see
[Reverting Changes](#reverting-changes)).

```bash
# Recommended order when switching configurations
sudo ./blocklist-firewalld.py revert          # undo the old configuration
./blocklist-firewalld.py generate --mode block-threats
sudo ./blocklist-firewalld.py setup           # apply the new one
```

**To restore the original configuration from the shipped backup instead:**
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

**⚠️ The ipsets themselves are permanent, but their entries are not.** `populate`
loads IPs into the *runtime* configuration, so a `firewall-cmd --reload` (or a
reboot) leaves the ipsets in place but empty. The rules survive; the IP lists do
not. Re-run `populate` afterwards - or rely on the
[cron job](#automated-updates-via-cron) to refill them on the next run.

## Usage

### Initial Setup

**Always preview first.** `--dry-run` needs no root, changes nothing, and tells you
exactly how many ipsets the active `blocklist.json` will create - a 3-entry
blocklist.de config and a 232-entry country config behave very differently:

```bash
./blocklist-firewalld.py --dry-run setup
```

When the output looks right, apply it:

```bash
# Run the full setup (create ipsets, flush, and populate)
sudo python3 blocklist-firewalld.py setup
```

`setup` is the default, so `sudo python3 blocklist-firewalld.py` does the same thing.

**To switch to the per-service blocklist.de lists:**

```bash
./blocklist-firewalld.py generate --mode blocklist-de
sudo ./blocklist-firewalld.py setup
```

**To use country-based blocking:**

```bash
# RECOMMENDED: threat countries only (6 ipsets)
./blocklist-firewalld.py generate --mode block-threats
sudo ./blocklist-firewalld.py setup

# Or block everything except the US
# WARNING: 232 ipsets, takes 10-30 minutes to populate
./blocklist-firewalld.py generate --mode allow-us
sudo ./blocklist-firewalld.py setup
```

### Individual Commands

```bash
# Create ipsets and add firewalld rules
sudo ./blocklist-firewalld.py create

# Download blocklists and populate ipsets
sudo ./blocklist-firewalld.py populate

# Flush (empty) the ipsets
sudo ./blocklist-firewalld.py flush

# Show what is currently in place
sudo ./blocklist-firewalld.py show
```

Add `-v` to see each `firewall-cmd` invocation, or `-n` to preview without changing anything.

### Reverting Changes

There are two levels of undo:

| Command | Removes rules | Deletes ipsets | Use when |
| --- | --- | --- | --- |
| `clean` | yes | no | You want to recreate the rules but keep the downloaded IPs |
| `revert` | yes | yes | You want the firewall back the way it was before setup |

```bash
# Remove the firewalld rules, keep the ipsets and their contents
sudo ./blocklist-firewalld.py clean

# Full undo: remove the rules AND delete the ipsets
sudo ./blocklist-firewalld.py revert
```

`revert` prints a summary and asks for confirmation before touching anything:

```
About to revert the firewall changes for 4 ipset(s):
  every rule and zone source referencing them will be removed
  4 ipset(s) will be deleted
  1 are not in the current config: country-old
Continue? [y/N]
```

What `revert` does, in order:

1. Scans **every** zone (not just the default one) for rich rules and sources that reference a managed ipset
2. Removes those rich rules and `ipset:` sources
3. Deletes the ipsets from the permanent configuration
4. Reloads firewalld

Useful flags:

```bash
# Skip the confirmation prompt (for scripts)
sudo ./blocklist-firewalld.py revert --yes

# See exactly what would be removed, without changing anything
./blocklist-firewalld.py revert --dry-run

# Only touch ipsets named in the current blocklist.json
sudo ./blocklist-firewalld.py revert --only-config
```

By default `revert` also cleans up **leftovers**: any ipset named `blocklist-*` or
`country-*` that is still in firewalld but no longer in your `blocklist.json`. This is
what you want after switching configurations (e.g. from `allow-us` to `block-threats`),
since those 200+ orphaned ipsets would otherwise keep filtering traffic forever. Pass
`--only-config` if you have ipsets with those prefixes that you manage yourself.

### Cloudflare Allowlist

**If your site is behind Cloudflare, read this before running `setup`/`create`.**

Cloudflare's IP ranges are shared by every site on their network. This tool's
blocklists can end up blocking Cloudflare itself in two ways:

1. **Abuse lists (blocklist.de) flag a Cloudflare edge IP.** These lists are
   crowd-sourced from server logs across the internet. If some *other*
   Cloudflare-fronted site gets attacked, the victim's logs show Cloudflare's
   edge IP as the source (not the real attacker), and that IP can get reported
   and land on the public abuse list. Once it's downloaded into your
   `blocklist-443`/`blocklist-80` ipset, your rich rule drops **anyone**
   connecting from it on that port - including Cloudflare connecting to your
   own origin. Symptom: intermittent Cloudflare 521/522/525 errors for
   visitors, with no obvious cause in your application logs.
2. **Country-based blocking (`allow-us` / `block-specific`) drops a whole
   country's netblocks**, which can include Cloudflare PoPs registered in
   that country - even though Cloudflare isn't the threat. This is a
   well-known gotcha with any geo-IP firewall in front of a CDN-fronted site.

**The fix:** `blocklist-firewalld.py create` (and therefore `setup`, and
therefore the default cron-driven run) automatically maintains a small
allowlist alongside your regular blocklists:

- Two ipsets, `cloudflare-allow` (IPv4) and `cloudflare-allow6` (IPv6),
  populated straight from Cloudflare's own
  [published ranges](https://www.cloudflare.com/ips/) - refreshed on every
  `create`/`setup` run, with a built-in fallback snapshot if the download
  fails (e.g. no internet access at that moment).
- A rich rule in every zone this tool manages, with a very low priority
  (`-32000`) that `accept`s traffic from those ipsets. Firewalld evaluates
  rich rules in ascending priority order and stops at the first match, so
  this ACCEPT is always checked - and always wins - **before** any DROP rule
  this tool adds at the default priority of `0`. It doesn't matter what later
  ends up in an abuse list or a country ipset: Cloudflare's own ranges are
  never blocked by this tool.
- Deliberately excluded from `clean`/`revert`'s cleanup: undoing your
  blocklists never removes this safety net.

This is **on by default**. To check, enable, refresh, or remove it explicitly:

```bash
# Show whether Cloudflare is currently protected
./blocklist-firewalld.py cloudflare status

# Create/refresh the allowlist ipsets and accept rules right now
# (useful immediately after upgrading the script, without waiting for setup/create)
sudo ./blocklist-firewalld.py cloudflare enable

# Remove the allowlist entirely (Cloudflare becomes subject to your
# regular blocklists/country rules again)
sudo ./blocklist-firewalld.py cloudflare disable
```

To opt out (not recommended if you're behind Cloudflare):

```bash
sudo ./blocklist-firewalld.py create --no-cloudflare-allowlist
sudo ./blocklist-firewalld.py setup  --no-cloudflare-allowlist
```

#### Diagnosing an active "Cloudflare can't reach my site" incident

If Cloudflare is *currently* unable to reach your origin, apply the allowlist
immediately - it takes effect right away and is safe to run at any time:

```bash
sudo ./blocklist-firewalld.py cloudflare enable
```

To confirm a Cloudflare IP was actually the culprit (rather than something
else, like an expired origin cert or a DNS/routing issue), check whether any
current Cloudflare range appears in your abuse-list ipsets:

```bash
# Get Cloudflare's current ranges
curl -s https://www.cloudflare.com/ips-v4

# Compare against what's actually blocked on port 443
sudo firewall-cmd --ipset=blocklist-443 --get-entries
sudo firewall-cmd --ipset=blocklist-80 --get-entries
```

If you were using country-based blocking (`allow-us`/`block-specific`) and
Cloudflare access was flaky rather than fully broken, that's consistent with
only *some* Cloudflare PoPs (those geolocated to blocked countries) being
affected - `cloudflare enable` fixes this too, since the accept rule is
zone-wide and doesn't care which ipset would otherwise have caught the IP.

### Verify Configuration

The quickest check is the built-in `show` sub-command, which summarises every
configured ipset and the rules that reference it:

```bash
sudo ./blocklist-firewalld.py show
```

```
default zone: public
ipsets: 3 runtime, 3 permanent, 3 configured

IPSET           STATE      ENTRIES
blocklist-443   active     2841
blocklist-80    active     1204
blocklist-ssh   active     1523

zone drop: 0 ipset rich rule(s), 0 ipset source(s)

zone public: 3 ipset rich rule(s), 0 ipset source(s)
  rule source ipset="blocklist-443" port port="443" protocol="tcp" drop
  rule source ipset="blocklist-80" port port="80" protocol="tcp" drop
  rule source ipset="blocklist-ssh" port port="22" protocol="tcp" drop
```

The `STATE` column shows `active` (loaded in the runtime configuration), `reload`
(exists permanently but not loaded yet - run `sudo firewall-cmd --reload`), or
`missing` (not created yet - run `create`). Use `show --no-counts` to skip the
entry counts, which is much faster with hundreds of ipsets.

#### Inspecting with firewall-cmd directly

All ipsets are created as **permanent firewalld ipsets**, so you can inspect
them directly with `firewall-cmd` (no need to fall back to the raw `ipset` tool).

**List the names of all ipsets known to firewalld:**

```bash
sudo firewall-cmd --get-ipsets
```

```
blocklist-ssh blocklist-80 blocklist-443
```

**Show an ipset's configuration (type, options) and its entries:**

```bash
sudo firewall-cmd --info-ipset=blocklist-ssh
```

```
blocklist-ssh
  type: hash:net
  options: family=inet hashsize=4096 maxelem=200000
  entries: 1.2.3.4 5.6.7.8 203.0.113.0/24
```

**List only the entries (IPs / networks) in an ipset:**

```bash
sudo firewall-cmd --ipset=blocklist-ssh --get-entries
```

```
1.2.3.4
5.6.7.8
203.0.113.0/24
```

**Count how many entries an ipset currently holds:**

```bash
sudo firewall-cmd --ipset=blocklist-ssh --get-entries | wc -l
```

```
1523
```

**View the rich rules in your default zone (shows which ipsets block which ports):**

```bash
sudo firewall-cmd --list-rich-rules
```

```
rule source ipset="blocklist-ssh" port port="22" protocol="tcp" drop
rule source ipset="blocklist-80" port port="80" protocol="tcp" drop
rule source ipset="blocklist-443" port port="443" protocol="tcp" drop
```

**For ipsets without a port mapping, confirm they are bound to the drop zone:**

```bash
sudo firewall-cmd --zone=drop --list-sources
```

```
ipset:country-cn ipset:country-ru
```

> **Note:** `--get-ipsets`, `--info-ipset`, and `--get-entries` operate on the
> **runtime** configuration by default. Add `--permanent` to inspect the
> permanent configuration instead (e.g. `sudo firewall-cmd --permanent --get-ipsets`).
> If runtime and permanent differ, run `sudo firewall-cmd --reload` to apply the
> permanent configuration.

You can still inspect entries with the raw `ipset` tool if you prefer:

```bash
sudo ipset list blocklist-ssh
```

### Automated Updates via Cron

Run the script as a cronjob to keep your blocklists updated. The following example runs the script at 3AM every day.

```bash
# Edit root's crontab
sudo crontab -e

# Add this line to update daily at 3AM
0 3 * * * /usr/bin/python3 /root/bin/blocklist-firewalld.py setup
```

**Note:** `setup` (the default when no sub-command is given) creates any missing
ipsets, flushes them, and repopulates them with fresh data.

If you only need to refresh the IPs and the ipsets already exist, `populate` is
enough - though note that it *adds* to the existing entries, so pair it with
`flush` for a clean refresh:

```bash
0 3 * * * /usr/bin/python3 /root/bin/blocklist-firewalld.py flush && /usr/bin/python3 /root/bin/blocklist-firewalld.py populate
```
