#!/usr/bin/env python3
"""blocklist-firewalld - manage firewalld ipset blocklists.

Sub-commands:
  setup     create + flush + populate (the default when no sub-command is given)
  create    create the ipsets and the firewalld rules that use them
  populate  download the blocklists and load the IPs into the ipsets
  flush     empty the ipsets without removing them
  clean     remove the firewalld rules but keep the ipsets
  revert    undo every firewall change: rules *and* ipsets
  generate  write a blocklist.json configuration
  show      show the current state of the managed ipsets and rules
  cloudflare  manage the Cloudflare allowlist (never block Cloudflare itself)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from collections import namedtuple
from pathlib import Path

CONFIG_NAME = "blocklist.json"
DOT_CONFIG_NAME = "." + CONFIG_NAME
ETC_CONFIG_DIR = "/etc/blocklist"

IPSET_TYPE = "hash:net"
IPSET_OPTIONS = ("family=inet", "hashsize=4096", "maxelem=200000")

# ipsets named after a service/port get a rich rule scoped to that port.
# Anything else is dropped outright via the fallback zone.
PORT_MAP = {"blocklist-ssh": "22", "blocklist-80": "80", "blocklist-443": "443"}
FALLBACK_ZONE = "drop"

# Used by `revert` to find leftovers from a previous configuration.
MANAGED_PREFIXES = ("blocklist-", "country-")

RICH_RULE_IPSET_RE = re.compile(r'ipset="?([^"\s]+)"?')

# All country codes available from ipdeny.com
# fmt: off
ALL_COUNTRIES = (
    "af", "ax", "al", "dz", "as", "ad", "ao", "ai", "aq", "ag", "ar", "am",
    "aw", "au", "at", "az", "bs", "bh", "bd", "bb", "by", "be", "bz", "bj",
    "bm", "bt", "bo", "ba", "bw", "br", "io", "bn", "bg", "bf", "bi", "kh",
    "cm", "ca", "cv", "ky", "cf", "td", "cl", "cn", "cc", "co", "km", "cg",
    "cd", "ck", "cr", "ci", "hr", "cu", "cy", "cz", "dk", "dj", "dm", "do",
    "ec", "eg", "sv", "gq", "er", "ee", "et", "fk", "fo", "fj", "fi", "fr",
    "gf", "pf", "ga", "gm", "ge", "de", "gh", "gi", "gr", "gl", "gd", "gp",
    "gu", "gt", "gn", "gw", "gy", "ht", "va", "hn", "hk", "hu", "is", "in",
    "id", "ir", "iq", "ie", "im", "il", "it", "jm", "jp", "je", "jo", "kz",
    "ke", "ki", "kp", "kr", "kw", "kg", "la", "lv", "lb", "ls", "lr", "ly",
    "li", "lt", "lu", "mo", "mk", "mg", "mw", "my", "mv", "ml", "mt", "mh",
    "mq", "mr", "mu", "yt", "mx", "fm", "md", "mc", "mn", "me", "ms", "ma",
    "mz", "mm", "na", "nr", "np", "nl", "nc", "nz", "ni", "ne", "ng", "nu",
    "nf", "mp", "no", "om", "pk", "pw", "ps", "pa", "pg", "py", "pe", "ph",
    "pl", "pt", "pr", "qa", "re", "ro", "ru", "rw", "kn", "lc", "pm", "vc",
    "ws", "sm", "st", "sa", "sn", "rs", "sc", "sl", "sg", "sk", "si", "sb",
    "so", "za", "es", "lk", "sd", "sr", "sz", "se", "ch", "sy", "tw", "tj",
    "tz", "th", "tl", "tg", "tk", "to", "tt", "tn", "tr", "tm", "tc", "tv",
    "ug", "ua", "ae", "gb", "um", "us", "uy", "uz", "vu", "ve", "vn", "vg",
    "vi", "wf", "ye", "zm", "zw",
)
# fmt: on

COMMON_THREATS = {
    "cn": "China",
    "ru": "Russia",
    "kp": "North Korea",
    "ir": "Iran",
    "sy": "Syria",
    "by": "Belarus",
}

BLOCKLIST_DE = {
    "https://lists.blocklist.de/lists/ssh.txt": "blocklist-ssh",
    "https://lists.blocklist.de/lists/80.txt": "blocklist-80",
    "https://lists.blocklist.de/lists/443.txt": "blocklist-443",
}

# Cloudflare's IP ranges are shared by every site behind Cloudflare. If any
# other Cloudflare-fronted site gets attacked and its logs show Cloudflare's
# edge IP as the source, that IP can land on abuse lists like blocklist.de -
# and then in *your* ipsets, blocking Cloudflare itself from reaching your
# origin. Country-based blocking has the same problem: it can drop whole
# netblocks that include Cloudflare PoPs. See ensure_cloudflare_allowlist().
CLOUDFLARE_IPV4_URL = "https://www.cloudflare.com/ips-v4"
CLOUDFLARE_IPV6_URL = "https://www.cloudflare.com/ips-v6"
CLOUDFLARE_IPSET_V4 = "cloudflare-allow"
CLOUDFLARE_IPSET_V6 = "cloudflare-allow6"
CLOUDFLARE_IPSETS = (CLOUDFLARE_IPSET_V4, CLOUDFLARE_IPSET_V6)
# Lower than any rich rule's default priority (0), so this ACCEPT is always
# evaluated - and wins, since rich rule actions are terminal - before a DROP
# rule at the default priority.
CLOUDFLARE_ACCEPT_PRIORITY = "-32000"

# Used only if the live download fails (e.g. no internet access). Cloudflare's
# ranges rarely change; run 'cloudflare refresh' to update this snapshot's
# in-firewall copy whenever possible. Last synced 2026-07-29 from
# cloudflare.com/ips-v4 and cloudflare.com/ips-v6.
CLOUDFLARE_FALLBACK_V4 = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)
CLOUDFLARE_FALLBACK_V6 = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)

LEGACY_FLAGS = {
    "--create": "create",
    "--flush": "flush",
    "--populate": "populate",
    "--clean": "clean",
}

Result = namedtuple("Result", "ok returncode lines stderr")


# --------------------------------------------------------------------------- #
# command execution
# --------------------------------------------------------------------------- #


class Runner:
    """Runs external commands, honouring --dry-run and --verbose."""

    def __init__(self, verbose=False, dry_run=False):
        self.verbose = verbose
        self.dry_run = dry_run
        self.failures = 0

    def log(self, message):
        if self.verbose:
            print(message)

    @staticmethod
    def warn(message):
        print("warning: " + message, file=sys.stderr)

    def run(self, argv, description=None, mutating=True, quiet=False):
        """Run argv and return a Result.

        Commands flagged as mutating are skipped (and printed) in dry-run mode;
        read-only probes always run so the logic still sees real state.
        """
        if description:
            self.log(description)

        pretty = " ".join(shlex.quote(part) for part in argv)
        if mutating and self.dry_run:
            print("[dry-run] " + pretty)
            return Result(True, 0, [], "")

        self.log("  $ " + pretty)
        try:
            proc = subprocess.run(
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
        except OSError as exc:
            if not quiet:
                self.failures += 1
                self.warn("could not run %s: %s" % (argv[0], exc))
            return Result(False, 127, [], str(exc))

        stderr = (proc.stderr or "").strip()
        if proc.returncode != 0 and not quiet:
            self.failures += 1
            self.warn(
                "%s failed (exit %d)%s"
                % (pretty, proc.returncode, ": " + stderr if stderr else "")
            )
        return Result(
            proc.returncode == 0,
            proc.returncode,
            (proc.stdout or "").splitlines(),
            stderr,
        )


def die(message, code=1):
    print("error: " + message, file=sys.stderr)
    raise SystemExit(code)


def require_root(runner):
    if runner.dry_run or not hasattr(os, "geteuid"):
        return
    if os.geteuid() != 0:
        die(
            "this command changes the firewall and must be run as root "
            "(try sudo, or use --dry-run)"
        )


def require_firewalld(runner):
    if shutil.which("firewall-cmd") is None:
        die("firewall-cmd not found; is firewalld installed?")
    state = runner.run(["firewall-cmd", "--state"], mutating=False, quiet=True)
    if not state.ok:
        detail = state.stderr or "\n".join(state.lines) or "unknown error"
        die("cannot talk to firewalld: %s" % " ".join(detail.split()))


def find_ipset_binary():
    for candidate in ("ipset", "/usr/sbin/ipset", "/sbin/ipset"):
        found = shutil.which(candidate) if "/" not in candidate else candidate
        if found and Path(found).exists():
            return found
    return None


# --------------------------------------------------------------------------- #
# configuration
# --------------------------------------------------------------------------- #


def config_candidates():
    home = Path.home()
    return [
        home / CONFIG_NAME,
        home / DOT_CONFIG_NAME,
        Path(ETC_CONFIG_DIR) / CONFIG_NAME,
        Path(__file__).resolve().parent / CONFIG_NAME,
    ]


def find_config(explicit=None):
    if explicit:
        path = Path(explicit).expanduser()
        if not path.is_file():
            die("config file not found: %s" % path)
        return path
    for candidate in config_candidates():
        if candidate.is_file():
            return candidate
    die(
        "no %s found; looked in:\n  %s"
        % (
            CONFIG_NAME,
            "\n  ".join(str(c) for c in config_candidates()),
        )
    )


def load_config(explicit=None):
    """Return {url: ipset_name} from the first config file found."""
    path = find_config(explicit)
    try:
        with open(str(path)) as handle:
            data = json.load(handle)
    except ValueError as exc:
        die("%s is not valid JSON: %s" % (path, exc))
    except OSError as exc:
        die("could not read %s: %s" % (path, exc))

    if not isinstance(data, dict) or not data:
        die("%s must be a non-empty JSON object of {url: ipset-name}" % path)

    for url, name in data.items():
        if not isinstance(name, str) or not name:
            die("%s: ipset name for %s must be a non-empty string" % (path, url))

    seen = {}
    for url, name in data.items():
        seen.setdefault(name, []).append(url)
    for name, urls in seen.items():
        if len(urls) > 1:
            Runner.warn(
                "ipset '%s' is used by %d URLs; entries will be merged"
                % (name, len(urls))
            )

    return path, data


def sorted_lists(config):
    """Config as [(url, ipset_name)] sorted by ipset name for stable output."""
    return sorted(config.items(), key=lambda item: item[1])


# --------------------------------------------------------------------------- #
# firewalld helpers
# --------------------------------------------------------------------------- #


def fw(runner, *args, **kwargs):
    return runner.run(["firewall-cmd"] + list(args), **kwargs)


def get_default_zone(runner):
    result = fw(runner, "--get-default-zone", mutating=False, quiet=True)
    return result.lines[0].strip() if result.ok and result.lines else "public"


def get_zones(runner):
    result = fw(runner, "--permanent", "--get-zones", mutating=False, quiet=True)
    zones = " ".join(result.lines).split() if result.ok else []
    return zones or [get_default_zone(runner), FALLBACK_ZONE]


def get_ipsets(runner, permanent=False):
    args = ["--permanent"] if permanent else []
    result = fw(runner, *(args + ["--get-ipsets"]), mutating=False, quiet=True)
    return set(" ".join(result.lines).split()) if result.ok else set()


def get_entries(runner, name):
    result = fw(runner, "--ipset=" + name, "--get-entries", mutating=False, quiet=True)
    return [line.strip() for line in result.lines if line.strip()]


def list_rich_rules(runner, zone, permanent=True):
    args = ["--permanent"] if permanent else []
    result = fw(
        runner,
        *(args + ["--zone=" + zone, "--list-rich-rules"]),
        mutating=False,
        quiet=True,
    )
    return [line.strip() for line in result.lines if line.strip()]


def list_sources(runner, zone, permanent=True):
    args = ["--permanent"] if permanent else []
    result = fw(
        runner,
        *(args + ["--zone=" + zone, "--list-sources"]),
        mutating=False,
        quiet=True,
    )
    return " ".join(result.lines).split() if result.ok else []


def rich_rule(name, port):
    return "rule source ipset=%s port port=%s protocol=tcp drop" % (name, port)


def rule_ipset(rule):
    match = RICH_RULE_IPSET_RE.search(rule)
    return match.group(1) if match else None


def reload_firewalld(runner):
    fw(runner, "--reload", description="Reloading firewalld")


def ensure_ipset(runner, name, family):
    """Create a permanent ipset if missing. Returns True if it was created."""
    if name in get_ipsets(runner, permanent=True):
        runner.log("ipset already exists: " + name)
        return False
    non_family_options = [o for o in IPSET_OPTIONS if not o.startswith("family=")]
    options = ["--option=family=" + family] + [
        "--option=" + option for option in non_family_options
    ]
    result = fw(
        runner,
        "--permanent",
        "--new-ipset=" + name,
        "--type=" + IPSET_TYPE,
        *options,
        description="Creating ipset " + name,
    )
    return result.ok


# --------------------------------------------------------------------------- #
# Cloudflare allowlist
#
# Two ipsets (v4 + v6) populated with Cloudflare's official ranges, each
# backed by a rich rule with a very low (negative) priority in every zone
# this tool touches. Rich rule actions are terminal and evaluated in
# ascending priority order, so this ACCEPT rule is always checked - and always
# wins - before any DROP rule added at the default priority of 0, regardless
# of what later shows up in an abuse blocklist or a country ipset.
#
# Deliberately NOT covered by MANAGED_PREFIXES: 'clean' and 'revert' must
# never remove this safety net, even when clearing out every blocklist ipset.
# --------------------------------------------------------------------------- #


def cloudflare_zones(runner):
    """Zones this tool has to protect: wherever it might add a DROP rule."""
    return sorted({get_default_zone(runner), FALLBACK_ZONE})


def cloudflare_accept_rule(name):
    return "rule priority=%s source ipset=%s accept" % (
        CLOUDFLARE_ACCEPT_PRIORITY,
        name,
    )


def fetch_cloudflare_ranges(runner, url, fallback, tmpfile):
    """Download url into tmpfile; fall back to the embedded snapshot on failure."""
    if shutil.which("curl") is not None:
        result = runner.run(
            ["curl", "-sSfL", "--retry", "2", "-o", str(tmpfile), url],
            description="Downloading " + url,
        )
        downloaded = result.ok and (
            runner.dry_run or (tmpfile.is_file() and tmpfile.stat().st_size > 0)
        )
        if downloaded:
            return
        runner.warn("could not download %s; using the built-in snapshot instead" % url)
    else:
        runner.warn("curl not found; using the built-in Cloudflare IP snapshot")

    if not runner.dry_run:
        tmpfile.write_text("\n".join(fallback) + "\n")


def ensure_cloudflare_allowlist(runner, zones=None):
    """Create/refresh the Cloudflare allowlist ipsets and their accept rules.

    Fully idempotent: existing ipsets and rules are left alone, but entries
    are always re-downloaded so the ranges stay current. Safe (and cheap - two
    small HTTP GETs) to call on every 'create'/'setup' run.

    require_root/require_firewalld are re-checked here (cheap, idempotent) so
    this is also safe to call directly, e.g. via 'cloudflare enable', not just
    as a side effect of 'create'.
    """
    require_root(runner)
    require_firewalld(runner)
    zones = zones if zones is not None else cloudflare_zones(runner)

    created = 0
    for name, family in ((CLOUDFLARE_IPSET_V4, "inet"), (CLOUDFLARE_IPSET_V6, "inet6")):
        if ensure_ipset(runner, name, family):
            created += 1

    ruled = 0
    for zone in zones:
        ruled_ipsets = set(
            filter(None, (rule_ipset(r) for r in list_rich_rules(runner, zone)))
        )
        for name in CLOUDFLARE_IPSETS:
            if name in ruled_ipsets:
                runner.log("Cloudflare accept rule already present in zone " + zone)
                continue
            result = fw(
                runner,
                "--permanent",
                "--zone=" + zone,
                "--add-rich-rule=" + cloudflare_accept_rule(name),
                description="Allowing Cloudflare (%s) ahead of block rules in zone %s"
                % (name, zone),
            )
            if result.ok:
                ruled += 1

    # Reload now so newly-created ipsets/rules are active at runtime before we
    # try to populate entries into them (mirrors create -> reload -> populate).
    reload_firewalld(runner)

    ipset_bin = find_ipset_binary()
    populated = 0
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdir = Path(tmpdirname)
        for name, url, fallback in (
            (CLOUDFLARE_IPSET_V4, CLOUDFLARE_IPV4_URL, CLOUDFLARE_FALLBACK_V4),
            (CLOUDFLARE_IPSET_V6, CLOUDFLARE_IPV6_URL, CLOUDFLARE_FALLBACK_V6),
        ):
            tmpfile = tmpdir / name
            fetch_cloudflare_ranges(runner, url, fallback, tmpfile)

            if ipset_bin is not None:
                # Keep the ipset in sync if Cloudflare ever retires a range,
                # instead of only ever adding to it.
                runner.run(
                    [ipset_bin, "flush", name],
                    description="Flushing ipset " + name,
                    quiet=True,
                )

            result = fw(
                runner,
                "--ipset=" + name,
                "--add-entries-from-file=" + str(tmpfile),
                description="Loading Cloudflare ranges into " + name,
            )
            if result.ok:
                populated += 1

    print(
        "cloudflare allowlist: created %d ipset(s), added %d accept rule(s), "
        "refreshed %d ipset(s)" % (created, ruled, populated)
    )
    return 0


def cmd_cloudflare_disable(runner, assume_yes=False):
    """Remove the Cloudflare allowlist: the accept rules AND the ipsets."""
    require_root(runner)
    require_firewalld(runner)

    zones = cloudflare_zones(runner)
    permanent = get_ipsets(runner, permanent=True)
    present = sorted(name for name in CLOUDFLARE_IPSETS if name in permanent)
    has_rules = any(
        rule_ipset(rule) in CLOUDFLARE_IPSETS
        for zone in zones
        for rule in list_rich_rules(runner, zone)
    )

    if not present and not has_rules:
        print("Cloudflare allowlist is not installed; nothing to do")
        return 0

    print("About to remove the Cloudflare allowlist.")
    print(
        "  Cloudflare will again be subject to your regular blocklists/country rules."
    )
    if not assume_yes and not runner.dry_run:
        if not confirm("Continue?"):
            print("aborted")
            return 1

    removed = remove_firewall_rules(runner, set(CLOUDFLARE_IPSETS))
    deleted = 0
    for name in present:
        result = fw(
            runner,
            "--permanent",
            "--delete-ipset=" + name,
            description="Deleting ipset " + name,
        )
        if result.ok:
            deleted += 1

    reload_firewalld(runner)
    print("removed %d rule(s), deleted %d ipset(s)" % (removed, deleted))
    return 0


def cmd_cloudflare_status(runner):
    require_firewalld(runner)

    zones = cloudflare_zones(runner)
    runtime = get_ipsets(runner)
    permanent = get_ipsets(runner, permanent=True)

    print("Cloudflare allowlist ipsets:")
    for name in CLOUDFLARE_IPSETS:
        if name in runtime:
            state = "active"
        elif name in permanent:
            state = "reload"
        else:
            state = "missing"
        count = len(get_entries(runner, name)) if name in runtime else "-"
        print("  %-20s %-9s entries: %s" % (name, state, count))

    print()
    print("accept rules:")
    any_rule = False
    for zone in zones:
        for rule in list_rich_rules(runner, zone):
            if rule_ipset(rule) in CLOUDFLARE_IPSETS:
                any_rule = True
                print("  zone %s: %s" % (zone, rule))
    if not any_rule:
        print("  none - Cloudflare is NOT protected; run 'cloudflare enable'")
    return 0


# --------------------------------------------------------------------------- #
# sub-command: create
# --------------------------------------------------------------------------- #


def cmd_create(runner, config, protect_cloudflare=True):
    require_root(runner)
    require_firewalld(runner)

    default_zone = get_default_zone(runner)
    existing_ipsets = get_ipsets(runner, permanent=True)
    existing_rules = list_rich_rules(runner, default_zone)
    existing_sources = set(list_sources(runner, FALLBACK_ZONE))
    ruled_ipsets = set(filter(None, (rule_ipset(r) for r in existing_rules)))

    created = 0
    ruled = 0
    for _url, name in sorted_lists(config):
        if name in existing_ipsets:
            runner.log("ipset already exists: " + name)
        else:
            options = ["--option=" + option for option in IPSET_OPTIONS]
            result = fw(
                runner,
                "--permanent",
                "--new-ipset=" + name,
                "--type=" + IPSET_TYPE,
                *options,
                description="Creating ipset " + name,
            )
            if not result.ok:
                continue
            created += 1

        port = PORT_MAP.get(name)
        if port:
            if name in ruled_ipsets:
                runner.log("rich rule already present for " + name)
                continue
            result = fw(
                runner,
                "--permanent",
                "--zone=" + default_zone,
                "--add-rich-rule=" + rich_rule(name, port),
                description="Blocking %s on port %s in zone %s"
                % (name, port, default_zone),
            )
        else:
            if "ipset:" + name in existing_sources:
                runner.log("already a source of zone %s: %s" % (FALLBACK_ZONE, name))
                continue
            result = fw(
                runner,
                "--permanent",
                "--zone=" + FALLBACK_ZONE,
                "--add-source=ipset:" + name,
                description="Adding %s to zone %s" % (name, FALLBACK_ZONE),
            )
        if result.ok:
            ruled += 1

    reload_firewalld(runner)
    print("created %d ipset(s), added %d firewall rule(s)" % (created, ruled))

    if protect_cloudflare:
        ensure_cloudflare_allowlist(runner)

    return 0


# --------------------------------------------------------------------------- #
# sub-command: flush
# --------------------------------------------------------------------------- #


def cmd_flush(runner, config):
    require_root(runner)

    ipset_bin = find_ipset_binary()
    if ipset_bin is None:
        die("ipset binary not found; install ipset or check your PATH")

    existing = get_ipsets(runner)
    flushed = 0
    for _url, name in sorted_lists(config):
        if name not in existing:
            runner.log("skipping unknown ipset: " + name)
            continue
        if runner.run(
            [ipset_bin, "flush", name], description="Flushing ipset " + name
        ).ok:
            flushed += 1

    print("flushed %d ipset(s)" % flushed)
    return 0


# --------------------------------------------------------------------------- #
# sub-command: populate
# --------------------------------------------------------------------------- #


def cmd_populate(runner, config):
    require_root(runner)
    require_firewalld(runner)

    for tool in ("curl", "sed"):
        if shutil.which(tool) is None:
            die("%s not found; it is required to download the blocklists" % tool)

    lists = sorted_lists(config)
    total = len(lists)
    populated = 0
    skipped = 0

    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdir = Path(tmpdirname)
        for index, (url, name) in enumerate(lists, start=1):
            tmpfile = tmpdir / name
            label = "[%d/%d] %s" % (index, total, name)

            # -f so an HTTP error page is never loaded into the ipset.
            download = runner.run(
                ["curl", "-sSfL", "--retry", "2", "-o", str(tmpfile), url],
                description="%s: downloading %s" % (label, url),
            )
            if not download.ok:
                runner.warn("skipping %s: download failed" % name)
                skipped += 1
                continue

            # ipsets here are IPv4 (family=inet); drop any IPv6 entries.
            runner.run(
                ["sed", "-i", "/:/d", str(tmpfile)],
                description="%s: removing IPv6 entries" % label,
            )

            if not runner.dry_run:
                if not tmpfile.is_file() or tmpfile.stat().st_size == 0:
                    runner.warn("skipping %s: downloaded list is empty" % name)
                    skipped += 1
                    continue

            result = fw(
                runner,
                "--ipset=" + name,
                "--add-entries-from-file=" + str(tmpfile),
                description="%s: loading entries" % label,
            )
            if result.ok:
                populated += 1
            else:
                skipped += 1

    print("populated %d ipset(s), skipped %d" % (populated, skipped))
    return 0


# --------------------------------------------------------------------------- #
# sub-commands: clean / revert
# --------------------------------------------------------------------------- #


def remove_firewall_rules(runner, targets):
    """Remove every rich rule and zone source that references targets."""
    removed = 0
    for zone in get_zones(runner):
        for rule in list_rich_rules(runner, zone):
            name = rule_ipset(rule)
            if name is None or name not in targets:
                continue
            result = fw(
                runner,
                "--permanent",
                "--zone=" + zone,
                "--remove-rich-rule=" + rule,
                description="Removing rich rule for %s from zone %s" % (name, zone),
            )
            if result.ok:
                removed += 1

        for source in list_sources(runner, zone):
            if not source.startswith("ipset:"):
                continue
            name = source[len("ipset:") :]
            if name not in targets:
                continue
            result = fw(
                runner,
                "--permanent",
                "--zone=" + zone,
                "--remove-source=" + source,
                description="Removing %s from zone %s" % (source, zone),
            )
            if result.ok:
                removed += 1
    return removed


def managed_ipsets(runner, config, only_config=False):
    """ipset names this tool is responsible for.

    Includes the configured names plus any ipset still in firewalld that uses
    one of the managed prefixes, so leftovers from an earlier blocklist.json
    are cleaned up too.
    """
    targets = set(config.values())
    if only_config:
        return targets
    known = get_ipsets(runner, permanent=True) | get_ipsets(runner)
    targets.update(name for name in known if name.startswith(MANAGED_PREFIXES))
    return targets


def confirm(prompt):
    try:
        answer = input(prompt + " [y/N] ")
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer.strip().lower() in ("y", "yes")


def cmd_clean(runner, config):
    require_root(runner)
    require_firewalld(runner)

    removed = remove_firewall_rules(runner, set(config.values()))
    reload_firewalld(runner)
    print("removed %d firewall rule(s); ipsets left in place" % removed)
    if removed:
        print("run 'revert' instead to also delete the ipsets")
    return 0


def cmd_revert(runner, config, only_config=False, assume_yes=False):
    """Undo every firewall change: drop the rules *and* delete the ipsets."""
    require_root(runner)
    require_firewalld(runner)

    targets = managed_ipsets(runner, config, only_config=only_config)
    if not targets:
        print("nothing to revert: no managed ipsets found")
        return 0

    permanent = get_ipsets(runner, permanent=True)
    to_delete = sorted(name for name in targets if name in permanent)
    orphans = sorted(targets - set(config.values()))

    print("About to revert the firewall changes for %d ipset(s):" % len(targets))
    print("  every rule and zone source referencing them will be removed")
    print("  %d ipset(s) will be deleted" % len(to_delete))
    if orphans:
        print(
            "  %d are not in the current config: %s"
            % (
                len(orphans),
                ", ".join(orphans[:8]) + (", ..." if len(orphans) > 8 else ""),
            )
        )

    if not assume_yes and not runner.dry_run:
        if not confirm("Continue?"):
            print("aborted")
            return 1

    removed = remove_firewall_rules(runner, targets)

    deleted = 0
    for name in to_delete:
        result = fw(
            runner,
            "--permanent",
            "--delete-ipset=" + name,
            description="Deleting ipset " + name,
        )
        if result.ok:
            deleted += 1

    reload_firewalld(runner)
    print("reverted: removed %d rule(s), deleted %d ipset(s)" % (removed, deleted))
    return 0


# --------------------------------------------------------------------------- #
# sub-command: show
# --------------------------------------------------------------------------- #


def cmd_show(runner, config, counts=True):
    require_firewalld(runner)

    default_zone = get_default_zone(runner)
    runtime = get_ipsets(runner)
    permanent = get_ipsets(runner, permanent=True)
    configured = sorted_lists(config)

    print("default zone: %s" % default_zone)
    print(
        "ipsets: %d runtime, %d permanent, %d configured"
        % (len(runtime), len(permanent), len(configured))
    )
    print()

    width = max([len(name) for _u, name in configured] + [5])
    print("%-*s  %-9s  %s" % (width, "IPSET", "STATE", "ENTRIES"))
    missing = 0
    for _url, name in configured:
        if name in runtime:
            state = "active"
        elif name in permanent:
            state = "reload"  # exists permanently but not loaded yet
        else:
            state = "missing"
            missing += 1
        if counts and name in runtime:
            entries = str(len(get_entries(runner, name)))
        else:
            entries = "-"
        print("%-*s  %-9s  %s" % (width, name, state, entries))

    cloudflare_protected = False
    for zone in sorted(set([default_zone, FALLBACK_ZONE])):
        rules = [r for r in list_rich_rules(runner, zone) if rule_ipset(r)]
        sources = [s for s in list_sources(runner, zone) if s.startswith("ipset:")]
        if any(rule_ipset(r) in CLOUDFLARE_IPSETS for r in rules):
            cloudflare_protected = True
        print()
        print(
            "zone %s: %d ipset rich rule(s), %d ipset source(s)"
            % (zone, len(rules), len(sources))
        )
        for rule in rules[:20]:
            print("  " + rule)
        if len(rules) > 20:
            print("  ... and %d more" % (len(rules) - 20))
        if sources:
            print(
                "  sources: "
                + " ".join(sources[:20])
                + (" ..." if len(sources) > 20 else "")
            )

    if missing:
        print()
        print("%d configured ipset(s) missing; run 'create'" % missing)
    if not counts:
        print()
        print("entry counts omitted (--no-counts)")

    print()
    print(
        "cloudflare allowlist: %s"
        % (
            "active (see 'cloudflare status' for details)"
            if cloudflare_protected
            else "NOT ENABLED - run './blocklist-firewalld.py cloudflare enable'"
        )
    )
    return 0


# --------------------------------------------------------------------------- #
# sub-command: generate
# --------------------------------------------------------------------------- #


def build_country_lists(countries, aggregated=True):
    base = "https://www.ipdeny.com/ipblocks/data/"
    if aggregated:
        base += "aggregated/"
        suffix = "-aggregated.zone"
    else:
        suffix = ".zone"
    return {"%s%s%s" % (base, code, suffix): "country-" + code for code in countries}


def cmd_generate(runner, mode, countries=None, output=CONFIG_NAME, aggregated=True):
    if mode == "blocklist-de":
        blocklist = dict(BLOCKLIST_DE)
    elif mode == "allow-us":
        blocklist = build_country_lists(
            [code for code in ALL_COUNTRIES if code != "us"], aggregated
        )
    elif mode == "block-threats":
        codes = list(COMMON_THREATS)
        blocklist = build_country_lists(codes, aggregated)
        print(
            "Blocking %d threat countries: %s"
            % (
                len(codes),
                ", ".join("%s (%s)" % (c, COMMON_THREATS[c]) for c in codes),
            ),
            file=sys.stderr,
        )
    elif mode == "block-specific":
        if not countries:
            die("--countries is required for block-specific mode")
        codes = [code.strip().lower() for code in countries.split(",") if code.strip()]
        if not codes:
            die("--countries did not contain any country codes")
        invalid = [code for code in codes if code not in ALL_COUNTRIES]
        if invalid:
            die("invalid country codes: " + ", ".join(invalid))
        blocklist = build_country_lists(codes, aggregated)
    else:  # pragma: no cover - argparse restricts the choices
        die("unknown mode: " + mode)

    if runner.dry_run:
        print("[dry-run] would write %d blocklist(s) to %s" % (len(blocklist), output))
        return 0

    try:
        with open(output, "w") as handle:
            json.dump(blocklist, handle, indent=4)
            handle.write("\n")
    except OSError as exc:
        die("could not write %s: %s" % (output, exc))

    print(
        "Generated %s with %d blocklist(s)" % (output, len(blocklist)), file=sys.stderr
    )
    return 0


# --------------------------------------------------------------------------- #
# sub-command: setup
# --------------------------------------------------------------------------- #


def cmd_setup(runner, config, protect_cloudflare=True):
    code = cmd_create(runner, config, protect_cloudflare=protect_cloudflare)
    if code:
        return code
    for step in (cmd_flush, cmd_populate):
        code = step(runner, config)
        if code:
            return code
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def translate_legacy_args(argv):
    """Map the pre-sub-command flags (--create, --populate, ...) onto commands."""
    translated = []
    for arg in argv:
        if arg in LEGACY_FLAGS:
            print(
                "note: %s is deprecated, use '%s' instead" % (arg, LEGACY_FLAGS[arg]),
                file=sys.stderr,
            )
            translated.append(LEGACY_FLAGS[arg])
        else:
            translated.append(arg)
    return translated


def common_parser(suppress):
    """Global options, shared by the main parser and every sub-parser.

    The sub-parser copies default to SUPPRESS so that a global given *before*
    the sub-command (``-v create``) is not clobbered by the sub-parser's own
    default, while still allowing it *after* it (``create -v``).
    """
    parser = argparse.ArgumentParser(add_help=False)
    extra = {"default": argparse.SUPPRESS} if suppress else {}
    parser.add_argument(
        "-c",
        "--config",
        metavar="PATH",
        help="path to blocklist.json (default: search "
        "$HOME, %s, script directory)" % ETC_CONFIG_DIR,
        **extra,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show every command as it runs",
        **extra,
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="show what would change without touching anything",
        **extra,
    )
    return parser


def build_parser():
    common = common_parser(suppress=True)

    parser = argparse.ArgumentParser(
        parents=[common_parser(suppress=False)],
        description="Load blocklists into firewalld using ipsets.",
        epilog="Run without a sub-command to perform the full setup "
        "(create + flush + populate).",
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    setup = subparsers.add_parser(
        "setup", parents=[common], help="create + flush + populate (default)"
    )
    create = subparsers.add_parser(
        "create", parents=[common], help="create ipsets and firewalld rules"
    )
    for sub in (setup, create):
        sub.add_argument(
            "--no-cloudflare-allowlist",
            dest="protect_cloudflare",
            action="store_false",
            default=True,
            help="do not add the Cloudflare allowlist (accept rules that keep "
            "Cloudflare's own IPs from ever being blocked by this tool)",
        )
    subparsers.add_parser(
        "populate", parents=[common], help="download blocklists and load the IPs"
    )
    subparsers.add_parser(
        "flush", parents=[common], help="empty the ipsets, keeping them in place"
    )
    subparsers.add_parser(
        "clean", parents=[common], help="remove the firewalld rules, keep the ipsets"
    )

    revert = subparsers.add_parser(
        "revert",
        parents=[common],
        help="undo all firewall changes: remove rules and delete ipsets",
    )
    revert.add_argument(
        "-y", "--yes", action="store_true", help="do not ask for confirmation"
    )
    revert.add_argument(
        "--only-config",
        action="store_true",
        help="only touch ipsets named in the config, ignoring "
        "leftovers from an earlier configuration",
    )

    show = subparsers.add_parser(
        "show", parents=[common], help="show the current ipsets and rules"
    )
    show.add_argument(
        "--no-counts",
        dest="counts",
        action="store_false",
        help="skip entry counts (much faster with many ipsets)",
    )

    generate = subparsers.add_parser(
        "generate",
        parents=[common],
        help="write a blocklist.json configuration",
    )
    generate.add_argument(
        "--mode",
        required=True,
        choices=["allow-us", "block-threats", "block-specific", "blocklist-de"],
        help="allow-us (block all except US), block-threats (common threat "
        "countries), block-specific (custom list), blocklist-de "
        "(original config)",
    )
    generate.add_argument(
        "--countries",
        help="comma separated country codes for " "block-specific mode (e.g. cn,ru,ir)",
    )
    generate.add_argument(
        "--output", default=CONFIG_NAME, help="output file (default: %s)" % CONFIG_NAME
    )
    generate.add_argument(
        "--no-aggregated",
        action="store_true",
        help="use non-aggregated zone files " "(more IP blocks, slower)",
    )

    cloudflare = subparsers.add_parser(
        "cloudflare",
        parents=[common],
        help="manage the Cloudflare allowlist (never block Cloudflare's own IPs)",
    )
    cloudflare.add_argument(
        "action",
        nargs="?",
        default="status",
        choices=["enable", "refresh", "disable", "status"],
        help="enable/refresh: create (if needed) and (re)populate the allowlist "
        "ipsets and accept rules. disable: remove them. status (default): "
        "show the current state.",
    )
    cloudflare.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="do not ask for confirmation (disable only)",
    )
    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(translate_legacy_args(argv))

    runner = Runner(verbose=args.verbose, dry_run=args.dry_run)
    command = args.command or "setup"

    # generate and cloudflare are independent of blocklist.json
    if command == "generate":
        return cmd_generate(
            runner,
            args.mode,
            countries=args.countries,
            output=args.output,
            aggregated=not args.no_aggregated,
        )

    if command == "cloudflare":
        if args.action in ("enable", "refresh"):
            return ensure_cloudflare_allowlist(runner)
        if args.action == "disable":
            return cmd_cloudflare_disable(runner, assume_yes=args.yes)
        return cmd_cloudflare_status(runner)

    path, config = load_config(args.config)
    runner.log("using config %s (%d blocklist(s))" % (path, len(config)))

    if command == "create":
        code = cmd_create(runner, config, protect_cloudflare=args.protect_cloudflare)
    elif command == "populate":
        code = cmd_populate(runner, config)
    elif command == "flush":
        code = cmd_flush(runner, config)
    elif command == "clean":
        code = cmd_clean(runner, config)
    elif command == "revert":
        code = cmd_revert(
            runner, config, only_config=args.only_config, assume_yes=args.yes
        )
    elif command == "show":
        code = cmd_show(runner, config, counts=args.counts)
    else:
        code = cmd_setup(
            runner, config, protect_cloudflare=getattr(args, "protect_cloudflare", True)
        )

    if code == 0 and runner.failures:
        print(
            "completed with %d failed command(s); re-run with --verbose "
            "for details" % runner.failures,
            file=sys.stderr,
        )
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        sys.exit(130)
