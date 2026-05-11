#!/usr/bin/env python3
"""
Helper script to generate different blocklist.json configurations
"""

import argparse
import json
import sys

# All country codes from ipdeny.com
ALL_COUNTRIES = [
    "af",
    "ax",
    "al",
    "dz",
    "as",
    "ad",
    "ao",
    "ai",
    "aq",
    "ag",
    "ar",
    "am",
    "aw",
    "au",
    "at",
    "az",
    "bs",
    "bh",
    "bd",
    "bb",
    "by",
    "be",
    "bz",
    "bj",
    "bm",
    "bt",
    "bo",
    "ba",
    "bw",
    "br",
    "io",
    "bn",
    "bg",
    "bf",
    "bi",
    "kh",
    "cm",
    "ca",
    "cv",
    "ky",
    "cf",
    "td",
    "cl",
    "cn",
    "cc",
    "co",
    "km",
    "cg",
    "cd",
    "ck",
    "cr",
    "ci",
    "hr",
    "cu",
    "cy",
    "cz",
    "dk",
    "dj",
    "dm",
    "do",
    "ec",
    "eg",
    "sv",
    "gq",
    "er",
    "ee",
    "et",
    "fk",
    "fo",
    "fj",
    "fi",
    "fr",
    "gf",
    "pf",
    "ga",
    "gm",
    "ge",
    "de",
    "gh",
    "gi",
    "gr",
    "gl",
    "gd",
    "gp",
    "gu",
    "gt",
    "gn",
    "gw",
    "gy",
    "ht",
    "va",
    "hn",
    "hk",
    "hu",
    "is",
    "in",
    "id",
    "ir",
    "iq",
    "ie",
    "im",
    "il",
    "it",
    "jm",
    "jp",
    "je",
    "jo",
    "kz",
    "ke",
    "ki",
    "kp",
    "kr",
    "kw",
    "kg",
    "la",
    "lv",
    "lb",
    "ls",
    "lr",
    "ly",
    "li",
    "lt",
    "lu",
    "mo",
    "mk",
    "mg",
    "mw",
    "my",
    "mv",
    "ml",
    "mt",
    "mh",
    "mq",
    "mr",
    "mu",
    "yt",
    "mx",
    "fm",
    "md",
    "mc",
    "mn",
    "me",
    "ms",
    "ma",
    "mz",
    "mm",
    "na",
    "nr",
    "np",
    "nl",
    "nc",
    "nz",
    "ni",
    "ne",
    "ng",
    "nu",
    "nf",
    "mp",
    "no",
    "om",
    "pk",
    "pw",
    "ps",
    "pa",
    "pg",
    "py",
    "pe",
    "ph",
    "pl",
    "pt",
    "pr",
    "qa",
    "re",
    "ro",
    "ru",
    "rw",
    "kn",
    "lc",
    "pm",
    "vc",
    "ws",
    "sm",
    "st",
    "sa",
    "sn",
    "rs",
    "sc",
    "sl",
    "sg",
    "sk",
    "si",
    "sb",
    "so",
    "za",
    "es",
    "lk",
    "sd",
    "sr",
    "sz",
    "se",
    "ch",
    "sy",
    "tw",
    "tj",
    "tz",
    "th",
    "tl",
    "tg",
    "tk",
    "to",
    "tt",
    "tn",
    "tr",
    "tm",
    "tc",
    "tv",
    "ug",
    "ua",
    "ae",
    "gb",
    "um",
    "us",
    "uy",
    "uz",
    "vu",
    "ve",
    "vn",
    "vg",
    "vi",
    "wf",
    "ye",
    "zm",
    "zw",
]

COMMON_THREATS = {
    "cn": "China",
    "ru": "Russia",
    "kp": "North Korea",
    "ir": "Iran",
    "sy": "Syria",
    "by": "Belarus",
}


def generate_blocklist(countries, use_aggregated=True):
    """Generate blocklist dictionary from country codes"""
    blocklist = {}
    base_url = "https://www.ipdeny.com/ipblocks/data/"

    if use_aggregated:
        base_url += "aggregated/"
        suffix = "-aggregated.zone"
    else:
        suffix = ".zone"

    for country_code in countries:
        url = f"{base_url}{country_code}{suffix}"
        blocklist[url] = f"country-{country_code}"

    return blocklist


def main():
    parser = argparse.ArgumentParser(
        description="Generate blocklist.json configurations for country-based IP blocking"
    )

    parser.add_argument(
        "--mode",
        choices=["allow-us", "block-threats", "block-specific", "blocklist-de"],
        required=True,
        help="Blocklist mode: allow-us (block all except US), block-threats (common threat countries), block-specific (custom list), blocklist-de (original config)",
    )

    parser.add_argument(
        "--countries",
        help="Comma-separated country codes for block-specific mode (e.g., cn,ru,ir)",
    )

    parser.add_argument(
        "--output",
        default="blocklist.json",
        help="Output file path (default: blocklist.json)",
    )

    parser.add_argument(
        "--no-aggregated",
        action="store_true",
        help="Use non-aggregated zone files (more IP blocks, slower)",
    )

    args = parser.parse_args()

    if args.mode == "blocklist-de":
        # Original blocklist.de configuration
        blocklist = {
            "https://lists.blocklist.de/lists/ssh.txt": "blocklist-ssh",
            "https://lists.blocklist.de/lists/80.txt": "blocklist-80",
            "https://lists.blocklist.de/lists/443.txt": "blocklist-443",
        }
    elif args.mode == "allow-us":
        # Block all countries except US
        countries = [c for c in ALL_COUNTRIES if c != "us"]
        blocklist = generate_blocklist(countries, not args.no_aggregated)
    elif args.mode == "block-threats":
        # Block common threat countries
        countries = list(COMMON_THREATS.keys())
        blocklist = generate_blocklist(countries, not args.no_aggregated)
        print(
            f"Blocking {len(countries)} threat countries: {', '.join([f'{c} ({COMMON_THREATS[c]})' for c in countries])}",
            file=sys.stderr,
        )
    elif args.mode == "block-specific":
        if not args.countries:
            print(
                "Error: --countries required for block-specific mode", file=sys.stderr
            )
            sys.exit(1)
        countries = [c.strip().lower() for c in args.countries.split(",")]
        # Validate country codes
        invalid = [c for c in countries if c not in ALL_COUNTRIES]
        if invalid:
            print(
                f"Error: Invalid country codes: {', '.join(invalid)}", file=sys.stderr
            )
            sys.exit(1)
        blocklist = generate_blocklist(countries, not args.no_aggregated)

    # Write output
    with open(args.output, "w") as f:
        json.dump(blocklist, f, indent=4)

    print(
        f"✓ Generated {args.output} with {len(blocklist)} blocklists", file=sys.stderr
    )


if __name__ == "__main__":
    main()
