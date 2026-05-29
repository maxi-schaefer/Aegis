import sys
import json
import argparse
from colorama import Fore

from scanner.core import run_recon
from scanner.ui import print_banner, print_summary_table, GOOD, WARN


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="High-Performance Recon Pipeline")
    parser.add_argument("domain", help="Target domain to scan (e.g., example.com)")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Number of concurrent workers (default: 20)")
    parser.add_argument("-o", "--output", type=str, help="Custom output JSON file location path")
    parser.add_argument("-bw", "--brute-wordlist", type=str, help="Path to a custom wordlist file on disk for directory brute-forcing")
    parser.add_argument("-sc", "--codes", type=str, default="200,301,302,403", 
                        help="Comma-separated status codes to match (default: 200,301,302,403)")
    args = parser.parse_args()

    domain = args.domain
    filename = args.output if args.output else f"{domain.replace('.', '_')}_results.json"
    status_codes = [int(status.strip()) for status in args.codes.split(",") if status.strip().isdigit()]

    try:
        results = run_recon(domain, threads=args.threads, wordlist=args.brute_wordlist, status_codes=status_codes)
    except KeyboardInterrupt:
        print(f"\n{WARN} System execution terminated cleanly.")
        sys.exit(1)

    # Render metrics dashboard block
    print_summary_table(results)
    
    # Handle storage serialization steps
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        print(f"{GOOD} Detailed asset report safely dumped to: {Fore.LIGHTGREEN_EX}{filename}{Fore.RESET}\n")
    except Exception as e:
        print(f"{WARN} Failed to write configuration output metrics file down to disk: {e}")


if __name__ == "__main__":
    main()