import threading
from colorama import Fore, Style, init

init(autoreset=True)

CONSOLE_LOCK = threading.Lock()

INFO = f"{Fore.LIGHTBLACK_EX}[{Fore.LIGHTRED_EX}*{Fore.LIGHTBLACK_EX}]{Fore.RESET}"
STEP = f"{Fore.LIGHTBLACK_EX}├──{Fore.RESET}"
LAST = f"{Fore.LIGHTBLACK_EX}└──{Fore.RESET}"
GOOD = f"{Fore.LIGHTBLACK_EX}[{Fore.LIGHTGREEN_EX}✓{Fore.LIGHTBLACK_EX}]{Fore.RESET}"
WARN = f"{Fore.LIGHTBLACK_EX}[{Fore.LIGHTYELLOW_EX}!{Fore.LIGHTBLACK_EX}]{Fore.RESET}"
ALERT = f"{Fore.RED}[🔥]{Fore.RESET}"


def safe_print(message: str):
    """Thread-safe print helper to keep terminal layout intact."""
    with CONSOLE_LOCK:
        print(message)


def print_banner():
    """Prints tool stylized ascii signature branding."""
    banner = rf"""
        {Fore.LIGHTRED_EX}
         ______     ______     ______     __     ______    
        /\  __ \   /\  ___\   /\  ___\   /\ \   /\  ___\   
        \ \  __ \  \ \  __\   \ \ \__ \  \ \ \  \ \___  \  
         \ \_\ \_\  \ \_____\  \ \_____\  \ \_\  \/\_____\ 
          \/_/\/_/   \/_____/   \/_____/   \/_/   \/_____/ 
        {Fore.RESET}
    """
    print(banner)


def print_summary_table(results: list):
    """Generates a structured post-scan analytics dashboard output window."""
    total_hosts = len(results)
    total_ports = 0
    total_endpoints = 0
    total_vulns = 0

    for r in results:
        total_ports += len(r.get("ports", [])) if isinstance(r.get("ports"), list) else 0
        total_vulns += len(r.get("vulnerabilities", []))
        for scheme, endpoints in r.get("exposed_endpoints", {}).items():
            total_endpoints += len(endpoints)

    print(f"\n{Fore.LIGHTBLACK_EX}┌──────────────────────────────────────────────────────────────┐")
    print(f"{Fore.LIGHTBLACK_EX}│                  {Style.BRIGHT}{Fore.WHITE}AEGIS PIPELINE RUN METRICS{Style.RESET_ALL}{Fore.LIGHTBLACK_EX}                  │")
    print(f"{Fore.LIGHTBLACK_EX}├──────────────────────────────────────────────────────────────┤")
    print(f"{Fore.LIGHTBLACK_EX}│  {Fore.WHITE}Analyzed Targets   :{Fore.RESET} {Fore.LIGHTBLUE_EX}{total_hosts:<41}{Fore.LIGHTBLACK_EX}│")
    print(f"{Fore.LIGHTBLACK_EX}│  {Fore.WHITE}Discovered Ports   :{Fore.RESET} {Fore.LIGHTGREEN_EX}{total_ports:<41}{Fore.LIGHTBLACK_EX}│")
    print(f"{Fore.LIGHTBLACK_EX}│  {Fore.WHITE}Exposed Endpoints  :{Fore.RESET} {Fore.LIGHTYELLOW_EX}{total_endpoints:<41}{Fore.LIGHTBLACK_EX}│")
    print(f"{Fore.LIGHTBLACK_EX}│  {Fore.WHITE}Identified CVEs    :{Fore.RESET} {Fore.LIGHTRED_EX}{total_vulns:<41}{Fore.LIGHTBLACK_EX}│")
    print(f"{Fore.LIGHTBLACK_EX}└──────────────────────────────────────────────────────────────┘\n")