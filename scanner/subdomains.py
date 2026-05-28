import subprocess

def enumerate_subdomains(domain: str) -> list[str]:
    """ Enumerate subdomains using subfinder. """
    try:
        result = subprocess.run(["subfinder", "-silent", "-d", domain], capture_output=True, text=True, check=True)
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]
    
    except subprocess.CalledProcessError as e:
        print(f"[!] Subfinder failed: {e.stderr}")
        return []
    except FileNotFoundError:
        print("[!] Subfinder is not installed or not in PATH.")
        return []

    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return []