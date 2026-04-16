import requests
import subprocess
import os
import uuid
import sys
from concurrent.futures import ThreadPoolExecutor

def detect_wildcard_status(domain):
    """Silently detects the status code returned by a non-existent subdomain."""
    random_string = str(uuid.uuid4())[:8]
    url = f"http://{random_string}.{domain}"
    try:
        # Fast timeout to avoid delaying the start of the main tools
        response = requests.get(url, timeout=5, allow_redirects=False)
        return response.status_code
    except Exception:
        return None

def get_crt_subdomains(domain):
    """Passive discovery via crt.sh API."""
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs = set()
    try:
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                names = entry['name_value'].split('\n')
                for name in names:
                    clean_name = name.replace('*.', '').lower().strip()
                    if (clean_name.endswith("." + domain) or clean_name == domain) and clean_name not in subs:
                        print(clean_name)
                        subs.add(clean_name)
    except Exception:
        pass

def run_subfinder(domain):
    """Passive discovery via Subfinder binary."""
    # -silent ensures only found subdomains are printed
    cmd = ["subfinder", "-d", domain, "-silent"]
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in process.stdout:
            sub = line.strip()
            if sub:
                print(sub)
        process.wait()
    except Exception:
        pass

def run_ffuf(domain, wordlist, wildcard_code):
    """Active discovery via ffuf brute-force."""
    match_codes = ["200", "301", "302", "403"]
    if wildcard_code and str(wildcard_code) in match_codes:
        match_codes.remove(str(wildcard_code))

    cmd = [
        "ffuf",
        "-w", wordlist,
        "-u", f"http://FUZZ.{domain}",
        "-mc", ",".join(match_codes),
        "-s",  # Silent mode
        "-t", "100" 
    ]
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in process.stdout:
            word = line.strip()
            if word:
                print(f"{word}.{domain}")
        process.wait()
    except Exception:
        pass

def main():
    target = input("Enter domain: ").strip()
    if not target:
        return

    # Normalization: remove protocol and paths
    target = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    wordlist = "subdomains.txt"
    if not os.path.exists(wordlist):
        print(f"Error: {wordlist} not found.")
        return

    # Check for wildcard once before starting parallel tasks
    wildcard_code = detect_wildcard_status(target)

    print(f"--- Enumerating {target} (CRT + Subfinder + FFUF) ---")

    # Use 3 workers to run all three discovery paths simultaneously
    with ThreadPoolExecutor(max_workers=3) as executor:
        executor.submit(get_crt_subdomains, target)
        executor.submit(run_subfinder, target)
        executor.submit(run_ffuf, target, wordlist, wildcard_code)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # os._exit(0) kills all threads immediately and silently
        os._exit(0)