import requests
import subprocess
import os
import uuid
import sys
import hashlib
from concurrent.futures import ThreadPoolExecutor


requests.packages.urllib3.disable_warnings()

def get_fingerprint(url):
    """Captures status, length, and a hash of the response body."""
    try:
        # verify=False handles self-signed or mismatched certs on random subdomains
        res = requests.get(url, timeout=5, allow_redirects=True, verify=False)
        body_hash = hashlib.md5(res.text[:100].encode()).hexdigest()
        return {
            "status": str(res.status_code),
            "size": str(len(res.content)),
            "hash": body_hash
        }
    except Exception:
        return None

def detect_wildcard_logic(domain):
    """random subdomains over HTTP/HTTPS to find wildcard fingerprints."""
    fps = []
    protocols = ["http", "https"]
    
    print(f"[*] Analyzing wildcard behavior for {domain}...")
    
    for _ in range(3):
        random_sub = f"{uuid.uuid4().hex[:8]}"
        for proto in protocols:
            url = f"{proto}://{random_sub}.{domain}"
            fp = get_fingerprint(url)
            if fp:
                fps.append(fp)
    
  
    unique_sizes = list(set(f["size"] for f in fps))
    unique_codes = list(set(f["status"] for f in fps))
    
    return unique_sizes, unique_codes

def get_vt_subdomains(domain):
   
    api_key = "virustotal api key here"
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    
    subs = set()
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for entry in data.get('data', []):
                sub = entry.get('id', '').lower().strip()
                if sub and sub not in subs:
                    print(f"{sub}")
                    subs.add(sub)
        elif response.status_code == 429:
            print("[!] VT Error: Rate limit (4 reqs/min) reached.")
    except Exception:
        pass

def run_subfinder(domain):
    cmd = ["subfinder", "-d", domain, "-silent"]
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in process.stdout:
            sub = line.strip()
            if sub:
                print(f"{sub}")
        process.wait()
    except Exception:
        pass

def run_ffuf(domain, wordlist, sizes, codes):
    """Runs ffuf and filters out the detected wildcard fingerprints."""
    match_codes = ["200", "204", "301", "302", "307", "403", "405"]
    for c in codes:
        if c in match_codes:
            match_codes.remove(c)

    cmd = [
        "ffuf",
        "-w", wordlist,
        "-u", f"http://FUZZ.{domain}",
        "-mc", ",".join(match_codes),
        "-s", 
        "-t", "50"
    ]

    
    if sizes:
        cmd.extend(["-fs", ",".join(sizes)])

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        for line in process.stdout:
            print(f"{line.strip()}.{domain}")
        process.wait()
    except Exception:
        pass
def run_crt(domain):
    cmd=f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' | jq -r '.[].name_value'"
    os.system(f"{cmd} 2>/dev/null")#error handilinf 2>/dev/null

def main():
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("Enter domain: ").strip()
    
    if not target: return
    target = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    wordlist = "subdomains.txt"
    if not os.path.exists(wordlist):
        print(f"Error: {wordlist} not found.")
        return

    
    wildcard_sizes, wildcard_codes = detect_wildcard_logic(target)
    
    if wildcard_sizes:
        print(f"[*] Wildcard detected. Filtering sizes: {', '.join(wildcard_sizes)}")

    print(f"--- Starting Enumeration on {target} ---")

    
    with ThreadPoolExecutor(max_workers=3) as executor:
        executor.submit(get_vt_subdomains, target)
        executor.submit(run_subfinder, target)
        executor.submit(run_ffuf, target, wordlist, wildcard_sizes, wildcard_codes)
        executor.submit(run_crt,domain)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        os._exit(0)
