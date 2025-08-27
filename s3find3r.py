import re
import requests
from urllib.parse import urlparse
import sys
import random

# Regex patterns to match potential S3 bucket names
s3_patterns = [
    r'https?://([a-zA-Z0-9._-]+)\.s3\.amazonaws\.com',
    r'https?://s3\.amazonaws\.com/([a-zA-Z0-9._-]+)',
    r'https?://s3-[a-z0-9-]+\.amazonaws\.com/([a-zA-Z0-9._-]+)',
    r'([a-zA-Z0-9._-]+)\.s3-[a-z0-9-]+\.amazonaws\.com',
]

def extract_s3_buckets_from_url(url):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (S3ReconTool)"
        }
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            print(f"[!] Failed to fetch {url} (Status: {resp.status_code})")
            return []

        buckets = set()
        for pattern in s3_patterns:
            matches = re.findall(pattern, resp.text)
            for match in matches:
                buckets.add(match.strip())

        return list(buckets)

    except Exception as e:
        print(f"[!] Error fetching {url}: {str(e)}")
        return []

def print_banner():
    banners = [
        r"""
   _______       ___      .______     ______   .______       _______ 
  /  _____|     /   \     |   _  \   /  __  \  |   _  \     |   ____|
 |  |  __      /  ^  \    |  |_)  | |  |  |  | |  |_)  |    |  |__   
 |  | |_ |    /  /_\  \   |   ___/  |  |  |  | |      /     |   __|  
 |  |__| |   /  _____  \  |  |      |  `--'  | |  |\  \----.|  |____ 
  \______|  /__/     \__\ | _|       \______/  | _| `._____||_______|
                      [ S3 Bucket Finder by CYBER RAGE ]
        """,
        r"""
   _____.___.              .__               __________                             
 __| _/\__| ____   ____   |  |   ____      \______   \__ __  ____ _____ ___  ___  
/ __ | |  |/ __ \ /    \  |  | _/ __ \      |       _/  |  \/    \\__  \\  \/  /  
/ /_/ | |  \  ___/|   |  \ |  |_\  ___/      |    |   \  |  /   |  \/ __ \\>    <   
\____ | |__|\___  >___|  / |____/\___  >     |____|_  /____/|___|  (____  /__/\_ \  
     \/         \/     \/            \/             \/           \/     \/      \/  
               [ {CYBER RAGE} — S3 Recon Engine ]
        """,
        r"""
   _____      _               _____                      _           
  / ____|    | |             |  __ \                    (_)          
 | |     __ _| |__  ___ _ __ | |__) |___  __ _ _ __ ___  _ _ __  ___ 
 | |    / _` | '_ \/ __| '_ \|  _  // _ \/ _` | '_ ` _ \| | '_ \/ __|
 | |___| (_| | |_) \__ \ | | | | \ \  __/ (_| | | | | | | | | | \__ \
  \_____\__,_|_.__/|___/_| |_|_|  \_\___|\__,_|_| |_| |_|_|_| |_|___/
               [ Auto S3 Hunter by CYBER RAGE ]
        """,
        r"""
   ____      _     _      ____                       _      
  / ___|___ | |__ (_) ___|  _ \ ___ _ __   ___  _ __| |_    
 | |   / _ \| '_ \| |/ __| |_) / _ \ '_ \ / _ \| '__| __|   
 | |__| (_) | |_) | | (__|  _ <  __/ |_) | (_) | |  | |_    
  \____\___/|_.__/|_|\___|_| \_\___| .__/ \___/|_|   \__|   
                                   |_|                      
                [ Recon Script by CYBER RAGE ]
        """,
        r"""
 ██████╗██╗   ██╗ ██████╗ ██████╗ ███████╗██████╗  █████╗  ██████╗ ███████╗
██╔════╝██║   ██║██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝ ██╔════╝
██║     ██║   ██║██║   ██║██████╔╝█████╗  ██████╔╝███████║██║  ███╗█████╗  
██║     ██║   ██║██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║██║   ██║██╔══╝  
╚██████╗╚██████╔╝╚██████╔╝██║     ███████╗██║  ██║██║  ██║╚██████╔╝███████╗
 ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
               [ S3 Bucket Extractor - CYBER RAGE ]
        """
    ]
    print(random.choice(banners))

def print_help():
    help_text = """
Usage: python s3find3r.py [options]

Options:
  -f <file>        Scan URLs listed in a text file
  -u <url>         Scan a single URL
  -o <file>        Save output to a file
  -b               Show a random banner
  --help           Show this help message
"""
    print(help_text)

if __name__ == "__main__":
    args = sys.argv[1:]
    urls = []
    output_file = None

    if not args or "--help" in args:
        print_help()
        sys.exit(0)

    if "-b" in args:
        print_banner()
        sys.exit(0)

    if "-u" in args:
        try:
            url_index = args.index("-u") + 1
            urls.append(args[url_index])
        except IndexError:
            print("[!] Missing URL after -u")
            sys.exit(1)

    if "-f" in args:
        try:
            file_index = args.index("-f") + 1
            with open(args[file_index], 'r') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except (IndexError, FileNotFoundError):
            print("[!] File not found or not specified after -f")
            sys.exit(1)

    if "-o" in args:
        try:
            output_index = args.index("-o") + 1
            output_file = args[output_index]
        except IndexError:
            print("[!] Missing file name after -o")
            sys.exit(1)

    if not urls:
        print("[!] No URL or file provided. Use -u or -f.")
        sys.exit(1)

    print_banner()

    found_buckets = set()

    for url in urls:
        print(f"[+] Scanning {url}")
        buckets = extract_s3_buckets_from_url(url)
        for b in buckets:
            print(f"  -> Found bucket: {b}")
            found_buckets.add(b)

    print("\n[✓] Total Unique Buckets Found:", len(found_buckets))
    for b in found_buckets:
        print(f"- {b}")

    if output_file:
        with open(output_file, "w") as out:
            for b in found_buckets:
                out.write(f"{b}\n")
        print(f"\n[💾] Results saved to: {output_file}")

    print("\n[👑] This tool was made by CYBER RAGE")
