import requests
import subprocess
import os
import json
import sys
import time
import argparse
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

# --- تنظیمات سیستم شما ---
API_URL = "http://localhost:3131/api/http" 
API_TOKEN = os.getenv("WATCHTOWER_API_TOKEN")
OLD_TARGETS_FILE = "all_scanned_targets.txt"    
OUTPUT_DIR = "./watchtower_scans"               
XSSNIPER_CMD = "go run xssniper.go"        

def log(msg, color="\033[36m"):
    ts = time.strftime("%H:%M:%S")
    print(f"\033[90m[{ts}]\033[0m {color}[BRIDGE] {msg}\033[0m")

def get_hostname(url):
    return urlparse(url).netloc if url.startswith('http') else url

def get_data_from_api(mode="normal"):
    log(f"Connecting to API in {mode.upper()} mode...")
    headers = {"X-API-Token": API_TOKEN, "Accept": "application/json"}
    all_urls, current_page, per_page = [], 1, 500
    api_params = {'only_changed': 'true'} if mode == "fresh" else {}

    try:
        while True:
            params = {**api_params, 'page': current_page, 'per_page': per_page}
            log(f"Fetching page {current_page}...")
            response = requests.get(API_URL, headers=headers, params=params, timeout=60)
            response.raise_for_status()
            res_json = response.json()
            page_data = res_json.get('data', [])
            for item in page_data:
                url = item.get('final_url') or item.get('url')
                if url: all_urls.append(url)
            total_pages = res_json.get('pages', 1)
            if current_page >= total_pages: break
            current_page += 1
        log(f"Total unique URLs retrieved from API: {len(all_urls)}")
        return all_urls
    except Exception as e:
        log(f"API Error: {e}", "\033[31m"); return []

def get_new_targets_only(targets):
    """پیدا کردن تارگت‌های جدید بدون اضافه کردن آن‌ها به فایل تاریخچه"""
    log("Checking for new targets (Diffing)...")
    if not os.path.exists(OLD_TARGETS_FILE):
        return targets
    
    with open(OLD_TARGETS_FILE, "r") as f:
        scanned = set(line.strip() for line in f if line.strip())
    
    new_targets = [t for t in targets if t not in scanned]
    return new_targets

def mark_as_scanned(url):
    """ثبت URL در فایل تاریخچه پس از اتمام موفقیت‌آمیز اسکن"""
    with open(OLD_TARGETS_FILE, "a") as f:
        f.write(url + "\n")
    log(f"Target marked as scanned: {url}", "\033[32m")

def run_nice_passive(target_url):
    domain = get_hostname(target_url)
    log(f"Running nice_passive.py for {domain}...")
    try:
        script_path = os.path.join(os.getcwd(), "nice_passive.py")
        subprocess.run(f"python3 {script_path} {domain}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        passive_file = f"{domain}.passive"
        if os.path.exists(passive_file):
            with open(passive_file, "r") as f: return f.read().splitlines()
    except: pass
    return []

def run_nice_params(target_url):
    host = get_hostname(target_url)
    log(f"Running nice_params for {target_url}...")
    try:
        subprocess.run(f"./nice_params -u {target_url} -d .", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        output_file = f"{host}-param.txt"
        if os.path.exists(output_file):
            with open(output_file, "r") as f: params = f.read().splitlines()
            os.remove(output_file)
            return params
    except: pass
    return []

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["normal", "fresh"], default="normal")
    args = parser.parse_args()
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)

    raw_targets = get_data_from_api(mode=args.mode)
    if not raw_targets: return

    # در مود Fresh همه را اسکن می‌کنیم، در مود Normal فقط جدیدها
    if args.mode == "fresh":
        new_targets = raw_targets
    else:
        new_targets = get_new_targets_only(raw_targets)

    if not new_targets:
        log("No targets to process.", "\033[32m")
        return

    log(f"Ready to process {len(new_targets)} targets in {args.mode.upper()} mode.")
    for target in new_targets:
        try:
            log(f"--- Starting: {target} ---", "\033[1m\033[35m")
            passive_urls = run_nice_passive(target)
            hidden_params = run_nice_params(target)
            
            job_file = os.path.join(OUTPUT_DIR, f"job_{int(time.time())}.txt")
            with open(job_file, "w") as f:
                f.write(target + "\n")
                for u in passive_urls: f.write(u + "\n")
                for p in hidden_params: f.write(p + "\n")
                
            log(f"Launching XSSniper for {target}...")
            # اجرای اسکنر
            subprocess.run(f"{XSSNIPER_CMD} -l {job_file} -w 3", shell=True, check=True)
            
            # فقط در صورت اتمام موفقیت‌آمیز، در تاریخچه ثبت می‌شود
            if args.mode == "normal":
                mark_as_scanned(target)
                
        except KeyboardInterrupt:
            log("Scan interrupted by user. Progress saved.", "\033[31m")
            sys.exit(0)
        except Exception as e:
            log(f"Error scanning {target}: {e}", "\033[31m")

if __name__ == "__main__":
    main()
