from pywidevine.cdm import Cdm
from pywidevine.device import Device
from pywidevine.pssh import PSSH
import argparse
import requests
import sys
import time
import hashlib
import hmac
import math
from http.cookiejar import MozillaCookieJar
from pathlib import Path

class TOTP:
    def __init__(self):
        self.secret = b"376136387538459893883312310911992847112448894410210511297108"
        self.version = 12
        self.period = 30
        self.digits = 6

    def generate(self, timestamp: int) -> str:
        counter = math.floor(timestamp / 1000 / self.period)
        counter_bytes = counter.to_bytes(8, byteorder="big")
        
        h = hmac.new(self.secret, counter_bytes, hashlib.sha1)
        hmac_result = h.digest()
        
        offset = hmac_result[-1] & 0x0F
        binary = (
            (hmac_result[offset] & 0x7F) << 24
            | (hmac_result[offset + 1] & 0xFF) << 16
            | (hmac_result[offset + 2] & 0xFF) << 8
            | (hmac_result[offset + 3] & 0xFF)
        )
        
        return str(binary % (10**self.digits)).zfill(self.digits)

class SpotifyAuth:
    SPOTIFY_HOME_PAGE_URL = "https://open.spotify.com/"
    CLIENT_VERSION = "1.2.61.294.g43083ca4"
    
    def __init__(self, cookies_path: str):
        self.totp = TOTP()
        self.session = requests.Session()
        
        # Load cookies
        cookies = MozillaCookieJar(cookies_path)
        cookies.load(ignore_discard=True, ignore_expires=True)
        self.session.cookies.update(cookies)
        
        # Set headers
        self.session.headers.update({
            "accept": "application/json",
            "accept-language": "en-US",
            "content-type": "application/json",
            "origin": self.SPOTIFY_HOME_PAGE_URL,
            "priority": "u=1, i",
            "referer": self.SPOTIFY_HOME_PAGE_URL,
            "sec-ch-ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-site",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
            "spotify-app-version": self.CLIENT_VERSION,
            "app-platform": "WebPlayer",
        })
        
        self._get_access_token()
    
    def _get_access_token(self):
        max_retries = 3
        retry_delay = 60
        
        for attempt in range(max_retries):
            try:
                # Get server time
                server_time_response = self.session.get("https://open.spotify.com/api/server-time", timeout=10)
                server_time_response.raise_for_status()
                server_time = 1e3 * server_time_response.json()["serverTime"]
                
                # Generate TOTP
                totp = self.totp.generate(timestamp=server_time)
                
                # Get access token
                token_response = self.session.get(
                    "https://open.spotify.com/api/token",
                    params={
                        "reason": "init",
                        "productType": "web-player",
                        "totp": totp,
                        "totpVer": str(self.totp.version),
                        "ts": str(server_time),
                    },
                    timeout=10
                )
                token_response.raise_for_status()
                session_info = token_response.json()
                
                self.access_token = session_info['accessToken']
                self.token_expiry = int(session_info['accessTokenExpirationTimestampMs'])
                
                print(f"✓ Successfully generated auth token")
                return
                
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"  ⚠ Token refresh failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                    print(f"  ⏳ Waiting {retry_delay} seconds before retry...")
                    time.sleep(retry_delay)
                else:
                    print(f"  ✗ Failed to refresh token after {max_retries} attempts")
                    raise
    
    def get_token(self):
        # Refresh token if expired
        timestamp_now = time.time() * 1000
        if timestamp_now >= self.token_expiry:
            print("Token expired, refreshing...")
            self._get_access_token()
        
        return self.access_token

def extract_key_from_pssh(pssh_value, license_url, auth_token, cdm, widevine_file_path):
    """Attempt to extract key from a PSSH value"""
    session_id = None
    try:
        session_id = cdm.open()
        
        pssh = PSSH(pssh_value)
        challenge = cdm.get_license_challenge(session_id, pssh)
        
        license_headers = {
            'Authorization': f'Bearer {auth_token}'
        }
        
        license = requests.post(
            license_url,
            headers=license_headers,
            data=challenge,
            timeout=15
        )
        
        if license.status_code == 200:
            cdm.parse_license(session_id, license.content)
            
            keys_extracted = []
            for key in cdm.get_keys(session_id):
                if key.type == 'CONTENT':
                    key_hex = key.key.hex()
                    key_id = key.kid.hex
                    keys_extracted.append(f"{key_id}:{key_hex}")
            
            cdm.close(session_id)
            return True, keys_extracted, license.status_code
        else:
            cdm.close(session_id)
            return False, [], license.status_code
            
    except Exception as e:
        if session_id is not None:
            try:
                cdm.close(session_id)
            except:
                pass
        return False, [], str(e)

def main():
    parser = argparse.ArgumentParser(description='Spotify Widevine Key Extractor with Auto Auth')
    parser.add_argument('--cookies', required=True, help='Path to cookies.txt file (Netscape format)')
    parser.add_argument('--wvd', default='./rooted_android14.wvd', help='Path to Widevine device file')
    args = parser.parse_args()
    
    # License URL domains to rotate through
    license_domains = [
        'gew1-spclient.spotify.com',
        'guc3-spclient.spotify.com',
        'gew4-spclient.spotify.com',
        'gae2-spclient.spotify.com',
        'gue1-spclient.spotify.com',
        'spclient.wg.spotify.com'
    ]
    
    print("=" * 60)
    print("Spotify Widevine Key Extractor")
    print("=" * 60)
    
    # Initialize Spotify Auth
    try:
        spotify_auth = SpotifyAuth(args.cookies)
    except Exception as e:
        print(f"✗ Failed to authenticate with Spotify: {e}")
        sys.exit(1)
    
    # Load Widevine device
    try:
        device = Device.load(args.wvd)
        cdm = Cdm.from_device(device)
        print(f"✓ Loaded Widevine device: {args.wvd}")
    except Exception as e:
        print(f"✗ Failed to load Widevine device: {e}")
        sys.exit(1)
    
    # Load PSSH values
    try:
        with open("pssh.txt", "r") as pssh_file:
            pssh_list = [line.strip() for line in pssh_file if line.strip()]
        print(f"✓ Loaded {len(pssh_list)} PSSH values from pssh.txt")
    except Exception as e:
        print(f"✗ Failed to read pssh.txt: {e}")
        sys.exit(1)
    
    print("=" * 60)
    print("Starting key extraction...\n")
    
    # Process each PSSH
    keys_file = open("keys.txt", "w")
    failed_file = open("failed_pssh.txt", "w")
    forbidden_file = open("pssh_403.txt", "w")
    
    successful_count = 0
    failed_count = 0
    forbidden_count = 0
    current_domain_idx = 0  # Global domain index that persists across all requests
    
    for idx, pssh_value in enumerate(pssh_list, 1):
        print(f"[{idx}/{len(pssh_list)}] Processing PSSH...")
        
        extracted = False
        retry_count = 0
        max_retries = 2
        attempts_on_current_pssh = 0
        
        while not extracted and retry_count <= max_retries:
            license_url = f"https://{license_domains[current_domain_idx]}/widevine-license/v1/audio/license"
            
            try:
                auth_token = spotify_auth.get_token()
            except Exception as e:
                print(f"  ✗ Failed to get auth token: {e}")
                print(f"  ⏳ Waiting 60 seconds before continuing...")
                time.sleep(60)
                continue
            
            if retry_count > 0:
                print(f"  Retry {retry_count}/{max_retries} using domain: {license_domains[current_domain_idx]}")
                time.sleep(5)  # 5 second delay for retries
            
            success, keys_extracted, status = extract_key_from_pssh(
                pssh_value, license_url, auth_token, cdm, args.wvd
            )
            
            attempts_on_current_pssh += 1
            
            if success:
                extracted = True
                for key_line in keys_extracted:
                    print(f"  ✓ Extracted: {key_line}")
                    keys_file.write(key_line + "\n")
                    keys_file.flush()
                successful_count += 1
                time.sleep(2)  # Normal 2 second delay
            else:
                # Special handling for 403 Forbidden - skip immediately, no retries
                if status == 403:
                    print(f"  🚫 403 Forbidden on {license_domains[current_domain_idx]} - skipping (no retries)")
                    forbidden_file.write(pssh_value + "\n")
                    forbidden_file.flush()
                    forbidden_count += 1
                    break  # Exit retry loop immediately
                
                print(f"  ✗ Failed with status: {status} on {license_domains[current_domain_idx]}")
                
                # Switch domain permanently for all future requests
                old_domain = license_domains[current_domain_idx]
                current_domain_idx = (current_domain_idx + 1) % len(license_domains)
                new_domain = license_domains[current_domain_idx]
                print(f"  🔄 Switching from {old_domain} to {new_domain} for all future requests")
                
                # Special handling for rate limiting (429)
                if status == 429:
                    if attempts_on_current_pssh == 1:
                        # First time hitting rate limit on this PSSH, just switched domain
                        pass
                    else:
                        # Hit rate limit again, wait longer
                        print(f"  ⏳ Rate limited - waiting 60 seconds...")
                        time.sleep(60)
                
                retry_count += 1
        
        if not extracted and status != 403:
            print(f"  ✗ Failed to extract key after {max_retries} retries")
            failed_file.write(pssh_value + "\n")
            failed_file.flush()
            failed_count += 1
    
    keys_file.close()
    failed_file.close()
    forbidden_file.close()
    
    print("\n" + "=" * 60)
    print("Extraction Complete!")
    print("=" * 60)
    print(f"✓ Successfully extracted: {successful_count}/{len(pssh_list)}")
    print(f"🚫 Forbidden (403): {forbidden_count}/{len(pssh_list)}")
    print(f"✗ Failed (other errors): {failed_count}/{len(pssh_list)}")
    print(f"\nKeys saved to: keys.txt")
    if forbidden_count > 0:
        print(f"403 Forbidden PSSH values saved to: pssh_403.txt")
    if failed_count > 0:
        print(f"Failed PSSH values saved to: failed_pssh.txt")

if __name__ == "__main__":
    main()
