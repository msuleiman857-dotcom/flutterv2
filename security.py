# security.py
import os
import re
import hmac
import hashlib
import uuid
import time
import requests
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from email_validator import validate_email, EmailNotValidError

ph = PasswordHasher()
PEPPER = os.environ.get("APP_SECRET_PEPPER", "dev_fallback_pepper").encode()
APP_HMAC_SECRET = os.environ.get("APP_HMAC_SECRET", "b9e831f45c229a1b07d6e534f10a3c928d77f62e14b5a0d3c9e8f1a2b3c4d5e6")

# In production, use Redis for this cache so it works across multiple servers.
# We use this to store PoW challenges temporarily.
POW_CACHE = {}

def hash_password(password: str) -> str:
    """Applies a cryptographic pepper via HMAC, then hashes with memory-hard Argon2id."""
    peppered_password = hmac.new(PEPPER, password.encode('utf-8'), hashlib.sha256).hexdigest()
    return ph.hash(peppered_password)

def verify_bot_token(token: str, ip_address: str) -> bool:
    """Validates CAPTCHA/Turnstile to block botnets."""
    if not token: return False

    # Use Cloudflare's built-in test secret key for development
    # This key ALWAYS returns success - no account needed
    secret_key = os.environ.get("CAPTCHA_SECRET_KEY", "1x0000000000000000000000000000000AA")

    verify_url = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
    try:
        response = requests.post(verify_url, data={
            'secret': secret_key,
            'response': token,
            'remoteip': ip_address
        }, timeout=5)
        return response.json().get("success", False)
    except requests.exceptions.RequestException:
        return False

def is_valid_email_format(email: str) -> bool:
    if len(email) > 254: return False
    try:
        validate_email(email, check_deliverability=False)
        return True
    except EmailNotValidError:
        return False

def is_valid_username(username: str) -> bool:
    if not (3 <= len(username) <= 50): return False
    return bool(re.match(r"^\w+$", username))

# --- APP SIGNATURE VERIFICATION ---

def generate_app_signature(payload: str) -> str:
    """Generates HMAC-SHA256 signature matching the Flutter app."""
    return hmac.new(
        APP_HMAC_SECRET.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

def verify_app_signature(request) -> bool:
    """Validates the X-App-Signature header against the request body."""
    received_signature = request.headers.get('X-App-Signature', '')
    if not received_signature:
        return False
    
    body = request.get_data(as_text=True)
    if not body:
        return False
    
    expected_signature = generate_app_signature(body)
    return hmac.compare_digest(expected_signature, received_signature)

# --- PROOF OF WORK & ANOMALY DETECTION ---

def generate_pow_challenge() -> dict:
    """Generates a cryptographic puzzle for the client to solve."""
    challenge_id = str(uuid.uuid4())
    nonce = os.urandom(16).hex()
    difficulty = 4 # Requires finding a hash starting with '0000'. Adjust based on device power.

    # Store in cache with an expiration time (e.g., 5 minutes)
    POW_CACHE[challenge_id] = {
        "nonce": nonce,
        "difficulty": difficulty,
        "expires": time.time() + 300
    }
    return {"challenge_id": challenge_id, "nonce": nonce, "difficulty": difficulty}

def verify_pow(challenge_id: str, client_answer: str) -> bool:
    """Verifies that the client actually spent CPU cycles solving the puzzle."""
    challenge = POW_CACHE.get(challenge_id)
    if not challenge or time.time() > challenge["expires"]:
        return False # Challenge invalid or expired

    # Check if the client's answer produces a hash with the required leading zeros
    attempt = f"{challenge['nonce']}{client_answer}".encode('utf-8')
    hash_result = hashlib.sha256(attempt).hexdigest()

    if hash_result.startswith('0' * challenge["difficulty"]):
        del POW_CACHE[challenge_id] # Burn the challenge so it can't be reused (Replay attack prevention)
        return True
    return False

def is_suspicious_request(request) -> bool:
    # 1. User-Agent Check - Allow browsers in development
    user_agent = request.headers.get('User-Agent', '').lower()

    # Allow Flutter's custom user agent
    if 'mysecureapp' in user_agent:
        pass  # Valid app user agent
    # Allow Chrome/Firefox/Safari for web testing
    elif any(browser in user_agent for browser in ['mozilla', 'chrome', 'safari', 'firefox']):
        pass  # Valid browser
    else:
        if not user_agent or 'python-requests' in user_agent or 'curl' in user_agent:
            return True

    # 2. Enforce Origin (skip for mobile apps, enforce for browsers)
    origin = request.headers.get('Origin')

    # Check if this looks like a browser request
    is_browser = any(browser in user_agent for browser in ['mozilla', 'chrome', 'safari', 'firefox'])

    if is_browser and origin:
        allowed_origins = [
            "http://localhost",
            "http://127.0.0.1",
            os.environ.get("EXPECTED_APP_ORIGIN", ""),
        ]
        is_valid_origin = any(origin.startswith(allowed) for allowed in allowed_origins if allowed)
        if not is_valid_origin:
            return True

    # 3. Validate Custom HMAC Signature (NOW ACTUALLY VERIFIES!)
    if not verify_app_signature(request):
        return True

    return False

# Generate a dummy hash once when the server starts.
# We use this to waste the exact same amount of CPU time when a user DOES NOT exist.
DUMMY_HASH = hash_password("dummy_timing_mitigation_password")

def verify_password(stored_hash: str, provided_password: str) -> bool:
    """Peppers the provided password and safely verifies it against the Argon2 hash."""
    peppered_password = hmac.new(PEPPER, provided_password.encode('utf-8'), hashlib.sha256).hexdigest()
    try:
        # Argon2 verification securely resists timing attacks internally
        return ph.verify(stored_hash, peppered_password)
    except VerifyMismatchError:
        return False

def dummy_verify(provided_password: str):
    """Executes a computationally heavy verify operation to mask user existence."""
    peppered_password = hmac.new(PEPPER, provided_password.encode('utf-8'), hashlib.sha256).hexdigest()
    try:
        ph.verify(DUMMY_HASH, peppered_password)
    except VerifyMismatchError:
        pass