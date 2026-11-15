import os
import time
import math
import eventlet.tpool
os.environ['EVENTLET_NO_GREENDNS'] = 'yes'

import eventlet
eventlet.monkey_patch()
import boto3

from flask import Flask, request, jsonify
import hmac
import hashlib
from database_connector import generate_reset_code
from flask_limiter import Limiter
from flask_socketio import SocketIO
from flask_limiter.util import get_remote_address
import logging
import json
import requests
from dotenv import load_dotenv
from email_security import send_reset_email, send_verify_email
from datetime import datetime, timedelta, timezone
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, messaging, storage
from firebase_admin import auth as firebase_auth
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from cryptography.fernet import Fernet
import uuid    
from security import (
    hash_password, is_valid_email_format, is_valid_username,
    verify_bot_token, generate_pow_challenge, verify_pow, is_suspicious_request,
    dummy_verify, verify_password
)
from concurrent.futures import ThreadPoolExecutor, as_completed
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

import secrets
from urllib.parse import urlencode
from flask import redirect, session, abort, Response

WEBHOOK_PUBLIC_KEY = os.getenv("WEBHOOK_PUBLIC_KEY")

def verify_webhook_signature(payload, signature_header, public_key_pem):
    try:
        parts = signature_header.split(',')
        timestamp = next((p.split('=', 1)[1] for p in parts if p.startswith('t=')), None)
        signature = next((p.split('=', 1)[1] for p in parts if p.startswith('v0=')), None)
        if not timestamp or not signature:
            return False
        if int(time.time() * 1000) - int(timestamp) > 600000:
            return False
        signed_payload = f"{timestamp}.{payload.decode()}"
        digest = hashlib.sha256(signed_payload.encode()).digest()
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        public_key.verify(base64.b64decode(signature), digest, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False

r2 = boto3.client(
    's3',
    endpoint_url=f"https://{os.getenv('R2_ACCOUNT_ID')}.r2.cloudflarestorage.com",
    aws_access_key_id=os.getenv('R2_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('R2_SECRET_ACCESS_KEY'),
    region_name='auto',
)

NIGERIAN_BANKS = {
    "044": "Access Bank", "058": "GTBank", "033": "UBA", "057": "Zenith Bank", "011": "First Bank", 
    "214": "FCMB", "070": "Fidelity Bank", "035": "Wema Bank", "050": "Ecobank", "232": "Sterling Bank", 
    "076": "Polaris Bank", "032": "Union Bank", "221": "Stanbic IBTC", "305": "Opay", "50211": "Kuda Bank", 
    "090405": "Moniepoint MFB", "100033": "PalmPay", "082": "Keystone Bank", "023": "CitiBank", 
    "063": "Diamond Bank", "103": "Globus Bank", "107": "Optimus Bank", "104": "Parallex Bank", 
    "301": "Jaiz Bank", "068": "Standard Chartered", "100": "SunTrust Bank", "215": "Unity Bank", 
    "030": "Heritage Bank", "101": "Providus Bank", "102": "Titan Trust", "106": "Signature Bank", 
    "108": "Premium Trust", "060": "Stanbic Mobile", "302": "TAJBank", "303": "Corona Merchant", 
    "304": "FBNQuest Merchant", "307": "Lotus Bank", "309": "Nova Merchant", "090110": "VFD MFB (Vbank)", 
    "090175": "Rubies Bank", "090267": "Kredi Money MFB", "090408": "Gromicro MFB", "090550": "Carbon", 
    "090156": "FairMoney MFB", "50515": "Baxi", "100022": "GoMoney", "90115": "Taj Wallet", "565": "One MFB", 
    "601": "Fina Trust MFB", "50259": "Sparkle MFB", "090133": "Alat by Wema", "090328": "Eyowo", 
    "090281": "Mint Finex MFB", "090410": "Migo", "120001": "9PSB", "120002": "Hope PSB", 
    "120003": "MTN MoMo PSB", "120004": "Airtel SmartCash PSB"
}

load_dotenv(os.path.expanduser("~/flas/.env"))

def _supabase_headers():
    return {
        "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
        "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
        "Content-Type": "application/json",
    }


# ── Shared HTTP session for the chat hot path ───────────────────────────────
# Bare requests.get/post() opens a brand-new TCP+TLS connection on every call.
# A pooled Session keeps connections alive and reuses them. Retries are limited
# to *connection setup* failures, so a send can never be duplicated.
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_sb = requests.Session()
_sb.mount("https://", HTTPAdapter(
    pool_connections=10,
    pool_maxsize=50,
    max_retries=Retry(connect=2, read=0, status=0, redirect=0, backoff_factor=0.2),
))
_SB_TIMEOUT = 8  # seconds, so a slow Supabase call can't hang a request forever

# Sender profile pics are looked up on every message; cache them for 10 min.
_pic_cache = {}  # user_id -> (profile_pic_url, expires_at)
_PIC_TTL = 600


def _get_profile_pic(user_id):
    uid = str(user_id)
    hit = _pic_cache.get(uid)
    if hit and hit[1] > time.time():
        return hit[0]
    try:
        res = _sb.get(
            f"{os.getenv('SUPABASE_URL')}/rest/v1/users",
            headers=_supabase_headers(),
            params={"id": f"eq.{uid}", "select": "profile_pic_url"},
            timeout=_SB_TIMEOUT,
        )
        if res.status_code == 200:
            rows = res.json()
            pic = rows[0].get('profile_pic_url') if rows else None
            _pic_cache[uid] = (pic, time.time() + _PIC_TTL)
            return pic
    except Exception as e:
        logging.warning(f"Could not fetch profile pic for {uid}: {e}")
    return None

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")
BRIDGE_KEY = os.getenv("BRIDGE_KEY")
KORA_API = (os.getenv('KORA_API'))
PREMIUM_PRICE = int(os.getenv('PREMIUM_PRICE_NAIRA'))
PREMIUM_DAYS = int(os.getenv('PREMIUM_DAYS'))
PUBLIC_URL = (os.getenv('PUBLIC_BASE_URL'))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIREBASE_KEY_PATH = os.path.join(BASE_DIR, "firebase")
if not firebase_admin._apps:
    try:
        # 1. Try to load credentials from an Environment Variable first (For Render)
        firebase_env_creds = os.getenv("FIREBASE_CREDENTIALS")
        
        if firebase_env_creds:
            cred_dict = json.loads(firebase_env_creds)
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred, {'storageBucket': 'flutterv2-98784.firebasestorage.app'})
            print("🔥 Firebase initialized successfully via Environment Variable!")
            
        else:
            print("⚠️ Firebase init failed: No credentials found in ENV or File.")
            
    except Exception as e:
        print(f"⚠️ Firebase init failed: {e}")

if not firebase_admin._apps:
    try:
        if FIREBASE_KEY_PATH and os.path.exists(FIREBASE_KEY_PATH):
            cred = credentials.Certificate(FIREBASE_KEY_PATH)
            firebase_admin.initialize_app(cred)
            print("🔥 Firebase initialized successfully!")
        else:
            print("⚠️ Firebase init failed: Path not found or not set in .env")
    except Exception as e:
        print(f"⚠️ Firebase init failed (Check your JSON file): {e}")

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")

fernet = Fernet(ENCRYPTION_KEY)

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

app.config['SECRET_KEY'] = FLASK_SECRET_KEY
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)
jwt = JWTManager(app)
active_users = {}
premium_cache = {}

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[]
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - SECURITY - %(levelname)s - %(message)s')

@socketio.on('connect')
def handle_connect():
    # Grab the user_id from the Flutter connection request
    user_id = request.args.get('user_id')
    if user_id:
        active_users[user_id] = request.sid
        print(f"User {user_id} connected! Active users: {len(active_users)}")
        # Warm the profile-pic cache so their first message doesn't pay for it.
        socketio.start_background_task(_get_profile_pic, user_id)

@socketio.on('disconnect')
def handle_disconnect():
    for uid, sid in list(active_users.items()):
        if sid == request.sid:
            del active_users[uid]
            print(f"User {uid} disconnected.")
            break

@app.route('/')
def base():
    return jsonify({"status": "haha"}), 200

@app.get('/health')
def health():
    return {'status': 'ok'}

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    try:
        res = requests.get(
            f"{os.getenv('SUPABASE_URL')}/rest/v1/revoked_tokens",
            headers=_supabase_headers(),
            params={"jti": f"eq.{jti}", "select": "jti"},
            timeout=5,
        )
        return res.status_code == 200 and len(res.json()) > 0
    except requests.exceptions.RequestException:
        # Supabase hiccup shouldn't lock every logged-in user out of the
        # entire app — fail open (treat as not-revoked) rather than closed.
        return False

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    user_id = get_jwt_identity()
    jwt_data = get_jwt()
    jti = jwt_data["jti"]
    expires_at = datetime.fromtimestamp(jwt_data["exp"], tz=timezone.utc).isoformat()

    try:
        res = requests.post(
            f"{os.getenv('SUPABASE_URL')}/rest/v1/revoked_tokens",
            headers=_supabase_headers(),
            json={"jti": jti, "expires_at": expires_at},
            timeout=10,
        )
        if res.status_code not in (200, 201):
            logging.error(f"Failed to revoke token for {user_id}: {res.text}")
            return jsonify({"status": "error", "message": "Logout failed. Please try again."}), 500

        return jsonify({"status": "success", "message": "Logged out."}), 200
    except requests.exceptions.RequestException as e:
        logging.error(f"logout request error for {user_id}: {e}")
        return jsonify({"status": "error", "message": "Logout failed. Please try again."}), 500

@app.route('/api/firebase-token', methods=['GET'])
@jwt_required()
def get_firebase_token():
    user_id = get_jwt_identity()
    try:
        custom_token = firebase_auth.create_custom_token(user_id)
        return jsonify({'success': True, 'token': custom_token.decode('utf-8')}), 200
    except Exception as e:
        logging.error(f"firebase token error: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/upload-profile-pic', methods=['POST'])
@jwt_required()
def upload_profile_pic():
    user_id = get_jwt_identity()

    try:
        file = request.files.get('file')
        mime_type = request.form.get('mime_type', 'image/jpeg')
        if not file:
            return jsonify({'success': False, 'message': 'No file provided'}), 400

        # Always saved as profile.jpg so each user has exactly one
        # profile picture file, overwritten on every new upload.
        storage_path = f"profile/{user_id}/profile.jpg"
        url = f"{os.getenv('SUPABASE_URL')}/storage/v1/object/meetup/{storage_path}"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": mime_type,
            "x-upsert": "true",
        }

        file_bytes = file.read()
        response = requests.post(url, headers=headers, data=file_bytes)

        if response.status_code in (200, 201):
            # Cache-bust so the new image shows immediately instead of
            # browsers/clients serving a stale cached copy of profile.jpg
            public_url = (
                f"{os.getenv('SUPABASE_URL')}/storage/v1/object/public/meetup/{storage_path}"
                f"?t={int(time.time())}"
            )
            return jsonify({'success': True, 'public_url': public_url}), 200
        else:
            logging.error(f"Supabase profile pic upload error: {response.text}")
            return jsonify({'success': False, 'message': 'Upload to storage failed'}), 500
    except Exception as e:
        logging.error(f"upload_profile_pic error: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/payments/exists', methods=['GET'])
@jwt_required()
def payment_exists():
    try:
        user_id = get_jwt_identity()
        other_id = request.args.get('other_id')

        if not other_id:
            return jsonify({"exists": False}), 400

        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}"
        }

        res = requests.get(
            f"{supabase_url}/rest/v1/payments",
            headers=headers,
            params={
                "or": f"(and(payer_id.eq.{user_id},recipient_id.eq.{other_id}),and(payer_id.eq.{other_id},recipient_id.eq.{user_id}))",
                "status": "eq.success",
                "concluded": "eq.false",        # ← only unreleased payments
                "select": "id,payer_id,reference",  # ← add reference here
                "order": "created_at.desc", 
                "limit": "1"
            }
        )

        if res.status_code == 200 and res.json():
            row = res.json()[0]
            is_payer = str(row['payer_id']) == str(user_id)
            return jsonify({
                "exists": True,
                "is_payer": is_payer,
                "reference": row['reference']   # ← return it
            }), 200

        return jsonify({"exists": False, "is_payer": False, "reference": None}), 200

    except Exception as e:
        logging.error(f"payment_exists error: {e}")
        return jsonify({"exists": False, "is_payer": False, "reference": None}), 500

def get_payout_status(reference, kora_headers, kora_api_base, timeout=15):
    """
    Source-of-truth check: does Kora already have a record of this payout reference?
    Returns:
      {"found": True,  "status": "success"|"processing"|"pending"|"failed", "raw": {...}}
      {"found": False, "status": None, "raw": None}                # Kora has never seen this reference
      {"found": None,  "status": None, "raw": {"error": "..."}}    # unknown — Kora unreachable/errored
    "found": None must ALWAYS be treated as "do not disburse" by the caller — never assume
    absence of confirmation means it's safe to pay.
    """
    url = f"{kora_api_base}/transactions/{reference}"
    try:
        response = requests.get(url, headers=kora_headers, timeout=timeout)
        if response.status_code == 404:
            return {"found": False, "status": None, "raw": None}
        if response.status_code != 200:
            logging.error(f"get_payout_status non-200 for {reference}: {response.status_code} {response.text}")
            return {"found": None, "status": None, "raw": {"error": response.text}}
        payload = response.json()
        record = payload.get("data", {}) or {}
        return {"found": True, "status": record.get("status"), "raw": payload}
    except requests.exceptions.RequestException as e:
        logging.error(f"get_payout_status request error for {reference}: {e}")
        return {"found": None, "status": None, "raw": {"error": str(e)}}


@app.route('/api/public_profile/<string:user_id>', methods=['GET'])
@jwt_required()
def get_public_profile(user_id):
    """Public-safe profile lookup — any logged-in user can view this, unlike
    /api/user_profile/<id> which is locked to the owner and exposes bank info."""
    try:
        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}"
        }

        res = requests.get(
            f"{supabase_url}/rest/v1/users",
            headers=headers,
            params={"id": f"eq.{user_id}", "select": "username,profile_pic_url,kyc,price_naira,latitude,longitude"}
        )

        if res.status_code != 200 or not res.json():
            return jsonify({"status": "error", "success": False, "message": "User not found"}), 404

        return jsonify({"status": "success", "success": True, "data": res.json()[0]}), 200

    except Exception as e:
        logging.error(f"get_public_profile error: {e}")
        return jsonify({"status": "error", "success": False, "message": "Internal server error"}), 500

@app.route('/api/user_profile/<string:user_id>', methods=['GET'])
@jwt_required()
def get_user_profile(user_id):
    if str(user_id) != get_jwt_identity():
        return jsonify({"status": "error", "message": "Unauthorized action"}), 403

    try:
        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}"
        }

        # Fetch user fields
        user_res = requests.get(
            f"{supabase_url}/rest/v1/users",
            headers=headers,
            params={"id": f"eq.{user_id}", "select": "username,kyc,profile_pic_url,price_naira"}
        )
        if user_res.status_code != 200 or not user_res.json():
            return jsonify({"status": "error", "message": "User not found"}), 404

        data = user_res.json()[0]

        # ✅ FIX: Also fetch linked bank details
        bank_res = requests.get(
            f"{supabase_url}/rest/v1/linked_bank",
            headers=headers,
            params={"owner_id": f"eq.{user_id}", "select": "account_number,bank_name"}
        )
        if bank_res.status_code == 200 and bank_res.json():
            bank = bank_res.json()[0]
            data['bank_no'] = bank.get('account_number')
            data['bank_institution'] = bank.get('bank_name')
        else:
            data['bank_no'] = None
            data['bank_institution'] = None

        return jsonify({"status": "success", "success": True, "data": data}), 200

    except Exception as e:
        logging.error(f"get_user_profile error: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

def _check_single_bank(bank_code, bank_name, account_number, headers):
    """Silently hits Kora API to verify if account matches the specific bank."""
    try:
        url = "https://api.korapay.com/merchant/api/v1/misc/banks/resolve"
        payload = {"bank": bank_code, "account": account_number, "currency": "NGN"}
        res = requests.post(url, json=payload, headers=headers, timeout=4)
        res_json = res.json()
        
        if res.status_code == 200 and res_json.get("status") is True:
            return {
                "bank_name": bank_name,
                "bank_code": bank_code,
                "account_name": res_json.get("data", {}).get("account_name")
            }
    except Exception:
        pass
    return None

@app.route('/api/payout/resolve-account', methods=['POST'])
@jwt_required()
def resolve_bank_account():
    try:
        data = request.get_json(silent=True) or {}
        account_number = data.get('account_number')
        bank_code = data.get('bank_code') # From dropdown input

        if not account_number or len(str(account_number).strip()) < 10:
            return jsonify({"status": "error", "success": False, "message": "Valid 10-digit account number is required"}), 400
            
        if not bank_code:
            return jsonify({"status": "error", "success": False, "message": "Bank institution selection is required"}), 400

        bank_name = NIGERIAN_BANKS.get(str(bank_code), "Unknown Bank")

        # 🌟 EXACT RECONSTRUCTION FROM YOUR ORIGINAL WORKING PATH CONFIG
        url = "https://api.korapay.com/merchant/api/v1/misc/banks/resolve"
        
        headers = {
            "Authorization": f"Bearer {os.getenv('KORAPAY_SECRET_KEY')}",
            "Content-Type": "application/json"
        }
        
        # 🌟 EXACT PAYLOAD KEYS FROM YOUR SCRIPT
        payload = {
            "bank": str(bank_code).strip(),
            "account": str(account_number).strip(),
            "currency": "NGN"
        }

        logging.info(f"Direct manual check for {bank_name} ({bank_code}) - Acct: {account_number}")
        
        response = requests.post(url, headers=headers, json=payload, timeout=10)

        if response.status_code == 200 and response.text:
            try:
                res_json = response.json()
                if res_json.get("status") is True and "data" in res_json:
                    account_name = res_json["data"].get("account_name")
                    if account_name:
                        return jsonify({
                            "status": "success",
                            "success": True,
                            "account_name": account_name
                        }), 200
            except json.JSONDecodeError:
                logging.error(f"Malformed JSON data received from gateway.")

        logging.warning(f"Korapay API Refusal (Status {response.status_code}): {response.text}")

        return jsonify({
            "status": "error",
            "success": False,
            "message": f"Could not verify details with {bank_name}. Please confirm credentials."
        }), 404

    except Exception as e:
        logging.error(f"Manual account resolution processing crash: {e}")
        return jsonify({"status": "error", "success": False, "message": "Internal verification error occurred"}), 500

@app.route('/api/payout/save-link', methods=['POST'])
@jwt_required()
def save_bank_link():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "message": "Missing request payload body"}), 400
            
        owner_id = data.get('owner_id')
        account_number = data.get('account_number')
        acct_name = data.get('acct_name')
        bank_code = data.get('bank_code')
        bank_name = data.get('bank_name')
        
        if not all([owner_id, account_number, acct_name, bank_code, bank_name]):
            return jsonify({"success": False, "message": "Missing required linkage fields"}), 400

        # ✨ INSERT / UPDATE LINKED BANK IN SUPABASE VIA REST API
        # ✨ FIXED: Added '?on_conflict=owner_id' to target the unique column constraint for merging
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/linked_bank?on_conflict=owner_id"
        
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates" # Now it knows exactly what to merge on duplicate!
        }
        payload = {
            "owner_id": str(owner_id),
            "account_number": str(account_number),
            "acct_name": str(acct_name),
            "bank_code": str(bank_code),
            "bank_name": str(bank_name)
        }

        response = requests.post(url, headers=headers, json=payload)

        if response.status_code in [200, 201]:
            return jsonify({"success": True, "message": "Bank account linked successfully!"}), 200
        else:
            logging.error(f"Supabase error linking bank: {response.text}")
            return jsonify({"success": False, "message": f"Database rejected linkage: {response.text}"}), 500

    except Exception as e:
        logging.error(f"Exception in save_bank_link: {str(e)}")
        return jsonify({"success": False, "message": f"Internal server exception error: {str(e)}"}), 500

@app.route('/api/update_location', methods=['POST'])
@jwt_required()
def update_location():
    try:
        user_id = get_jwt_identity()
        data = request.get_json(silent=True) or {}
        lat = data.get('latitude')
        lng = data.get('longitude')

        if lat is None or lng is None:
            return jsonify({"success": False, "message": "Missing coordinates"}), 400

        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json"
        }

        res = requests.patch(
            f"{supabase_url}/rest/v1/users?id=eq.{user_id}",
            headers=headers,
            json={"latitude": lat, "longitude": lng}
        )

        if res.status_code in (200, 204):
            return jsonify({"success": True}), 200
        else:
            return jsonify({"success": False}), 500

    except Exception as e:
        logging.error(f"update_location error: {e}")
        return jsonify({"success": False}), 500

@app.route('/api/user_location/<string:user_id>', methods=['GET'])
@jwt_required()
def get_user_location(user_id):
    me = get_jwt_identity()

    if not re.fullmatch(r'[0-9a-fA-F-]{36}', user_id):
        return jsonify({"success": False, "message": "Invalid user id"}), 400

    if me != user_id:
        chk = requests.get(
            f"{os.getenv('SUPABASE_URL')}/rest/v1/mutual_contacts",
            headers=_supabase_headers(),
            params={
                "status": "eq.true",
                "select": "id",
                "or": f"(and(sender.eq.{me},accepter.eq.{user_id}),"
                      f"and(sender.eq.{user_id},accepter.eq.{me}))",
                "limit": "1",
            },
            timeout=_SB_TIMEOUT,
        )
        if chk.status_code != 200 or not chk.json():
            return jsonify({"success": False, "message": "Not in your circle"}), 403
    try:
        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}"
        }

        res = requests.get(
            f"{supabase_url}/rest/v1/users",
            headers=headers,
            params={"id": f"eq.{user_id}", "select": "latitude,longitude"}
        )

        if res.status_code == 200 and res.json():
            row = res.json()[0]
            return jsonify({
                "success": True,
                "latitude": row.get("latitude"),
                "longitude": row.get("longitude")
            }), 200

        return jsonify({"success": False, "message": "User not found"}), 404

    except Exception as e:
        logging.error(f"get_user_location error: {e}")
        return jsonify({"success": False}), 500

@app.route('/api/payout/cancel', methods=['POST'])
@jwt_required()
def cancel_payout():
    """Destroys the pending payment row when the user backs out."""
    try:
        user_id = get_jwt_identity()
        data = request.get_json(silent=True) or {}
        reference = data.get('reference')
        
        if not reference:
            return jsonify({"status": "error", "message": "Reference required"}), 400

        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/payments"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
        }
        # Only delete if it's pending, belongs to this user, and matches the reference
        params = {
            "reference": f"eq.{reference}",
            "payer_id": f"eq.{user_id}",
            "status": "eq.pending"
        }
        
        res = requests.delete(url, headers=headers, params=params)
        
        if res.status_code in (200, 204):
            return jsonify({"status": "success", "message": "Payment row destroyed"}), 200
        else:
            logging.error(f"Failed to delete payment: {res.text}")
            return jsonify({"status": "error", "message": "Failed to delete"}), 500

    except Exception as e:
        logging.error(f"Cancel payout error: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

def _haversine_km(lat1, lon1, lat2, lon2):
    """Straight-line distance in km between two lat/lng points."""
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    return R * (2 * math.atan2(math.sqrt(a), math.sqrt(1 - a)))


@app.route('/api/update-token', methods=['POST'])
@jwt_required()
def api_update_token():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    user_id = data.get('user_id')
    fcm_token = data.get('fcm_token')

    if str(user_id) != get_jwt_identity():
        return jsonify({"status": "error", "message": "Unauthorized user action"}), 403

    if not user_id or not fcm_token:
        return jsonify({"status": "error", "message": "Missing user_id or fcm_token"}), 400

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/users"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal" # Tells Supabase not to send the whole user row back
        }

        # Tell Supabase which user to update (WHERE id = user_id)
        params = {"id": f"eq.{user_id}"}

        # The data we are updating (SET fcm_token = fcm_token)
        payload = {"fcm_token": fcm_token}

        # Use requests.patch to UPDATE data
        response = requests.patch(url, headers=headers, params=params, json=payload)

        if response.status_code in [200, 204]:
            return jsonify({"status": "success", "message": "FCM Token updated!"}), 200
        else:
            logging.error(f"Supabase update token error: {response.text}")
            return jsonify({"status": "error", "message": "Database error"}), 500

    except Exception as e:
        logging.error(f"Failed to update token: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route('/api/login', methods=['POST'])
@limiter.limit("70 per minute")
def api_login():
    client_ip = request.remote_addr

    # 1. ANOMALY DETECTION (Block direct IP access & malicious scripts)
    '''if is_suspicious_request(request):
        logging.warning(f"Suspicious login dropped from IP: {client_ip}")
        return jsonify({"status": "error", "message": "Not found"}), 404'''

    try:
        data = request.get_json(silent=True)
    except Exception:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    if not data or 'username' not in data or 'password' not in data:
       return jsonify({'status': 'error', 'message': 'Username/Email and password required'}), 400

    identifier = str(data['username']).strip()
    password = str(data['password'])
    bot_token = str(data.get("captcha_token", ""))
    pow_challenge_id = str(data.get("pow_challenge_id", ""))
    pow_answer = str(data.get("pow_answer", ""))
    
    # ✨ NEW: Grab the location from the incoming Flutter payload. 
    # Fallback safely to "Unknown" if the user denied permission on the frontend.
    user_latitude = data.get("latitude")   # NEW
    user_longitude = data.get("longitude")

    # Input length limits to prevent extreme payload DoS
    if len(identifier) < 3 or not (1 <= len(password) <= 128):
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

    try:
        # SUPABASE REST API CONFIG
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/users"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json"
        }

        # 3. FETCH USER BY IDENTIFIER ONLY
        params = {"select": "*"}
        if '@' in identifier:
            params["email"] = f"eq.{identifier}"
        else:
            params["username"] = f"eq.{identifier}"

        # Send the web request to Supabase
        response = requests.get(url, headers=headers, params=params)

        if response.status_code != 200:
            logging.error(f"Supabase login fetch error: {response.text}")
            return jsonify({'status': 'error', 'message': 'Database error'}), 500

        data = response.json()
        user = data[0] if len(data) > 0 else None

        # 4. TIMING ATTACK MITIGATION & PASSWORD VERIFICATION
        is_valid_login = False

        if user:
            is_valid_login = verify_password(user['password'], password)
        else:
            dummy_verify(password)

        # 5. FINAL DECISION
        if is_valid_login:
            access_token = create_access_token(identity=str(user['id']))
        
            # ✅ FIX: Fetch linked bank at login and include in response
            bank_no = None
            bank_institution = None
            try:
                bank_res = requests.get(
                    f"{os.getenv('SUPABASE_URL')}/rest/v1/linked_bank",
                    headers=headers,
                    params={"owner_id": f"eq.{user['id']}", "select": "account_number,bank_name"}
                )
                if bank_res.status_code == 200 and bank_res.json():
                    bank = bank_res.json()[0]
                    bank_no = bank.get('account_number')
                    bank_institution = bank.get('bank_name')
            except Exception as bank_err:
                logging.error(f"Bank fetch at login failed: {bank_err}")
        
            return jsonify({
                'status': 'success',
                'username': user['username'],
                'id': user['id'],
                'access_token': access_token,
                'kyc': user.get('kyc', False),
                'bank_kyc': user.get('bank_kyc', False),        # ✅ NEW
                'customer_id': user.get('customer_id'),          # ✅ NEW
                'bank_no': bank_no,
                'bank_institution': bank_institution
            }), 200
        else:
            logging.warning(f"Failed login attempt for identifier: {identifier} from IP: {client_ip}")
            return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

    except Exception as e:
        logging.error(f"Login error: {e}")
        import traceback
        logging.error(f"Full traceback: {traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': 'An internal server error occurred'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({"status": "error","message": "Too many requests. Please try again later."}), 429

@app.route('/api/register/challenge', methods=['GET'])
def get_challenge():
    """Client must call this first to get a CPU puzzle to solve."""
    challenge = generate_pow_challenge()
    return jsonify(challenge), 200

@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def api_register():
    client_ip = request.remote_addr

    try:
        data = request.get_json(silent=True)
    except Exception:
        return jsonify({"status": "error", "message": "Invalid JSON"}), 400

    if not data or not isinstance(data, dict):
        return jsonify({"status": "error", "message": "Invalid body"}), 400

    username = str(data.get("username", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    password = str(data.get("password", ""))

    if not is_valid_username(username) or not is_valid_email_format(email):
        return jsonify({"status": "error", "message": "Invalid registration data."}), 400

    if len(password) < 8 or len(password) > 128:
        return jsonify({"status": "error", "message": "Password must be 8-128 characters."}), 400

    try:
        # 1. Check if user already exists (Email OR Username)
        url_users = f"{os.getenv('SUPABASE_URL')}/rest/v1/users"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json"
        }
        
        # Supabase 'or' syntax checks both conditions in a single query
        params = {
            "or": f"(email.eq.{email},username.eq.{username})",
            "select": "email,username" 
        }
        
        check_user = requests.get(url_users, headers=headers, params=params)
        
        if check_user.status_code == 200:
            existing_users = check_user.json()
            if len(existing_users) > 0:
                # Figure out exactly which field caused the conflict
                conflict = existing_users[0]
                if conflict.get('email') == email:
                    return jsonify({"status": "error", "message": "An account with this email already exists."}), 409
                else:
                    return jsonify({"status": "error", "message": "This username is already taken."}), 409

        # 2. Generate OTP and Expiry Time
        otp_code = generate_reset_code() # Reusing your secure generator
        
        # 3. Store OTP in verify_email table (UPSERT to overwrite if they request again)
        url_verify = f"{os.getenv('SUPABASE_URL')}/rest/v1/verify_email"
        headers["Prefer"] = "resolution=merge-duplicates" # Overwrite if email exists
        
        payload = {
            "email": email,
            "verification_code": otp_code,
            "created_at": datetime.now(timezone.utc).isoformat()
        }

        params_upsert = {"on_conflict": "email"}
        response = requests.post(url_verify, headers=headers, json=payload, params=params_upsert)

        if response.status_code in (200, 201):
            # 4. Send the email using your existing function
            send_verify_email(email, otp_code)
            
            return jsonify({
                "status": "success",
                "message": "OTP sent! Please check your email."
            }), 200
        else:
            logging.error(f"Supabase DB error saving OTP: {response.text}")
            return jsonify({"status": "error", "message": "Failed to generate OTP."}), 500

    except Exception as e:
        logging.error(f"Registration exception: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route("/api/verify_reg_otp", methods=["POST"])
@limiter.limit("10 per minute")
def verify_reg_otp():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()
    otp_code = data.get("otp_code", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not email or not otp_code or not username or not password:
        return jsonify({"status": "error", "message": "All fields and OTP are required"}), 400

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url_verify = f"{os.getenv('SUPABASE_URL')}/rest/v1/verify_email"
        url_users = f"{os.getenv('SUPABASE_URL')}/rest/v1/users"
        
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json"
        }

        # 1. Fetch OTP from verify_email table
        params = {"email": f"eq.{email}", "select": "*"}
        res = requests.get(url_verify, headers=headers, params=params)

        if res.status_code != 200:
            return jsonify({"status": "error", "message": "Database error"}), 500

        verify_data = res.json()
        if not verify_data or len(verify_data) == 0:
            return jsonify({"status": "error", "message": "Invalid email or OTP expired."}), 400

        row = verify_data[0]
        db_code = row.get("verification_code")
        created_at_str = row.get("created_at")

        # 2. Check if code matches
        if not db_code or db_code != otp_code:
            return jsonify({"status": "error", "message": "Invalid code."}), 400

        # 3. Check 5-minute expiration
        if created_at_str:
            clean_time_str = created_at_str[:19] # Ignore trailing milliseconds
            created_time = datetime.fromisoformat(clean_time_str).replace(tzinfo=timezone.utc)
            
            if datetime.now(timezone.utc) > created_time + timedelta(minutes=5):
                # Delete expired OTP
                requests.delete(url_verify, headers=headers, params={"email": f"eq.{email}"})
                return jsonify({"status": "error", "message": "OTP expired. Please register again."}), 400

        # 4. OTP is valid! Hash password and insert into users table
        hashed_password = hash_password(password)
        user_uuid = str(uuid.uuid4())

        user_payload = {
            "id": user_uuid,
            "email": email,
            "username": username,
            "password": hashed_password
        }

        # Use minimal return to save bandwidth
        headers["Prefer"] = "return=minimal"
        insert_res = requests.post(url_users, headers=headers, json=user_payload)

        if insert_res.status_code in (200, 201):
            # 5. Cleanup: Delete the used OTP from verify_email table
            requests.delete(url_verify, headers=headers, params={"email": f"eq.{email}"})
            
            logging.info(f"Account verified and created. UUID: {user_uuid}")
            return jsonify({"status": "success", "message": "Account verified! You can now log in."}), 201
            
        elif insert_res.status_code == 409 or "duplicate key" in insert_res.text.lower():
            return jsonify({"status": "error", "message": "Username already taken."}), 409
        else:
            return jsonify({"status": "error", "message": "Failed to create account."}), 500

    except Exception as e:
        logging.error(f"Verify Reg OTP error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

def parse_supabase_ts(ts_str):
    """Permanently fixes the 'Invalid isoformat string' error by padding microseconds."""
    if not ts_str: return None
    try:
        # 1. Standardize the offset
        clean_ts = ts_str.replace('Z', '+00:00')
        
        # 2. Fix the microsecond length if a decimal exists
        if '.' in clean_ts:
            base, offset = clean_ts.split('+') if '+' in clean_ts else (clean_ts, "")
            time_part, micro_part = base.split('.')
            # Pad the microsecond part to exactly 6 digits
            micro_part = micro_part.ljust(6, '0')[:6]
            clean_ts = f"{time_part}.{micro_part}+{offset}" if offset else f"{time_part}.{micro_part}"
            
        return datetime.fromisoformat(clean_ts)
    except Exception as e:
        logging.error(f"Timestamp parsing failed for {ts_str}: {e}")
        return datetime.now(timezone.utc) # Fallback to prevent 500 errors


@app.route('/api/conversations/<string:user_id>', methods=['GET'])
@jwt_required()
def get_conversations(user_id):
    # Security Check
    if str(user_id) != get_jwt_identity():
        return jsonify({"status": "error", "message": "Unauthorized action"}), 403

    try:
        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
        
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json"
        }

        # ── 1. Fetch conversations from Supabase RPC ────────────────────────
        rpc_url = f"{supabase_url}/rest/v1/rpc/get_user_conversations"
        response = requests.post(rpc_url, headers=headers, json={"p_user_id": user_id})

        if response.status_code != 200:
            logging.error(f"Supabase RPC error: {response.text}")
            return jsonify({"status": "error", "message": "Database error"}), 500

        conversations = response.json()
        current_user_premium = bool(is_premium_user(None, user_id))

        # ── 1.5. Find conversations that exist ONLY via payments ────────────
        # The RPC above only returns users with at least one row in
        # `messages`. If two users only ever exchanged a payment (or all
        # their messages were wiped/expired) they won't be in `conversations`
        # yet. We find those payment-only partners here and append synthetic
        # rows so they show up in the list too. Step 3 below already knows
        # how to turn a payment into a preview line, so we let it handle
        # these new rows the same way it handles existing ones.
        try:
            existing_ids = {str(c.get('id')) for c in conversations if c.get('id')}

            all_pay_res = requests.get(
                f"{supabase_url}/rest/v1/payments",
                headers={
                    "apikey": supabase_key,
                    "Authorization": f"Bearer {supabase_key}",
                },
                params={
                    "or": f"(payer_id.eq.{user_id},recipient_id.eq.{user_id})",
                    "status": "eq.success",
                    "select": "payer_id,recipient_id",
                }
            )

            if all_pay_res.status_code == 200:
                payment_partner_ids = set()
                for p in all_pay_res.json():
                    payer = str(p.get('payer_id'))
                    recipient = str(p.get('recipient_id'))
                    other = recipient if payer == str(user_id) else payer
                    if other and other != str(user_id):
                        payment_partner_ids.add(other)

                missing_ids = payment_partner_ids - existing_ids

                if missing_ids:
                    users_res = requests.get(
                        f"{supabase_url}/rest/v1/users",
                        headers={
                            "apikey": supabase_key,
                            "Authorization": f"Bearer {supabase_key}",
                        },
                        params={
                            "id": f"in.({','.join(missing_ids)})",
                            "select": "id,username,email,profile_pic_url,is_premium",
                        }
                    )

                    if users_res.status_code == 200:
                        for u in users_res.json():
                            conversations.append({
                                "id": str(u.get('id')),
                                "username": u.get('username'),
                                "email": u.get('email'),
                                "profile_pic_url": u.get('profile_pic_url'),
                                "is_premium": bool(u.get('is_premium', False)),
                                "message_content": None,
                                "media_content": None,
                                "last_msg_time": None,
                                "sender_id": None,
                                "is_read": True,
                                "unread_count": 0,
                                "is_other_typing": False,
                                "other_typing_text": None,
                            })
                    else:
                        logging.warning(f"Fetching payment-only users failed: {users_res.text}")
            else:
                logging.warning(f"Fetching all payments failed: {all_pay_res.text}")

        except Exception as missing_conv_err:
            logging.warning(f"Payment-only conversation lookup failed: {missing_conv_err}")

        # ── 2. Decrypt + format basic conversation data ─────────────────────
        for conv in conversations:
            conv['is_other_typing'] = bool(conv.get('is_other_typing', False))
            conv['is_read'] = bool(conv.get('is_read', False))
            conv['is_premium'] = bool(conv.get('is_premium', False))
            
            if not current_user_premium:
                conv['other_typing_text'] = None
                
            if conv.get('message_content') and fernet:
                try:
                    conv['message_content'] = fernet.decrypt(
                        conv['message_content'].encode()
                    ).decode()
                except Exception:
                    pass  # Ignore decryption errors (fallback to raw text if needed)

        # ── 3. Pull latest payment per conversation and patch if more recent 
        try:
            # We don't need Content-Type for GET requests
            pay_headers = {
                "apikey": supabase_key,
                "Authorization": f"Bearer {supabase_key}",
            }
            
            for conv in conversations:
                other_id = conv.get('id')
                if not other_id:
                    continue
                    
                try:
                    pay_res = requests.get(
                        f"{supabase_url}/rest/v1/payments",
                        headers=pay_headers,
                        params={
                            "or": f"(and(payer_id.eq.{user_id},recipient_id.eq.{other_id}),and(payer_id.eq.{other_id},recipient_id.eq.{user_id}))",
                            "status": "eq.success",
                            "select": "amount,payer_id,created_at",
                            "order": "created_at.desc",
                            "limit": "1",
                        }
                    )
                    
                    if pay_res.status_code == 200 and pay_res.json():
                        payment = pay_res.json()[0]
                        pay_time = parse_supabase_ts(payment['created_at'])
                        
                        last_msg_time = conv.get('last_msg_time')
                        msg_time = parse_supabase_ts(last_msg_time) if last_msg_time else None

                        # If payment is newer than the last text message, overwrite preview
                        if msg_time is None or pay_time >= msg_time:
                            is_me = str(payment['payer_id']) == str(user_id)
                            amount = payment['amount']
                            
                            conv['message_content'] = (
                                f"You Sent ₦{amount}" if is_me
                                else f"You Received • ₦{amount}"
                            )
                            # Pre-format time for Flutter display
                            conv['last_msg_time'] = pay_time.strftime('%H:%M')
                            conv['_sort_ts'] = pay_time
                        else:
                            conv['_sort_ts'] = msg_time
                            
                except Exception as conv_pay_err:
                    logging.warning(f"Payment patch failed for conv {other_id}: {conv_pay_err}")
                    
        except Exception as pay_err:
            logging.warning(f"Payment preview block failed: {pay_err}")

        # ── 4. Format last_msg_time for convs NOT patched by payment ────────
        for conv in conversations:
            raw_time = conv.get('last_msg_time')
            if raw_time:
                # If it's already HH:MM (patched by block 3), skip parsing!
                if isinstance(raw_time, str) and len(raw_time) <= 5 and ':' in raw_time:
                    continue 

                try:
                    dt = parse_supabase_ts(raw_time)
                    conv.setdefault('_sort_ts', dt)
                    conv['last_msg_time'] = dt.strftime('%H:%M')
                except Exception as parse_err:
                    logging.warning(f"Failed to parse time {raw_time}: {parse_err}")
                    pass  # Leave as is if parsing fails
            else:
                conv.setdefault('_sort_ts', None)
        conversations.sort(
            key=lambda c: c.get('_sort_ts') or datetime.min.replace(tzinfo=timezone.utc),
            reverse=True,
        )
        for conv in conversations:
            conv.pop('_sort_ts', None)

        # ── 5. Return Final Payload ─────────────────────────────────────────
        return jsonify({
            "status": "success",
            "conversations": conversations,
            "current_user_is_premium": current_user_premium
        }), 200

    except Exception as e:
        logging.error(f"Get conversations error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route('/api/get-upload-url', methods=['POST'])
@jwt_required()
def get_upload_url():
    data = request.get_json(silent=True) or {}
    filename  = data.get('filename')
    mime_type = data.get('mime_type')
    user_id   = get_jwt_identity()
    if not filename or not mime_type:
        return jsonify({'success': False, 'message': 'filename and mime_type required'}), 400

    storage_path = f"posts/{user_id}/{filename}"
    try:
        signed_url = eventlet.tpool.execute(
            r2.generate_presigned_url,
            'put_object',
            Params={
                'Bucket': os.getenv('R2_BUCKET_NAME'),
                'Key': storage_path,
                'ContentType': mime_type,
            },
            ExpiresIn=900,
        )
        public_url = f"{os.getenv('R2_PUBLIC_URL_BASE')}/{storage_path}"
        return jsonify({
            'success':    True,
            'signed_url': signed_url,
            'public_url': public_url,
            'path':       storage_path,
        }), 200
    except Exception as e:
        logging.error(f"get_upload_url error: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500
        
@app.route('/api/messages/<string:user_id>/<string:other_id>', methods=['GET'])
@jwt_required()
def get_private_messages(user_id, other_id):
    if str(user_id) != get_jwt_identity():
        return jsonify({"status": "error", "message": "Unauthorized action"}), 403

    mark_read = request.args.get('mark_read', 'true').lower() == 'true'

    try:
        # ✨ HTTPS FIREWALL BYPASS: Call the Mega-Function ✨
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/rpc/get_private_chat_data"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json"
        }

        payload = {
            "p_user_id": user_id,
            "p_other_id": other_id,
            "p_mark_read": mark_read
        }

        response = _sb.post(url, headers=headers, json=payload, timeout=_SB_TIMEOUT)

        if response.status_code != 200:
            logging.error(f"Supabase RPC error: {response.text}")
            return jsonify({"status": "error", "message": "Database error"}), 500

        data = response.json()
        messages = data.get('messages', [])

        # Decrypt messages using your Fernet key locally in Python
        for msg in messages:
            # Format timestamp to match what Flutter expects
            if msg.get('sent_at'):
                try:
                    # Parse standard Postgres ISO timestamp and strip for Flutter
                    dt = parse_supabase_ts(msg['sent_at'])
                    msg['sent_at'] = dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    pass

            if msg.get('message_content') and fernet:
                try:
                    msg['message_content'] = fernet.decrypt(msg['message_content'].encode()).decode()
                except:
                    pass  # Old unencrypted message or invalid

            # Decrypt replied_to_text
            if msg.get('replied_to_text') and fernet:
                try:
                    msg['replied_to_text'] = fernet.decrypt(msg['replied_to_text'].encode()).decode()
                except:
                    pass

        # ---- Pull payment history between these two users from `payments` ----
        # Plain REST query against the payments table (same pattern as
        # initiate_payout / check_payment elsewhere in this file).
        # No RPC editing needed — payments is a normal Supabase table.
        try:
            pay_headers = {
                "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
                "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
            }
            pay_res = _sb.get(
                f"{os.getenv('SUPABASE_URL')}/rest/v1/payments",
                headers=pay_headers,
                timeout=_SB_TIMEOUT,
                params={
                    "or": f"(and(payer_id.eq.{user_id},recipient_id.eq.{other_id}),and(payer_id.eq.{other_id},recipient_id.eq.{user_id}))",
                    "select": "id,reference,payer_id,recipient_id,amount,status,concluded,is_accepted,created_at",
                    "order": "created_at.asc"
                }
            )
            if pay_res.status_code == 200:
                for p in pay_res.json():
                    sent_at = p.get('created_at')
                    if sent_at:
                        try:
                            sent_at = parse_supabase_ts(sent_at).strftime('%Y-%m-%d %H:%M:%S')
                        except Exception:
                            pass
                    messages.append({
                        "id": f"payment_{p['reference']}",
                        "type": "payment",
                        "sender_id": str(p['payer_id']),
                        "reference": p['reference'],
                        "amount": p['amount'],
                        "status": p['status'],
                        "is_accepted": p.get('is_accepted', False),
                        "concluded": p.get('concluded', False), 
                        "sent_at": sent_at,
                        "is_read": True,
                    })
            else:
                logging.error(f"Failed to fetch payments for chat: {pay_res.text}")
        except Exception as pay_err:
            logging.error(f"Payment history merge error: {pay_err}")

        # Re-sort everything chronologically now that payments are mixed in
        messages.sort(key=lambda m: m.get('sent_at') or '')

        # Return the perfectly formatted payload to Flutter
        return jsonify({
            "status": "success",
            "messages": messages,
            "is_other_user_typing": data.get('is_other_user_typing', False),
            "other_typing_text": data.get('other_typing_text'),
            "is_stealth_enabled": data.get('is_stealth_enabled', False)
        }), 200

    except Exception as e:
        logging.error(f"Get messages error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

def is_premium_user(conn, user_id):
    """Check if user is premium via HTTPS Firewall Bypass"""
    try:
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/users"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
        }

        # This is the HTTPS version of "SELECT is_premium FROM users WHERE id = %s"
        params = {
            "id": f"eq.{user_id}",
            "select": "is_premium"
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json()
            if data and len(data) > 0:
                return bool(data[0].get('is_premium', False))

        return False

    except Exception as e:
        logging.error(f"Premium check error: {e}")
        return False

@app.route("/api/send_message", methods=["POST"])
@jwt_required()
def api_send_message():
    data = request.get_json(silent=True) or {}

    sender_id = data.get("sender_id")
    receiver_id = data.get("receiver_id")
    message_content = str(data.get("message") or data.get("message_content", "")).strip()
    # Accept the old key too, so older app builds keep working.
    reply_to_msg_id = data.get("reply_to_msg_id") or data.get("replied_to_id")
    media_content = data.get("media_content") or data.get("media_url")

    if str(sender_id) != str(get_jwt_identity()):
        return jsonify({"status": "error", "message": "Unauthorized action"}), 403

    if not reply_to_msg_id or str(reply_to_msg_id).lower() == 'null':
        reply_to_msg_id = None
    else:
        try:
            reply_to_msg_id = int(reply_to_msg_id)
        except:
            reply_to_msg_id = None

    if not sender_id or not receiver_id:
        return jsonify({"status": "error", "message": "Missing IDs"}), 400

    encrypted_content = None
    if message_content and fernet:
        encrypted_content = fernet.encrypt(message_content.encode()).decode()

    try:
        # ---- Insert message via RPC ----
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/rpc/send_message_and_get_meta"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json"
        }
        payload = {
            "p_sender_id": sender_id,
            "p_receiver_id": receiver_id,
            "p_message_content": encrypted_content,
            "p_media_content": media_content,
            "p_reply_to_msg_id": reply_to_msg_id
        }
        response = _sb.post(url, headers=headers, json=payload, timeout=_SB_TIMEOUT)

        if response.status_code != 200:
            logging.error(f"Supabase Send RPC error: {response.text}")
            return jsonify({"status": "error", "message": "Failed to save message"}), 500

        db_data = response.json()
        is_stealth = db_data.get('is_stealth', False)
        sender_name = db_data.get('sender_name', 'Someone')
        target_token = db_data.get('fcm_token')
        message_id = db_data.get('message_id')  # <-- now comes straight from the RPC, no extra query

        # ---- Sender profile pic (cached; warmed when the socket connects) ----
        sender_pic_url = _get_profile_pic(sender_id)

        # ---- WebSocket delivery ----
        receiver_id_str = str(receiver_id)
        if receiver_id_str in active_users:
            try:
                socketio.emit('receive_message', {
                    "id": message_id,
                    "sender_id": str(sender_id),
                    "sender_name": sender_name,
                    "sender_pic_url": sender_pic_url or "",
                    "message": message_content,
                    "media_content": media_content,
                    "reply_to_msg_id": reply_to_msg_id,
                    "is_stealth": is_stealth
                }, to=active_users[receiver_id_str])

                sender_sid = active_users.get(str(sender_id))
                if sender_sid:
                    socketio.emit('message_sent_success', {
                        "id": message_id
                    }, to=sender_sid)

                print(f"Message delivered via WebSocket to {receiver_id}")
            except Exception as e:
                logging.error(f"WebSocket delivery failed: {e}")

        # ---- Push notification (backgrounded — does NOT block the response) ----
        if target_token:
            def _send_push():
                try:
                    if is_stealth:
                        display_body = "🕶️ Ultra Stealth Message received"
                    else:
                        display_body = message_content if message_content else "📎 Sent an attachment"
                        if reply_to_msg_id:
                            display_body = f"↩️ Replying: {display_body}"

                    messaging.send(messaging.Message(
                        notification=messaging.Notification(
                            title=f"New message from {sender_name}",
                            body=display_body,
                            image=sender_pic_url or None,
                        ),
                        android=messaging.AndroidConfig(
                            priority='high',
                            notification=messaging.AndroidNotification(
                                image=sender_pic_url or None,
                                priority='high',
                                channel_id='chat_messages',
                            ),
                        ),
                        data={
                            "type": "chat_message",
                            "sender_id": str(sender_id),
                            "sender_name": sender_name,
                            "sender_pic_url": sender_pic_url or "",
                            "is_stealth": "true" if is_stealth else "false"
                        },
                        token=target_token,
                    ))
                except Exception as e:
                    logging.error(f"Firebase push error: {e}")

            socketio.start_background_task(_send_push)

        return jsonify({
            "status": "success",
            "message": "Message sent",
            "is_stealth": is_stealth,
            "message_id": message_id
        }), 201

    except Exception as e:
        logging.error(f"Send message error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route("/api/request-password-reset", methods=["POST"])
@limiter.limit("4 per hour")
def request_password_reset():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower()  # Always normalize emails!

    if not email:
        return jsonify({"status": "error", "message": "Email is required"}), 400

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url_users = f"{os.getenv('SUPABASE_URL')}/rest/v1/users"
        # Removed url_resets completely!

        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json"
        }

        # 1. Fetch user by email to ensure they exist AND grab their rate limit stats
        user_res = requests.get(url_users, headers=headers, params={
            "email": f"eq.{email}",
            "select": "id, reset_count, reset_window_start"
        })

        if user_res.status_code != 200:
            logging.error(f"Supabase GET user error: {user_res.text}")
            return jsonify({"status": "error", "message": "Database error"}), 500

        user_data_list = user_res.json()
        if not user_data_list or len(user_data_list) == 0:
            return jsonify({"status": "error", "message": "Email not found"}), 404

        user_data = user_data_list[0]

        now = datetime.now(timezone.utc)
        window_start_str = user_data.get("reset_window_start")
        reset_count = user_data.get("reset_count") or 0  # Default to 0 if None

        # 2. Rate Limit Logic (Max 3 per hour)
        if window_start_str:
            # ✨ THE FIX: Strip off the fractional seconds AND the 'Z' so Python doesn't crash!
            clean_window_str = str(window_start_str).split('.')[0].replace("Z", "")
            window_time = datetime.fromisoformat(clean_window_str)

            # Ensure window_time is timezone-aware
            if window_time.tzinfo is None:
                window_time = window_time.replace(tzinfo=timezone.utc)

            if (now - window_time) < timedelta(hours=1):
                if reset_count >= 3:
                    return jsonify({"status": "error", "message": "Too many requests. Try again later."}), 429
                new_count = reset_count + 1
                new_window = window_start_str # Keep the existing window string
            else:
                # Window expired (>1 hour ago), reset the counter
                new_count = 1
                new_window = now.isoformat()
        else:
            # First time ever requesting a reset
            new_count = 1
            new_window = now.isoformat()

        # 3. Generate reset code and set expiry (10 minutes)
        reset_code = generate_reset_code()  # Keep your existing generator
        expiry_time = (now + timedelta(minutes=10)).isoformat()

        # 4. UPDATE the user's row with the new code AND the new rate limit stats
        patch_payload = {
            "reset_code": reset_code,
            "reset_code_expires": expiry_time,
            "reset_count": new_count,
            "reset_window_start": new_window
        }
        update_res = requests.patch(url_users, headers=headers, params={"email": f"eq.{email}"}, json=patch_payload)

        if update_res.status_code not in (200, 204):
            logging.error(f"Supabase PATCH user error: {update_res.text}")
            return jsonify({"status": "error", "message": "Failed to update reset code"}), 500

        # 5. Actually send the email!
        send_reset_email(email, reset_code)

        return jsonify({"status": "success", "message": f"A reset code has been sent to {email}"}), 200

    except Exception as e:
        logging.error(f"Request password reset error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route("/api/verify-reset-otp", methods=["POST"])
def verify_reset_otp():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower() # Normalize for safety
    otp_code = data.get("otp_code", "").strip()

    if not email or not otp_code:
        return jsonify({"error": "Email and OTP are required"}), 400

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url_users = f"{os.getenv('SUPABASE_URL')}/rest/v1/users"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json"
        }

        # 1. Fetch user's reset code and expiry
        params = {
            "email": f"eq.{email}",
            "select": "reset_code,reset_code_expires"
        }
        res = requests.get(url_users, headers=headers, params=params)

        if res.status_code != 200:
            logging.error(f"Supabase GET user error: {res.text}")
            return jsonify({"status": "error", "message": "Database error"}), 500

        user_data = res.json()
        if not user_data or len(user_data) == 0:
            return jsonify({"error": "Invalid email"}), 400

        row = user_data[0]
        db_reset_code = row.get("reset_code")
        db_reset_code_expires = row.get("reset_code_expires")

        # 2. Check if OTP matches
        if not db_reset_code or db_reset_code != otp_code:
            return jsonify({"error": "Invalid code"}), 400

        if db_reset_code_expires:
            # ✨ THE FIX: Slice the first 19 chars (YYYY-MM-DDTHH:MM:SS) to ignore crashing milliseconds
            base_time_str = db_reset_code_expires[:19]
            expiry_time = datetime.fromisoformat(base_time_str)

            # Force it to be UTC-aware
            if expiry_time.tzinfo is None:
                expiry_time = expiry_time.replace(tzinfo=timezone.utc)

            # If expired, wipe it from the database (PATCH) and return the error
            if datetime.now(timezone.utc) > expiry_time:
                patch_payload = {
                    "reset_code": None,
                    "reset_code_expires": None
                }
                # Fire the HTTPS update quietly
                requests.patch(url_users, headers=headers, params=params, json=patch_payload)
                return jsonify({"error": "Code expired"}), 400
        else:
             return jsonify({"error": "Invalid code"}), 400

        # 4. Success!
        return jsonify({"message": "OTP verified successfully"}), 200

    except Exception as e:
        logging.error(f"Verify OTP error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route("/api/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip().lower() # Normalized for safety
    otp_code = data.get("otp_code", "").strip()
    new_password = data.get("new_password", "").strip()

    # Password length validation
    if len(new_password) < 8 or len(new_password) > 128:
        return jsonify({"error": "Password must be 8-128 characters"}), 400

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url_users = f"{os.getenv('SUPABASE_URL')}/rest/v1/users"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json"
        }

        # 1. Fetch user's reset code and expiry
        params = {
            "email": f"eq.{email}",
            "select": "reset_code,reset_code_expires"
        }
        res = requests.get(url_users, headers=headers, params=params)

        if res.status_code != 200:
            logging.error(f"Supabase GET user error: {res.text}")
            return jsonify({"status": "error", "message": "Database error"}), 500

        user_data = res.json()
        if not user_data or len(user_data) == 0:
            return jsonify({"error": "Invalid email or OTP"}), 400

        row = user_data[0]
        db_reset_code = row.get("reset_code")
        db_reset_code_expires = row.get("reset_code_expires")

        # 2. Validate OTP Match
        if not db_reset_code or db_reset_code != otp_code:
            return jsonify({"error": "Invalid email or OTP"}), 400

        if db_reset_code_expires:
            # ✨ THE FIX: Slice the first 19 chars (YYYY-MM-DDTHH:MM:SS) to ignore crashing milliseconds
            base_time_str = db_reset_code_expires[:19]
            expiry_time = datetime.fromisoformat(base_time_str)

            # Force it to be UTC-aware
            if expiry_time.tzinfo is None:
                expiry_time = expiry_time.replace(tzinfo=timezone.utc)

            # Compare using UTC timezone to match the server strictly
            if datetime.now(timezone.utc) > expiry_time:
                return jsonify({"error": "OTP expired"}), 400
        else:
            return jsonify({"error": "No OTP request found"}), 400

        # 4. Hash the new password
        hashed_password = hash_password(new_password)

        # 5. Update user's password and wipe the reset fields
        patch_payload = {
            "password": hashed_password,
            "reset_code": None,
            "reset_code_expires": None
        }
        update_res = requests.patch(url_users, headers=headers, params=params, json=patch_payload)

        if update_res.status_code not in (200, 204):
            logging.error(f"Supabase PATCH user error: {update_res.text}")
            return jsonify({"status": "error", "message": "Failed to update password"}), 500

        logging.info(f"Password reset successful for email: {email}")
        return jsonify({"message": "Password has been reset successfully"}), 200

    except Exception as e:
        logging.error(f"Reset password error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route('/api/verify-user', methods=['POST'])
def verify_user():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    user_id = data.get('user_id')
    username = data.get('username')

    if not user_id or not username:
        return jsonify({"status": "error", "message": "Missing user_id or username"}), 400

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/users"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
        }

        # This is the HTTPS equivalent of "SELECT id FROM users WHERE id = %s AND username = %s"
        params = {
            "id": f"eq.{user_id}",
            "username": f"eq.{username}",
            "select": "id"
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            user_data = response.json()
            # If the list has data, the user exists!
            if user_data and len(user_data) > 0:
                return jsonify({"status": "valid"}), 200
            else:
                return jsonify({"status": "invalid", "message": "User data mismatch"}), 401
        else:
            logging.error(f"Supabase verify user error: {response.text}")
            return jsonify({"status": "error", "message": "Database error"}), 500

    except Exception as e:
        logging.error(f"Verify user error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route("/api/search_user", methods=["POST"])
@jwt_required()
def search_user():
    data = request.get_json(silent=True) or {}
    # 1. Clean the input
    username_query = str(data.get("username", "")).strip()

    if not username_query:
        return jsonify({"status": "success", "users": []}), 200

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/users"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
        }

        # 2. Use Supabase 'ilike' (case-insensitive) filter
        # The syntax 'username_query*' acts as the wildcard (LIKE username%)
        params = {
            "username": f"ilike.{username_query}*",
            "select": "id,username,email,is_premium",
            "order": "username.asc",
            "limit": "10"
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code != 200:
            logging.error(f"Supabase search error: {response.text}")
            return jsonify({"status": "error", "message": "Database error"}), 500

        rows = response.json()

        # 3. Format the results for Flutter
        results = [
            {
                "id": r.get("id"),
                "username": r.get("username"),
                "email": r.get("email"),
                "is_premium": bool(r.get("is_premium"))
            } for r in rows
        ]

        return jsonify({"status": "success", "users": results}), 200

    except Exception as e:
        logging.error(f"Search user error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route("/api/update_profile_pic", methods=["POST", "OPTIONS"])
@jwt_required()
def api_update_profile_pic():
    # 1. Handle Pre-flight for Flutter Web
    if request.method == "OPTIONS":
        return jsonify({"status": "ok"}), 200

    data = request.get_json(silent=True) or {}

    # Cast to string because your DB schema uses varchar(36)
    user_id = str(data.get("user_id", ""))
    profile_pic_url = data.get("profile_pic_url")

    # 2. Security Check: Force both sides to string to avoid type mismatch
    jwt_id = str(get_jwt_identity())

    if user_id != jwt_id:
        logging.warning(f"Unauthorized update attempt: {user_id} tried to update as {jwt_id}")
        return jsonify({"status": "error", "message": "Unauthorized action"}), 403

    if not user_id or user_id == "None":
        return jsonify({"status": "error", "message": "Missing valid user ID"}), 400

    # Handle removal of pic
    if profile_pic_url is None:
        profile_pic_url = ""

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/users"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json",
            "Prefer": "return=representation"  # Asks Supabase to return the updated row
        }

        params = {
            "id": f"eq.{user_id}"
        }

        payload = {
            "profile_pic_url": profile_pic_url
        }

        response = requests.patch(url, headers=headers, params=params, json=payload)

        if response.status_code not in (200, 204):
            logging.error(f"Supabase update profile pic error: {response.text}")
            return jsonify({"status": "error", "message": "Internal server error"}), 500

        # Check if any row was actually changed (mimicking cursor.rowcount == 0)
        if response.status_code == 200 and len(response.json()) == 0:
            return jsonify({"status": "error", "message": "User not found in database"}), 404

        return jsonify({
            "status": "success",
            "message": "Profile picture updated successfully",
            "profile_pic_url": profile_pic_url
        }), 200

    except Exception as e:
        logging.error(f"Update profile pic error: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

def _alert_sb(path):
    return f"{os.getenv('SUPABASE_URL')}/rest/v1/{path}"


def _alert_valid_uuid(value):
    """True only for a canonical lowercase uuid string (safe to use in filters)."""
    try:
        s = str(value).lower()
        return str(uuid.UUID(s)) == s
    except (ValueError, AttributeError, TypeError):
        return False

def _alert_contact_ids(user_id):
    """Everyone with an ACCEPTED mutual_contacts row to this user, either direction."""
    res = requests.get(
        _alert_sb('mutual_contacts'),
        headers=_supabase_headers(),
        params={
            'status': 'eq.true',
            'or': f'(sender.eq.{user_id},accepter.eq.{user_id})',
            'select': 'sender,accepter',
        },
        timeout=_SB_TIMEOUT,
    )
    if res.status_code != 200:
        raise RuntimeError(f"contacts lookup failed: {res.text}")
    ids = set()
    for row in res.json():
        ids.add(row['accepter'] if row['sender'] == user_id else row['sender'])
    return list(ids)


# ═══════════════════════════════════════════════════════════════════════════
#  SAFELENS CIRCLE (trusted contacts)
#
#  Uses the mutual_contacts table (status: false = pending, true = accepted).
#
#    GET  /api/circle/search?q=   find users by username
#    POST /api/circle/request     send a request (or auto-accept)
#    GET  /api/circle             my circle + incoming + outgoing
#    POST /api/circle/respond     accept / decline a request
#    POST /api/circle/remove      remove a contact / cancel a request
#
#  Alerts are stored in the messages table (one row per contact) and are
#  added separately.
# ═══════════════════════════════════════════════════════════════════════════


_CIRCLE_MAX_PENDING = 30


def _circle_bad(msg, code=400, **extra):
    body = {"success": False, "status": "error", "message": msg}
    body.update(extra)
    return jsonify(body), code


def _circle_ok(**data):
    body = {"success": True, "status": "success"}
    body.update(data)
    return jsonify(body), 200


def _circle_now():
    return datetime.now(timezone.utc).isoformat()


def _alert_parse_ts(s):
    """Parse a Supabase timestamp, whatever fractional-second length it has."""
    s = str(s).replace('Z', '+00:00')
    if '.' in s:
        head, tail = s.split('.', 1)
        digits = ''
        for ch in tail:
            if ch.isdigit():
                digits += ch
            else:
                break
        s = f"{head}.{digits[:6].ljust(6, '0')}{tail[len(digits):]}"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _circle_pair_row(a, b):
    res = requests.get(
        _alert_sb('mutual_contacts'),
        headers=_supabase_headers(),
        params={
            'or': f'(and(sender.eq.{a},accepter.eq.{b}),and(sender.eq.{b},accepter.eq.{a}))',
            'select': 'id,sender,accepter,status',
            'limit': '1',
        },
        timeout=_SB_TIMEOUT,
    )
    if res.status_code != 200:
        raise RuntimeError(f"pair lookup failed: {res.text}")
    rows = res.json()
    return rows[0] if rows else None


def _circle_link_by_id(link_id):
    res = requests.get(
        _alert_sb('mutual_contacts'),
        headers=_supabase_headers(),
        params={'id': f'eq.{link_id}', 'select': 'id,sender,accepter,status', 'limit': '1'},
        timeout=_SB_TIMEOUT,
    )
    if res.status_code != 200:
        raise RuntimeError(f"link lookup failed: {res.text}")
    rows = res.json()
    return rows[0] if rows else None


def _circle_usernames(ids):
    ids = [i for i in set(ids) if _alert_valid_uuid(i)]
    if not ids:
        return {}
    quoted = ','.join(f'"{i}"' for i in ids)
    res = requests.get(
        _alert_sb('users'),
        headers=_supabase_headers(),
        params={'id': f'in.({quoted})', 'select': 'id,username'},
        timeout=_SB_TIMEOUT,
    )
    if res.status_code != 200:
        return {}
    return {r['id']: (r.get('username') or 'Someone') for r in res.json()}


def _circle_push(user_id, title, body, data):
    """Fire-and-forget push to one user. Never raises."""
    def run():
        try:
            u = requests.get(
                _alert_sb('users'),
                headers=_supabase_headers(),
                params={'id': f'eq.{user_id}', 'select': 'fcm_token'},
                timeout=_SB_TIMEOUT,
            )
            rows = u.json() if u.status_code == 200 else []
            token = rows[0].get('fcm_token') if rows else None
            if not token:
                return
            messaging.send(messaging.Message(
                notification=messaging.Notification(title=title, body=body),
                android=messaging.AndroidConfig(priority='high'),
                data={k: str(v) for k, v in data.items()},
                token=token,
            ))
        except Exception as e:
            logging.error(f"circle push failed: {e}")
    socketio.start_background_task(run)


# ───────────────────────────── CIRCLE ─────────────────────────────

@app.route('/api/circle/search', methods=['GET'])
@limiter.limit("40 per minute")
@jwt_required()
def circle_search():
    me = get_jwt_identity()
    raw = (request.args.get('q') or '').strip()
    q = ''.join(ch for ch in raw if ch.isalnum() or ch in '._-')[:30]
    if len(q) < 3:
        return _circle_bad("Type at least 3 characters.")
    try:
        res = requests.get(
            _alert_sb('users'),
            headers=_supabase_headers(),
            params={'username': f'ilike.{q}*', 'id': f'neq.{me}',
                    'select': 'id,username', 'order': 'username.asc', 'limit': '10'},
            timeout=_SB_TIMEOUT,
        )
        if res.status_code != 200:
            return _circle_bad("Search failed.", 500)
        users = res.json()
        if not users:
            return _circle_ok(results=[])

        rel = requests.get(
            _alert_sb('mutual_contacts'),
            headers=_supabase_headers(),
            params={'or': f'(sender.eq.{me},accepter.eq.{me})',
                    'select': 'id,sender,accepter,status'},
            timeout=_SB_TIMEOUT,
        )
        by_other = {}
        if rel.status_code == 200:
            for r in rel.json():
                by_other[r['accepter'] if r['sender'] == me else r['sender']] = r

        out = []
        for u in users:
            r = by_other.get(u['id'])
            if not r:
                relation = 'none'
            elif r['status']:
                relation = 'accepted'
            elif r['sender'] == me:
                relation = 'pending_sent'
            else:
                relation = 'pending_received'
            out.append({'user_id': u['id'], 'username': u['username'],
                        'relation': relation, 'link_id': r['id'] if r else None})
        return _circle_ok(results=out)
    except Exception as e:
        logging.error(f"circle_search error: {e}")
        return _circle_bad("Server error.", 500)


@app.route('/api/circle/request', methods=['POST'])
@limiter.limit("20 per hour")
@jwt_required()
def circle_request():
    me = get_jwt_identity()
    target = str((request.get_json(silent=True) or {}).get('user_id', '')).lower()
    if not _alert_valid_uuid(target):
        return _circle_bad("Invalid user.")
    if target == me:
        return _circle_bad("You can't add yourself.")
    try:
        t = requests.get(
            _alert_sb('users'), headers=_supabase_headers(),
            params={'id': f'eq.{target}', 'select': 'id', 'limit': '1'},
            timeout=_SB_TIMEOUT,
        )
        if t.status_code != 200 or not t.json():
            return _circle_bad("User not found.", 404)

        my_name = _circle_usernames([me]).get(me, 'Someone')
        existing = _circle_pair_row(me, target)
        if existing:
            if existing['status']:
                return _circle_ok(relation='accepted', link_id=existing['id'],
                                  message="Already in your circle.")
            if existing['sender'] == me:
                return _circle_ok(relation='pending_sent', link_id=existing['id'],
                                  message="Request already sent.")
            # They already asked you, so both want it: accept.
            requests.patch(
                _alert_sb('mutual_contacts'), headers=_supabase_headers(),
                params={'id': f"eq.{existing['id']}", 'status': 'eq.false'},
                json={'status': True, 'responded_at': _circle_now()},
                timeout=_SB_TIMEOUT,
            )
            _circle_push(target, f"{my_name} accepted your request",
                         "You can now see each other's safety alerts.",
                         {'type': 'circle_accepted', 'user_id': me})
            return _circle_ok(relation='accepted', link_id=existing['id'])

        cnt = requests.get(
            _alert_sb('mutual_contacts'),
            headers={**_supabase_headers(), 'Prefer': 'count=exact'},
            params={'sender': f'eq.{me}', 'status': 'eq.false', 'select': 'id', 'limit': '1'},
            timeout=_SB_TIMEOUT,
        )
        try:
            pending = int(cnt.headers.get('Content-Range', '0/0').split('/')[-1])
        except ValueError:
            pending = 0
        if pending >= _CIRCLE_MAX_PENDING:
            return _circle_bad("You have too many pending requests. Wait for some to be answered.", 429)

        ins = requests.post(
            _alert_sb('mutual_contacts'),
            headers={**_supabase_headers(), 'Prefer': 'return=representation'},
            json={'sender': me, 'accepter': target, 'status': False},
            timeout=_SB_TIMEOUT,
        )
        if ins.status_code == 409:  # both sides added each other at the same moment
            again = _circle_pair_row(me, target)
            if again:
                return _circle_ok(relation='pending_sent', link_id=again['id'])
        if ins.status_code not in (200, 201):
            logging.error(f"circle insert failed: {ins.text}")
            return _circle_bad("Could not send request.", 500)

        row = ins.json()[0]
        _circle_push(target, f"{my_name} wants to add you",
                     "Accept to see each other's safety alerts.",
                     {'type': 'circle_request', 'user_id': me, 'link_id': row['id']})
        return _circle_ok(relation='pending_sent', link_id=row['id'])
    except Exception as e:
        logging.error(f"circle_request error: {e}")
        return _circle_bad("Server error.", 500)


@app.route('/api/circle', methods=['GET'])
@jwt_required()
def circle_list():
    me = get_jwt_identity()
    try:
        res = requests.get(
            _alert_sb('mutual_contacts'),
            headers=_supabase_headers(),
            params={'or': f'(sender.eq.{me},accepter.eq.{me})',
                    'select': 'id,sender,accepter,status,created_at,responded_at',
                    'order': 'created_at.desc'},
            timeout=_SB_TIMEOUT,
        )
        if res.status_code != 200:
            return _circle_bad("Could not load your circle.", 500)
        rows = res.json()
        others = [r['accepter'] if r['sender'] == me else r['sender'] for r in rows]
        names = _circle_usernames(others)

        circle, incoming, outgoing = [], [], []
        for r in rows:
            other = r['accepter'] if r['sender'] == me else r['sender']
            item = {'link_id': r['id'], 'user_id': other,
                    'username': names.get(other, 'Someone'),
                    'since': r.get('responded_at') or r.get('created_at')}
            if r['status']:
                circle.append(item)
            elif r['sender'] == me:
                outgoing.append(item)
            else:
                incoming.append(item)
        return _circle_ok(circle=circle, incoming=incoming, outgoing=outgoing)
    except Exception as e:
        logging.error(f"circle_list error: {e}")
        return _circle_bad("Server error.", 500)


@app.route('/api/circle/respond', methods=['POST'])
@limiter.limit("60 per hour")
@jwt_required()
def circle_respond():
    me = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    link_id = str(data.get('link_id', '')).lower()
    accept = data.get('accept') is True
    if not _alert_valid_uuid(link_id):
        return _circle_bad("Invalid request.")
    try:
        row = _circle_link_by_id(link_id)
        if not row:
            return _circle_bad("Request not found.", 404)
        if row['accepter'] != me or row['status']:
            return _circle_bad("Nothing to respond to.", 403)

        if accept:
            requests.patch(
                _alert_sb('mutual_contacts'), headers=_supabase_headers(),
                params={'id': f'eq.{link_id}', 'status': 'eq.false'},
                json={'status': True, 'responded_at': _circle_now()},
                timeout=_SB_TIMEOUT,
            )
            my_name = _circle_usernames([me]).get(me, 'Someone')
            _circle_push(row['sender'], f"{my_name} accepted your request",
                         "You can now see each other's safety alerts.",
                         {'type': 'circle_accepted', 'user_id': me})
            return _circle_ok(relation='accepted', link_id=link_id)

        requests.delete(
            _alert_sb('mutual_contacts'), headers=_supabase_headers(),
            params={'id': f'eq.{link_id}', 'status': 'eq.false'},
            timeout=_SB_TIMEOUT,
        )
        return _circle_ok(relation='none')
    except Exception as e:
        logging.error(f"circle_respond error: {e}")
        return _circle_bad("Server error.", 500)


@app.route('/api/circle/remove', methods=['POST'])
@limiter.limit("60 per hour")
@jwt_required()
def circle_remove():
    me = get_jwt_identity()
    link_id = str((request.get_json(silent=True) or {}).get('link_id', '')).lower()
    if not _alert_valid_uuid(link_id):
        return _circle_bad("Invalid request.")
    try:
        row = _circle_link_by_id(link_id)
        if not row or me not in (row['sender'], row['accepter']):
            return _circle_bad("Not found.", 404)
        # Silent on purpose: removing someone sends no notification.
        requests.delete(
            _alert_sb('mutual_contacts'), headers=_supabase_headers(),
            params={'id': f'eq.{link_id}'}, timeout=_SB_TIMEOUT,
        )
        return _circle_ok()
    except Exception as e:
        logging.error(f"circle_remove error: {e}")
        return _circle_bad("Server error.", 500)


# ═══════════════════════════════════════════════════════════════════════════
#  SAFELENS ALERTS  -  stored in the `messages` table
#
#  Paste at the BOTTOM of routes.py (below the circle routes).
#  No new imports and no new environment variables.
#  Run messages_alert_columns.sql first.
#
#  Uses what routes.py already has: fernet, _sb, r2, _supabase_headers,
#  _SB_TIMEOUT, socketio, eventlet, messaging, R2_BUCKET_NAME and
#  R2_PUBLIC_URL_BASE, plus the circle helpers (_alert_sb, _alert_valid_uuid,
#  _alert_contact_ids, _alert_parse_ts, _circle_ok, _circle_bad,
#  _circle_usernames).
#
#  How it works
#    - The phone sends an alert with its own fix (or none).
#    - If it has no fix, the server falls back to the last location saved on
#      the user's row (the 2-minute checks).
#    - One messages row per accepted contact, all sharing an alert_key.
#      latitude / longitude are real columns; the rest (address, accuracy,
#      trigger...) is a small JSON inside message_content, encrypted with
#      your Fernet key like every other message.
#    - The video uploads AFTERWARDS through your existing /api/get-upload-url,
#      then /api/alert/attach-media writes its link into media_content.
#
#  Routes
#    POST /api/alert               fire an alert (finger lifted)
#    POST /api/alert/attach-media  link an uploaded clip to an alert
#    GET  /api/alerts/sent         alerts I sent
#    GET  /api/alerts/received     alerts sent to me, clustered
#    POST /api/alerts/read         mark alerts as read
# ═══════════════════════════════════════════════════════════════════════════

_ALERT_MAX_VIDEO_BYTES = 150 * 1024 * 1024


def _alert_encode(body):
    text = json.dumps(body, separators=(',', ':'))
    return fernet.encrypt(text.encode()).decode() if fernet else text


def _alert_decode(content):
    """The alert details stored in message_content, or None if this row is not an alert."""
    if not content:
        return None
    text = content
    if fernet:
        try:
            text = fernet.decrypt(content.encode()).decode()
        except Exception:
            text = content
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    return data if isinstance(data, dict) and data.get('v') == 1 else None


def _alert_view(row, info, seen):
    """One alert as the app expects it."""
    return {
        'key': row['alert_key'],
        'user_id': row['sender_id'],
        'sent_at': row['sent_at'],
        'latitude': row.get('latitude'),
        'longitude': row.get('longitude'),
        'accuracy': info.get('accuracy'),
        'address': info.get('address'),
        'fix_at': info.get('fix_at'),
        'trigger': info.get('trigger', 'screen'),
        'source': info.get('source', 'phone'),
        'spoof': bool(info.get('spoof', False)),
        'expects_video': bool(info.get('expects_video', False)),
        'media_url': row.get('media_content') or None,
        'seen': seen,
    }


def _alert_push_all(sender_id, rows, lat, lng):
    """Background: push one notification to each contact. Never raises."""
    try:
        recipients = [r['receiver_id'] for r in rows]
        if not recipients:
            return
        name = _circle_usernames([sender_id]).get(sender_id, 'Someone')
        quoted = ','.join(f'"{c}"' for c in recipients)
        t = requests.get(
            _alert_sb('users'), headers=_supabase_headers(),
            params={'id': f'in.({quoted})', 'select': 'id,fcm_token'},
            timeout=_SB_TIMEOUT,
        )
        tokens = {r['id']: r.get('fcm_token') for r in t.json()} if t.status_code == 200 else {}
        has_loc = lat is not None and lng is not None
        body = ("Their last known location was shared with you. Tap to open the map."
                if has_loc else
                "They lifted their finger, but no location was available.")
        alert_key = rows[0].get('alert_key')

        for cid in recipients:
            token = tokens.get(cid)
            if not token:
                continue
            try:
                # ANDROID gets a DATA-ONLY message (no `notification` block).
                # That is what lets the Flutter background handler draw the
                # sticky, vibrating notification itself, even when the app is
                # closed. With a `notification` block Android would draw its
                # own plain one and our code would never run.
                # iOS cannot run code for data-only pushes reliably, so it
                # keeps a normal visible alert through the apns section.
                messaging.send(messaging.Message(
                    android=messaging.AndroidConfig(
                        priority='high',
                        ttl=3600,  # an hour-old emergency push is worse than none
                    ),
                    apns=messaging.APNSConfig(
                        headers={'apns-priority': '10'},
                        payload=messaging.APNSPayload(aps=messaging.Aps(
                            alert=messaging.ApsAlert(
                                title=f"🚨 {name} may need help", body=body),
                            sound='default',
                        )),
                    ),
                    data={
                        'type': 'safety_alert',
                        'alert_key': str(alert_key),
                        'sender_id': sender_id,
                        'sender_name': name,
                        'latitude': '' if lat is None else str(lat),
                        'longitude': '' if lng is None else str(lng),
                    },
                    token=token,
                ))
            except messaging.UnregisteredError:
                try:  # dead token: clear it
                    requests.patch(
                        _alert_sb('users'), headers=_supabase_headers(),
                        params={'id': f'eq.{cid}'}, json={'fcm_token': None},
                        timeout=_SB_TIMEOUT,
                    )
                except Exception:
                    pass
            except Exception as e:
                logging.error(f"alert push to {cid} failed: {e}")
    except Exception as e:
        logging.error(f"alert push crashed: {e}")


@app.route('/api/alert', methods=['POST'])
@limiter.limit("30 per hour")
@jwt_required()
def fire_alert():
    me = get_jwt_identity()
    data = request.get_json(silent=True) or {}

    def bad(msg, code=400):
        return _circle_bad(msg, code)

    alert_key = str(data.get('alert_key', '')).lower()
    if not _alert_valid_uuid(alert_key):
        return bad("Invalid alert id")

    lat, lng = data.get('latitude'), data.get('longitude')
    if (lat is None) != (lng is None):
        return bad("Send both coordinates or neither")
    if lat is not None:
        try:
            lat, lng = float(lat), float(lng)
        except (TypeError, ValueError):
            return bad("Invalid coordinates")
        if not (-90 <= lat <= 90 and -180 <= lng <= 180):
            return bad("Coordinates out of range")

    trigger = data.get('trigger_type', 'screen')
    if trigger not in ('screen', 'volume'):
        return bad("Invalid trigger")

    try:
        accuracy = float(data['accuracy']) if data.get('accuracy') is not None else None
    except (TypeError, ValueError):
        accuracy = None

    fix_at = None
    if data.get('fix_at'):
        try:
            fix_at = _alert_parse_ts(data['fix_at']).isoformat()
        except Exception:
            fix_at = None

    address = str(data.get('address') or '').strip()[:200] or None
    source = 'phone'

    try:
        contacts = _alert_contact_ids(me)
        if not contacts:
            return _circle_ok(alert_key=alert_key, contacts=0)

        # No fix from the phone? Fall back to the last location saved on the user's row.
        if lat is None:
            u = requests.get(
                _alert_sb('users'), headers=_supabase_headers(),
                params={'id': f'eq.{me}', 'select': 'latitude,longitude', 'limit': '1'},
                timeout=_SB_TIMEOUT,
            )
            rows = u.json() if u.status_code == 200 else []
            if rows and rows[0].get('latitude') is not None and rows[0].get('longitude') is not None:
                lat, lng = float(rows[0]['latitude']), float(rows[0]['longitude'])
                source = 'last_known'
            else:
                source = 'none'

        content = _alert_encode({
            'v': 1,
            'address': address,
            'accuracy': accuracy,
            'fix_at': fix_at,
            'trigger': trigger,
            'source': source,
            'spoof': bool(data.get('suspected_spoof', False)),
            'expects_video': bool(data.get('expects_video', False)),
        })

        new_rows = [{
            'sender_id': me,
            'receiver_id': cid,
            'message_content': content,
            'latitude': lat,
            'longitude': lng,
            'alert_key': alert_key,
            'is_read': False,
        } for cid in contacts]

        res = _sb.post(
            _alert_sb('messages'),
            headers={**_supabase_headers(),
                     'Prefer': 'resolution=ignore-duplicates,return=representation'},
            params={'on_conflict': 'alert_key,receiver_id'},
            json=new_rows,
            timeout=_SB_TIMEOUT,
        )
        if res.status_code not in (200, 201):
            logging.error(f"alert insert failed: {res.status_code} {res.text}")
            return bad("Could not save alert", 500)

        inserted = res.json()
        if inserted:  # a repeat of an alert we already stored inserts nothing: no second push
            socketio.start_background_task(_alert_push_all, me, inserted, lat, lng)
        return _circle_ok(alert_key=alert_key, contacts=len(contacts), source=source)
    except Exception as e:
        logging.error(f"fire_alert error: {e}")
        return bad("Server error", 500)


@app.route('/api/alert/attach-media', methods=['POST'])
@limiter.limit("30 per hour")
@jwt_required()
def alert_attach_media():
    me = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    alert_key = str(data.get('alert_key', '')).lower()
    media_url = str(data.get('media_url', '')).strip()
    if not _alert_valid_uuid(alert_key):
        return _circle_bad("Invalid alert id")

    # The link must be exactly what /api/get-upload-url hands out for THIS user
    # and THIS alert. Nothing else can be attached.
    base = (os.getenv('R2_PUBLIC_URL_BASE') or '').rstrip('/')
    prefix = f"{base}/posts/{me}/alert-{alert_key}."
    if not base or not media_url.startswith(prefix) or media_url[len(prefix):] not in ('mp4', 'mov'):
        return _circle_bad("Invalid video link")

    key = media_url[len(base) + 1:]
    try:
        try:
            head = eventlet.tpool.execute(r2.head_object, Bucket=os.getenv('R2_BUCKET_NAME'), Key=key)
        except Exception:
            return _circle_bad("Upload not found. Please try again.")
        size = int(head.get('ContentLength', 0))
        if size <= 0 or size > _ALERT_MAX_VIDEO_BYTES:
            return _circle_bad("Video has an invalid size.")

        res = requests.patch(
            _alert_sb('messages'),
            headers={**_supabase_headers(), 'Prefer': 'return=representation'},
            params={'sender_id': f'eq.{me}', 'alert_key': f'eq.{alert_key}'},
            json={'media_content': media_url},
            timeout=_SB_TIMEOUT,
        )
        if res.status_code != 200 or not res.json():
            return _circle_bad("Alert not found.", 404)
        return _circle_ok()
    except Exception as e:
        logging.error(f"alert_attach_media error: {e}")
        return _circle_bad("Server error", 500)


@app.route('/api/alerts/sent', methods=['GET'])
@jwt_required()
def alerts_sent():
    me = get_jwt_identity()
    try:
        res = requests.get(
            _alert_sb('messages'), headers=_supabase_headers(),
            params={
                'sender_id': f'eq.{me}',
                'alert_key': 'not.is.null',
                'select': 'receiver_id,message_content,media_content,latitude,longitude,'
                          'alert_key,sent_at,is_read,read_at',
                'order': 'sent_at.desc',
                'limit': '300',
            },
            timeout=_SB_TIMEOUT,
        )
        if res.status_code != 200:
            logging.error(f"alerts_sent query failed: {res.text}")
            return _circle_bad("Could not load alerts.", 500)

        groups, order = {}, []
        for r in res.json():
            info = _alert_decode(r.get('message_content'))
            if info is None:
                continue
            k = r['alert_key']
            if k not in groups:
                groups[k] = {'row': dict(r, sender_id=me), 'info': info, 'deliveries': []}
                order.append(k)
            groups[k]['deliveries'].append({
                'receiver_id': r['receiver_id'],
                'is_read': bool(r.get('is_read')),
                'read_at': r.get('read_at'),
            })
            if r.get('media_content') and not groups[k]['row'].get('media_content'):
                groups[k]['row']['media_content'] = r['media_content']

        names = _circle_usernames([d['receiver_id'] for g in groups.values() for d in g['deliveries']])
        alerts = []
        for k in order:
            g = groups[k]
            item = _alert_view(g['row'], g['info'], True)
            for d in g['deliveries']:
                d['username'] = names.get(d['receiver_id'], 'Someone')
            item['deliveries'] = g['deliveries']
            alerts.append(item)
        return _circle_ok(alerts=alerts)
    except Exception as e:
        logging.error(f"alerts_sent error: {e}")
        return _circle_bad("Server error", 500)


@app.route('/api/alerts/received', methods=['GET'])
@jwt_required()
def alerts_received():
    me = get_jwt_identity()
    try:
        # Removing someone from your circle also hides their old alerts.
        contacts = set(_alert_contact_ids(me))
        if not contacts:
            return _circle_ok(clusters=[], unseen=0)

        res = requests.get(
            _alert_sb('messages'), headers=_supabase_headers(),
            params={
                'receiver_id': f'eq.{me}',
                'alert_key': 'not.is.null',
                'select': 'sender_id,message_content,media_content,latitude,longitude,'
                          'alert_key,sent_at,is_read',
                'order': 'sent_at.desc',
                'limit': '300',
            },
            timeout=_SB_TIMEOUT,
        )
        if res.status_code != 200:
            logging.error(f"alerts_received query failed: {res.text}")
            return _circle_bad("Could not load alerts.", 500)

        items = []
        for r in res.json():
            if r['sender_id'] not in contacts:
                continue
            info = _alert_decode(r.get('message_content'))
            if info is None:
                continue
            item = _alert_view(r, info, bool(r.get('is_read')))
            item['_t'] = _alert_parse_ts(r['sent_at'])
            items.append(item)

        now = datetime.now(timezone.utc)
        by_user = {}
        for it in items:
            by_user.setdefault(it['user_id'], []).append(it)
        names = _circle_usernames(list(by_user.keys()))

        clusters = []
        for uid, lst in by_user.items():
            lst.sort(key=lambda x: x['_t'])  # oldest first
            groups, cur = [], [lst[0]]
            for it in lst[1:]:
                if it['_t'] - cur[-1]['_t'] > timedelta(minutes=30):
                    groups.append(cur)
                    cur = [it]
                else:
                    cur.append(it)
            groups.append(cur)

            for g in groups:
                latest = g[-1]['_t']
                age = now - latest
                status = ('active' if age < timedelta(minutes=15)
                          else 'earlier' if age < timedelta(hours=24) else 'older')
                escalating = (age < timedelta(minutes=30) and any(
                    g[i + 2]['_t'] - g[i]['_t'] <= timedelta(minutes=10)
                    for i in range(len(g) - 2)))
                clusters.append({
                    'user_id': uid,
                    'username': names.get(uid, 'Someone'),
                    'status': status,
                    'escalating': escalating,
                    'count': len(g),
                    'unseen': sum(1 for x in g if not x['seen']),
                    'alerts': [{k: v for k, v in x.items() if k != '_t'} for x in reversed(g)],
                    '_sort': latest,
                })

        clusters.sort(key=lambda c: c['_sort'], reverse=True)
        for c in clusters:
            c.pop('_sort')
        return _circle_ok(clusters=clusters, unseen=sum(c['unseen'] for c in clusters))
    except Exception as e:
        logging.error(f"alerts_received error: {e}")
        return _circle_bad("Server error", 500)


@app.route('/api/alerts/read', methods=['POST'])
@jwt_required()
def alerts_mark_read():
    me = get_jwt_identity()
    raw = (request.get_json(silent=True) or {}).get('alert_keys') or []
    keys = [str(k).lower() for k in raw][:50]
    keys = [k for k in keys if _alert_valid_uuid(k)]
    if not keys:
        return _circle_ok()
    try:
        requests.patch(
            _alert_sb('messages'), headers=_supabase_headers(),
            params={'receiver_id': f'eq.{me}', 'alert_key': f"in.({','.join(keys)})",
                    'is_read': 'eq.false'},
            json={'is_read': True, 'read_at': datetime.now(timezone.utc).isoformat()},
            timeout=_SB_TIMEOUT,
        )
        return _circle_ok()
    except Exception as e:
        logging.error(f"alerts_mark_read error: {e}")
        return _circle_bad("Server error", 500)

# Every limit lives here. The premium page, /api/entitlements and the
# enforcement all read this, so changing a number changes them all.
PLAN_LIMITS = {
    'free':    {'circle_max': 2,  'alerts_per_day': 6,  'max_video_secs': 30,
                'can_download': False, 'can_use_map': False},
    'premium': {'circle_max': 10, 'alerts_per_day': 30, 'max_video_secs': 120,
                'can_download': True,  'can_use_map': True},
}


def premium_status(user_id):
    """Premium = premium_until is in the future. is_premium=true with NO date is a
    manual grant that never expires. Returns None if Supabase failed."""
    try:
        r = requests.get(_alert_sb('users'), headers=_supabase_headers(), timeout=_SB_TIMEOUT,
                         params={'id': f'eq.{user_id}', 'select': 'is_premium,premium_until'})
        r.raise_for_status()
        row = (r.json() or [{}])[0]
        until = _alert_parse_ts(row['premium_until']) if row.get('premium_until') else None
        active = until > datetime.now(timezone.utc) if until else bool(row.get('is_premium'))
        if until and row.get('is_premium') and not active:        # expired: drop the stale flag
            requests.patch(_alert_sb('users'), headers=_supabase_headers(), timeout=_SB_TIMEOUT,
                           params={'id': f'eq.{user_id}'}, json={'is_premium': False})
        return {'is_premium': active,
                'premium_until': until.isoformat() if until else None,
                'plan': PLAN_LIMITS['premium' if active else 'free']}
    except Exception as e:
        logging.error(f"premium_status error: {e}")
        return None


def premium_settle(ref):
    """Confirm ONE payment with Korapay, then apply it exactly once.
    The webhook, the callback page and the offer poll all call this, in any order
    or all at once. -> paid | already | pending | failed | underpaid | unknown | error"""
    try:
        o = requests.get(_alert_sb('premium_orders'), headers=_supabase_headers(), timeout=_SB_TIMEOUT,
                         params={'reference': f'eq.{ref}', 'select': 'status'})
        o.raise_for_status()
        rows = o.json()
        if not rows:
            return 'unknown'
        if rows[0]['status'] == 'paid':
            return 'already'

        # Never trust a webhook or a redirect. Ask Korapay directly.
        k = requests.get(f'{KORA_API}/charges/{ref}', timeout=12,
                         headers={'Authorization': f"Bearer {os.getenv('KORAPAY_SECRET_KEY')}"})
        if k.status_code == 404:
            return 'pending'                                      # not paid yet
        k.raise_for_status()
        charge = k.json().get('data') or {}
        if charge.get('reference') not in (None, ref):
            return 'error'
        state = str(charge.get('status', '')).lower()

        if state == 'success':       # applied inside ONE database transaction (premium.sql)
            a = requests.post(_alert_sb('rpc/apply_premium_order'), headers=_supabase_headers(),
                              timeout=_SB_TIMEOUT,
                              json={'p_reference': ref, 'p_amount': float(charge.get('amount') or 0)})
            a.raise_for_status()
            result = a.json().get('result', 'error')
            logging.info(f"premium order {ref}: {result}")
            return result
        if state == 'failed':
            requests.patch(_alert_sb('premium_orders'), headers=_supabase_headers(), timeout=_SB_TIMEOUT,
                           params={'reference': f'eq.{ref}', 'status': 'eq.pending'},
                           json={'status': 'failed'})
            return 'failed'
        return 'pending'
    except Exception as e:
        logging.error(f"premium_settle error: {e}")
        return 'error'


# ── what the premium page shows: price, days, features, and who you are ─────
@app.route('/api/premium/offer', methods=['GET'])
@jwt_required()
def premium_offer():
    me = get_jwt_identity()
    try:    # webhook never arrived (server asleep)? re-check this user's recent pending orders
        since = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        for o in requests.get(_alert_sb('premium_orders'), headers=_supabase_headers(), timeout=_SB_TIMEOUT,
                              params={'user_id': f'eq.{me}', 'status': 'eq.pending',
                                      'created_at': f'gte.{since}', 'select': 'reference',
                                      'order': 'created_at.desc', 'limit': '2'}).json():
            premium_settle(o['reference'])
    except Exception as e:
        logging.error(f"premium_offer reconcile error: {e}")

    st = premium_status(me)
    if st is None:
        return _circle_bad('Could not load premium right now.', 500)

    free, paid = PLAN_LIMITS['free'], PLAN_LIMITS['premium']
    dur = lambda s: f"{s // 60} minute{'s' if s > 60 else ''}" if s % 60 == 0 else f"{s} seconds"
    return _circle_ok(
        is_premium=st['is_premium'], premium_until=st['premium_until'],
        price_naira=PREMIUM_PRICE, days=PREMIUM_DAYS,
        period='month' if PREMIUM_DAYS == 30 else f'{PREMIUM_DAYS} days',
        features=[
            {'icon': 'circle', 'title': f"Up to {paid['circle_max']} trusted contacts",
             'detail': f"Free accounts can add {free['circle_max']}."},
            {'icon': 'alerts', 'title': f"{paid['alerts_per_day']} alerts a day",
             'detail': f"Free accounts get {free['alerts_per_day']}."},
            {'icon': 'video', 'title': f"Record up to {dur(paid['max_video_secs'])}",
             'detail': f"Free recordings stop at {dur(free['max_video_secs'])}."},
            {'icon': 'map', 'title': 'Live map on every alert',
             'detail': 'Free accounts see a pin and coordinates.'},
            {'icon': 'download', 'title': 'Save videos to your phone',
             'detail': 'Download any video alert you receive.'},
        ])


# ── what this user is allowed to do right now (the app caches this) ─────────
@app.route('/api/entitlements', methods=['GET'])
@jwt_required()
def premium_entitlements():
    st = premium_status(get_jwt_identity())
    if st is None:
        return _circle_bad('Could not load your plan right now.', 500)
    return _circle_ok(is_premium=st['is_premium'], premium_until=st['premium_until'], **st['plan'])


# ── Pay button: create the order, hand back Korapay's checkout link ─────────
@app.route('/api/premium/checkout', methods=['POST'])
@limiter.limit('10 per hour')
@jwt_required()
def premium_checkout():
    me = get_jwt_identity()
    key = os.getenv('KORAPAY_SECRET_KEY')
    if not key:
        return _circle_bad('Payments are not available right now.', 503)
    try:
        u = requests.get(_alert_sb('users'), headers=_supabase_headers(), timeout=_SB_TIMEOUT,
                         params={'id': f'eq.{me}', 'select': 'username,email'}).json()
        if not u or not u[0].get('email'):
            return _circle_bad('Your account has no email. Add one first.')

        # The price is decided HERE. The app never sends an amount, name or email.
        ref = str(uuid.uuid4())
        requests.post(_alert_sb('premium_orders'), headers={**_supabase_headers(), 'Prefer': 'return=minimal'},
                      timeout=_SB_TIMEOUT,
                      json={'reference': ref, 'user_id': me, 'amount': PREMIUM_PRICE,
                            'days': PREMIUM_DAYS}).raise_for_status()

        k = requests.post(f'{KORA_API}/charges/initialize', timeout=20,
                          headers={'Authorization': f'Bearer {key}'},
                          json={'reference': ref, 'amount': PREMIUM_PRICE, 'currency': 'NGN',
                                'narration': 'SafeLens Premium', 'merchant_bears_cost': False,
                                'redirect_url': f'{PUBLIC_URL}/premium/callback',
                                'notification_url': f'{PUBLIC_URL}/api/premium/webhook',
                                'customer': {'name': u[0].get('username') or 'Customer',
                                             'email': u[0]['email']}})
        url = (k.json().get('data') or {}).get('checkout_url')
        if not k.ok or not url:
            logging.error(f"korapay initialize failed: {k.status_code} {k.text[:300]}")
            requests.patch(_alert_sb('premium_orders'), headers=_supabase_headers(), timeout=_SB_TIMEOUT,
                           params={'reference': f'eq.{ref}'}, json={'status': 'failed'})
            return _circle_bad('Could not reach the payment provider. Try again.', 502)
        return _circle_ok(checkout_url=url, reference=ref)
    except Exception as e:
        logging.error(f"premium_checkout error: {e}")
        return _circle_bad('Could not start the payment. Try again.', 500)


# ── Korapay -> us.  Signed, but we still confirm with Korapay before applying ─
@app.route('/api/premium/webhook', methods=['POST'])
def premium_webhook():
    secret = os.getenv('KORAPAY_SECRET_KEY')
    if not secret:
        return '', 503
    try:    # whole-number amounts are read as ints so we re-sign them exactly like JSON.stringify
        body = json.loads(request.get_data(),
                          parse_float=lambda s: int(float(s)) if float(s).is_integer() else float(s))
        ref = body['data']['reference']
        signed = json.dumps(body['data'], separators=(',', ':'), ensure_ascii=False)
    except (ValueError, KeyError, TypeError):
        return '', 200

    # Korapay signs ONLY the `data` object: HMAC-SHA256 (hex) with your secret key.
    expected = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
    sent = request.headers.get('x-korapay-signature', '').strip().lower()
    if not hmac.compare_digest(expected.encode(), sent.encode()):
        logging.warning('premium webhook: signature did not match, ignored')
        return '', 200

    if str(body.get('event', '')).startswith('charge.') and _alert_valid_uuid(ref):
        if premium_settle(ref) == 'error':
            return '', 500                      # transient problem: Korapay will retry
    return '', 200


# ── the page the user lands on after paying (in their browser, not the app) ──
_PREMIUM_PAGES = {
    'paid':      ('#8fd9b6', 'Payment received', 'Premium is active. You can close this tab and go back to SafeLens.'),
    'pending':   ('#f5b942', 'Payment is processing', 'This can take a minute. Go back to SafeLens and tap Check again.'),
    'error':     ('#f5b942', 'We could not confirm it yet', 'Go back to SafeLens and tap Check again in a minute.'),
    'failed':    ('#f2735b', 'Payment did not go through', 'Go back to SafeLens to try again.'),
    'underpaid': ('#f2735b', 'Amount was too low', 'The amount received was less than the price. Please contact support.'),
    'unknown':   ('#f2735b', 'Link not recognised', 'Go back to SafeLens and start again.'),
}


@app.route('/premium/callback', methods=['GET'])
@limiter.limit('60 per minute')
def premium_callback():
    ref = request.args.get('reference', '')
    result = premium_settle(ref) if _alert_valid_uuid(ref) else 'unknown'
    color, title, text = _PREMIUM_PAGES.get('paid' if result == 'already' else result,
                                            _PREMIUM_PAGES['unknown'])
    return Response(
        '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>SafeLens</title>'
        '<body style="margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;'
        'background:#0f0f10;color:#f4efe6;font-family:system-ui,sans-serif">'
        '<div style="max-width:420px;margin:24px;padding:34px 28px;border-radius:28px;background:#1b1b1d;text-align:center">'
        f'<div style="width:16px;height:16px;border-radius:50%;background:{color};margin:0 auto 20px"></div>'
        f'<h1 style="font-size:24px;margin:0 0 10px">{title}</h1>'
        f'<p style="margin:0;color:#b9b3a8;line-height:1.55">{text}</p></div></body>',
        mimetype='text/html')


# ── replacements for the two old functions you deleted ──────────────────────
@app.route('/api/user/<string:user_id>/premium', methods=['GET'])
@jwt_required()
def check_premium_status(user_id):
    """Is this user premium? (the camera drawer asks this)"""
    if str(user_id) != get_jwt_identity():
        return _circle_bad('Unauthorized action', 403)
    st = premium_status(user_id)
    if st is None:
        return _circle_bad('Database error', 500)
    return _circle_ok(is_premium=st['is_premium'], premium_until=st['premium_until'])


def is_premium_user(conn, user_id):
    st = premium_status(user_id)
    return bool(st and st['is_premium'])
