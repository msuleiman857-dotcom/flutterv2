import os
import time
import math
os.environ['EVENTLET_NO_GREENDNS'] = 'yes'

import eventlet
eventlet.monkey_patch()

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
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from cryptography.fernet import Fernet
import uuid    
from security import (
    hash_password, is_valid_email_format, is_valid_username,
    verify_bot_token, generate_pow_challenge, verify_pow, is_suspicious_request,
    dummy_verify, verify_password
)
from concurrent.futures import ThreadPoolExecutor, as_completed

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

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

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

@socketio.on('disconnect')
def handle_disconnect():
    for uid, sid in list(active_users.items()):
        if sid == request.sid:
            del active_users[uid]
            print(f"User {uid} disconnected.")
            break

@app.route('/')
def health():
    return jsonify({"status": "hack me if you can"}), 200

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

@app.route("/api/payments/release", methods=["POST"])
@jwt_required()
def release_funds():
    payer_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    recipient_id = data.get("recipient_id")

    if not recipient_id:
        return jsonify({"status": "error", "message": "Recipient ID is required"}), 400

    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_SERVICE_KEY")
    sb_headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json"
    }

    try:
        # ── STEP 1: Fetch ALL unreleased success payments from this payer to this recipient
        pay_res = requests.get(
            f"{supabase_url}/rest/v1/payments",
            headers=sb_headers,
            params={
                "payer_id": f"eq.{payer_id}",
                "recipient_id": f"eq.{recipient_id}",
                "status": "eq.success",
                "concluded": "eq.false",
                "select": "id,reference,payer_id,recipient_id,amount,status,concluded",
                "order": "created_at.asc"
            }
        )
        
        logging.info(f"DEBUG release_funds: payer_id={payer_id}, recipient_id={recipient_id}")
        logging.info(f"DEBUG pay_res status: {pay_res.status_code}")
        
        if pay_res.status_code != 200 or not pay_res.json():
            return jsonify({"status": "error", "message": "No pending payments found"}), 404

        payments = pay_res.json()

        # ── STEP 2: Fetch recipient bank details once ──────────────────────
        bank_res = requests.get(
            f"{supabase_url}/rest/v1/linked_bank",
            headers=sb_headers,
            params={
                "owner_id": f"eq.{recipient_id}",
                "select": "account_number,acct_name,bank_code,bank_name"
            }
        )
        if bank_res.status_code != 200 or not bank_res.json():
            return jsonify({"status": "error", "message": "Recipient has no linked bank account"}), 422

        bank = bank_res.json()[0]

        kora_base_url = os.getenv("KORA_GCP_BASE_URL")
        kora_secret = os.getenv("KORAPAY_SECRET_KEY")
        kora_headers = {
            "Authorization": f"Bearer {kora_secret}",
            "Content-Type": "application/json"
        }

        released = []
        failed = []

        # ── STEP 3: Loop every unreleased payment and disburse each one ────
        for payment in payments:
            reference = payment["reference"]
            try:
                kora_api_base = "https://api.korapay.com/merchant/api/v1"
                # ── NEW: VERIFY TRANSACTION ON KORAPAY FIRST ───────────────
                verify_res = requests.get(
                    f"{kora_api_base}/charges/{reference}",
                    headers=kora_headers,
                    timeout=15
                )

                if verify_res.status_code != 200:
                    logging.error(f"Kora validation request failed for {reference}: {verify_res.text}")
                    failed.append(reference)
                    continue

                verify_data = verify_res.json()
                kora_data = verify_data.get("data", {})

                # 1. Check status from KoraPay backend
                if not verify_data.get("status") or kora_data.get("status") != "success":
                    logging.error(f"Security Alert: Kora backend reports {reference} is not successful. DB mismatch.")
                    failed.append(reference)
                    continue

                # 2. Verify amount matches to prevent price tampering
                try:
                    kora_amount = float(kora_data.get("amount", 0))
                    db_amount = float(payment["amount"])
                    
                    if abs(kora_amount - db_amount) > 0.01:
                        logging.error(f"Security Alert: Price mismatch for {reference}. DB: {db_amount}, Kora: {kora_amount}")
                        failed.append(reference)
                        continue
                except (ValueError, TypeError) as price_err:
                    logging.error(f"Error parsing amount for validation on {reference}: {price_err}")
                    failed.append(reference)
                    continue
                # ───────────────────────────────────────────────────────────

                payout_amount = round(db_amount * 0.8, 2)
                kora_payload = {
                    "reference": f"RELEASE-{reference}",
                    "destination": {
                        "type": "bank_account",
                        "amount": payout_amount,
                        "currency": "NGN",  
                        "narration": f"Meetup payout to {bank['acct_name']}",
                        "bank_account": {
                            "bank": bank["bank_code"],
                            "account": bank["account_number"]
                        },
                        "customer": {
                            "name": bank["acct_name"],
                            "email": f"{recipient_id}@internal.app"
                        }
                    }
                }

                kora_res = requests.post(
                    f"{kora_base_url}/merchant/api/v1/transactions/disburse",
                    json=kora_payload,
                    headers=kora_headers,
                    timeout=30
                )

                if kora_res.status_code not in (200, 201):
                    logging.error(f"Kora disburse failed for {reference}: {kora_res.text}")
                    failed.append(reference)
                    continue

                # ── STEP 4: Mark this payment concluded ────────────────────
                requests.patch(
                    f"{supabase_url}/rest/v1/payments",
                    headers=sb_headers,
                    params={
                        "reference": f"eq.{reference}",
                        "payer_id": f"eq.{payer_id}",
                        "concluded": "eq.false"
                    },
                    json={"concluded": True}
                )

                # ── STEP 5: Audit trail ────────────────────────────────────
                requests.post(
                    f"{supabase_url}/rest/v1/released_funds",
                    headers={**sb_headers, "Prefer": "return=representation"},
                    json={
                        "reference": reference,
                        "payer_id": payer_id,
                        "recipient_id": recipient_id,
                        "amount": payout_amount,
                        "currency": "NGN",
                        "bank_code": bank["bank_code"],
                        "bank_name": bank["bank_name"],
                        "account_number": bank["account_number"],
                        "released_at": datetime.now(timezone.utc).isoformat()
                    }
                )

                released.append(reference)
                logging.info(f"Released: {reference} → {recipient_id}")

            except Exception as e:
                logging.error(f"Error releasing {reference}: {e}")
                failed.append(reference)
                continue

        if not released:
            return jsonify({
                "status": "error",
                "message": "All payouts failed. Please try again."
            }), 502

        # ── STEP 6: Notify recipient via socket ────────────────────────────
        total_released = sum(
            float(p["amount"]) for p in payments
            if p["reference"] in released
        )
        if recipient_id in active_users: # Make sure active_users is available in scope
            socketio.emit("funds_released", {
                "references": released,
                "total_amount": total_released,
                "currency": "NGN"
            }, room=active_users[recipient_id])

        return jsonify({
            "status": "success",
            "message": f"{len(released)} payment(s) released successfully",
            "released": released,
            "failed": failed,
            "total_released": total_released
        }), 200

    except requests.exceptions.Timeout:
        logging.error(f"Kora timeout on bulk release. Payer: {payer_id}")
        return jsonify({"status": "error", "message": "Payment gateway timed out"}), 504
    except Exception as e:
        logging.error(f"release_funds error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route("/api/payments/decline", methods=["POST"])
@jwt_required()
def decline_payment():
    recipient_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}
    reference = data.get("reference")

    if not reference:
        return jsonify({"status": "error", "message": "Reference required"}), 400

    supabase_url = os.getenv("SUPABASE_URL")
    supabase_key = os.getenv("SUPABASE_SERVICE_KEY")
    sb_headers = {
        "apikey": supabase_key,
        "Authorization": f"Bearer {supabase_key}",
        "Content-Type": "application/json"
    }

    try:
        # Fetch the payment
        pay_res = requests.get(
            f"{supabase_url}/rest/v1/payments",
            headers=sb_headers,
            params={
                "reference": f"eq.{reference}",
                "recipient_id": f"eq.{recipient_id}",
                "status": "eq.success",
                "concluded": "eq.false",
                "select": "id,reference,payer_id,recipient_id,amount"
            }
        )
        if pay_res.status_code != 200 or not pay_res.json():
            return jsonify({"status": "error", "message": "Payment not found"}), 404

        payment = pay_res.json()[0]
        payer_id = payment["payer_id"]
        amount = float(payment["amount"])

        # Fetch payer bank details to refund back to sender
        bank_res = requests.get(
            f"{supabase_url}/rest/v1/linked_bank",
            headers=sb_headers,
            params={
                "owner_id": f"eq.{payer_id}",
                "select": "account_number,acct_name,bank_code,bank_name"
            }
        )
        if bank_res.status_code != 200 or not bank_res.json():
            return jsonify({"status": "error", "message": "Sender has no linked bank account"}), 422

        bank = bank_res.json()[0]

        kora_secret = os.getenv("KORAPAY_SECRET_KEY")
        kora_base_url = os.getenv("KORA_GCP_BASE_URL")
        kora_headers = {
            "Authorization": f"Bearer {kora_secret}",
            "Content-Type": "application/json"
        }

        # Refund full amount back to payer — no 80% cut
        kora_payload = {
            "reference": f"REFUND-{reference}",
            "destination": {
                "type": "bank_account",
                "amount": amount,
                "currency": "NGN",
                "narration": f"Meetup refund to {bank['acct_name']}",
                "bank_account": {
                    "bank": bank["bank_code"],
                    "account": bank["account_number"]
                },
                "customer": {
                    "name": bank["acct_name"],
                    "email": f"{payer_id}@internal.app"
                }
            }
        }

        kora_res = requests.post(
            f"{kora_base_url}/merchant/api/v1/transactions/disburse",
            json=kora_payload,
            headers=kora_headers,
            timeout=30
        )

        if kora_res.status_code not in (200, 201):
            logging.error(f"Kora refund failed for {reference}: {kora_res.text}")
            return jsonify({"status": "error", "message": "Refund failed"}), 502

        # Mark payment concluded + declined
        requests.patch(
            f"{supabase_url}/rest/v1/payments",
            headers=sb_headers,
            params={"reference": f"eq.{reference}"},
            json={"concluded": True, "is_accepted": False}
        )

        # Notify payer via socket
        if str(payer_id) in active_users:
            socketio.emit("payment_declined", {
                "reference": reference,
                "amount": str(amount),
                "recipient_id": recipient_id,
                "payer_id": str(payer_id),
            }, room=active_users[str(payer_id)])

        return jsonify({"status": "success", "message": "Payment declined and refunded"}), 200

    except requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Payment gateway timed out"}), 504
    except Exception as e:
        logging.error(f"decline_payment error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route('/api/upload-media', methods=['POST'])
@jwt_required()
def upload_media():
    user_id = get_jwt_identity()

    try:
        file = request.files.get('file')
        mime_type = request.form.get('mime_type', 'application/octet-stream')
        ext = request.form.get('ext', 'bin')
        if not file:
            return jsonify({'success': False, 'message': 'No file provided'}), 400
        unique_id = str(uuid.uuid4())
        storage_path = f"posts/{user_id}/{unique_id}.{ext}"

        bucket = storage.bucket()
        blob = bucket.blob(storage_path)
        blob.upload_from_string(file.read(), content_type=mime_type)
        public_url = f"https://storage.googleapis.com/{bucket.name}/{storage_path}"

        return jsonify({'success': True, 'public_url': public_url}), 200
    except Exception as e:
        logging.error(f"upload_media error: {e}")
        return jsonify({'success': False, 'message': 'Internal server error'}), 500

@app.route('/api/update_price', methods=['POST'])
@jwt_required()
def update_price():
    try:
        user_id = get_jwt_identity()
        data = request.get_json(silent=True) or {}
        new_price = data.get('price_naira')

        if new_price is None:
            return jsonify({"status": "error", "message": "Price is required"}), 400

        supabase_url = os.getenv('SUPABASE_URL')
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json"
        }

        # Update the database
        res = requests.patch(
            f"{supabase_url}/rest/v1/users?id=eq.{user_id}",
            headers=headers,
            json={"price_naira": float(new_price)}
        )

        if res.status_code in (200, 204):
            # ✨ REAL-TIME MAGIC: Tell all active feeds that this user changed their price
            socketio.emit('price_updated', {
                'user_id': str(user_id),
                'price_naira': float(new_price)
            })
            return jsonify({"status": "success", "message": "Price updated!"}), 200
        else:
            return jsonify({"status": "error", "message": "Database error"}), 500

    except Exception as e:
        logging.error(f"update_price error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500

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


@app.route('/api/payment/accept', methods=['POST'])
@jwt_required()
def accept_payment_bubble():
    try:
        user_id = get_jwt_identity()  # This is the receiver
        data = request.get_json(silent=True) or {}
        reference = data.get('reference')
        receiver_lat = data.get('receiver_lat')
        receiver_lng = data.get('receiver_lng')

        if not reference:
            return jsonify({"status": "error", "message": "Missing reference"}), 400

        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json"
        }

        # Fetch payment row to get payer_id
        pay_res = requests.get(
            f"{supabase_url}/rest/v1/payments?reference=eq.{reference}&select=payer_id,recipient_id,amount,status,concluded",
            headers=headers
        )
        if pay_res.status_code != 200 or not pay_res.json():
            return jsonify({"status": "error", "message": "Payment not found"}), 404

        payment = pay_res.json()[0]
        payer_id = str(payment['payer_id'])
        recipient_id = str(payment['recipient_id'])

        # Security: only the recipient can accept
        if user_id != recipient_id:
            return jsonify({"status": "error", "message": "Unauthorized"}), 403

        # Guard: don't accept an already concluded payment
        if payment.get('concluded'):
            return jsonify({"status": "error", "message": "Payment already concluded"}), 409

        # ── Mark is_accepted = true in payments table ──────────────────────
        patch_res = requests.patch(
            f"{supabase_url}/rest/v1/payments?reference=eq.{reference}",
            headers=headers,
            json={"is_accepted": True}
        )
        if patch_res.status_code not in (200, 204):
            logging.error(f"Failed to set is_accepted for {reference}: {patch_res.text}")
            return jsonify({"status": "error", "message": "Failed to update payment"}), 500

        distance_km = None
        if receiver_lat is not None and receiver_lng is not None:
            sender_res = requests.get(
                f"{supabase_url}/rest/v1/users?id=eq.{payer_id}&select=latitude,longitude,username",
                headers=headers
            )
            if sender_res.status_code == 200 and sender_res.json():
                sender = sender_res.json()[0]
                if sender.get('latitude') is not None and sender.get('longitude') is not None:
                    distance_km = round(_haversine_km(
                        float(receiver_lat), float(receiver_lng),
                        float(sender['latitude']), float(sender['longitude'])
                    ), 1)

        # ── Emit to payer — includes is_accepted so their bubble updates ──
        if payer_id in active_users:
            socketio.emit('payment_accepted', {
                'reference': reference,
                'distance_km': distance_km,
                'receiver_id': recipient_id,
                'payer_id': payer_id,
                'is_accepted': True,        # 👈 bubble state for payer
            }, room=active_users[payer_id])
            logging.info(f"payment_accepted emitted to sender {payer_id}, distance={distance_km}km")

        # ── Also emit to recipient themselves so their own bubble updates ──
        if recipient_id in active_users:
            socketio.emit('payment_accepted', {
                'reference': reference,
                'distance_km': distance_km,
                'receiver_id': recipient_id,
                'payer_id': payer_id,
                'is_accepted': True,        # 👈 bubble state for recipient
            }, room=active_users[recipient_id])

        return jsonify({
            "status": "success",
            "distance_km": distance_km,
        }), 200

    except Exception as e:
        logging.error(f"accept_payment_bubble error: {e}")
        return jsonify({"status": "error", "message": "Internal error"}), 500

@socketio.on('profile_pic_updated')
def handle_profile_pic_updated(data):
    user_id = str(data.get('user_id'))
    url = data.get('profile_pic_url')
    socketio.emit('profile_pic_updated', {
        'user_id': user_id,
        'profile_pic_url': url
    }, broadcast=True)
        
@socketio.on('mark_as_read')
def handle_mark_as_read(data):
    """
    Triggers when a receiver sees a message. 
    Updates DB and tells the sender to turn their checkmark blue.
    """
    message_id = data.get('message_id')
    sender_id = data.get('sender_id')  # The person who originally sent the message

    if not message_id or not sender_id:
        return

    try:
        # 1. Update Supabase so the change is permanent
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/messages"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"
        }
        params = {"id": f"eq.{message_id}"}
        payload = {"is_read": True}
        
        # Sync update to database
        requests.patch(url, headers=headers, params=params, json=payload)

        # 2. Real-time "Tap on the shoulder" for the Sender
        # If the sender is currently online, tell their app to update the UI instantly
        print(f"DEBUG mark_as_read: sender_id={sender_id}, active_users={list(active_users.keys())}")
        if str(sender_id) in active_users:
            sender_sid = active_users[str(sender_id)]
            print(f"DEBUG emitting message_read_update to sid={sender_sid}")
            socketio.emit('message_read_update', {
                'message_id': message_id
            }, room=sender_sid)
        else:
            print(f"DEBUG sender_id {sender_id} NOT in active_users — relay skipped")
            
    except Exception as e:
        logging.error(f"Error in mark_as_read relay: {e}")

@socketio.on('typing')
def handle_typing(data):
    """
    Handles typing status via WebSockets.
    This replaces the /api/set_typing HTTP route and stops the logs.
    """
    sender_id = str(data.get('sender_id'))
    receiver_id = str(data.get('receiver_id'))
    is_typing = data.get('is_typing', False)
    typing_text = data.get('typing_text', "")

    # 1. Update the database (Supabase) via HTTPS Bypass
    try:
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/typing_status"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json"
        }

        if is_typing:
            # UPSERT: Insert or update if exists
            headers["Prefer"] = "resolution=merge-duplicates"
            payload = {
                "sender_id": sender_id,
                "receiver_id": receiver_id,
                "is_typing": True,
                "typing_text": str(typing_text),
                "updated_at": datetime.now(timezone.utc).isoformat()
            }
            requests.post(url, headers=headers, json=payload)
        else:
            # DELETE: Remove the typing indicator
            params = {"sender_id": f"eq.{sender_id}", "receiver_id": f"eq.{receiver_id}"}
            requests.delete(url, headers=headers, params=params)

        # 2. Real-time Relay: Tell the receiver instantly
        if receiver_id in active_users:
            socketio.emit('typing', {
                'sender_id': sender_id,
                'is_typing': is_typing,
                'typing_text': typing_text
            }, room=active_users[receiver_id])

    except Exception as e:
        logging.error(f"Error in socket typing relay: {e}")

@app.route('/api/posts/<string:post_id>/like', methods=['POST'])
@jwt_required()
def toggle_post_like(post_id):
    """
    Lightweight route: Simply inserts or deletes rows from post_likes.
    Does NOT calculate counts or handle Socket.IO broadcasts directly.
    """
    current_user_id = get_jwt_identity()
    supabase_url = os.getenv('SUPABASE_URL')
    headers = {
        "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
        "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
        "Content-Type": "application/json"
    }

    try:
        # Check if this user has already liked this post
        check_url = f"{supabase_url}/rest/v1/post_likes"
        params = {
            "post_id": f"eq.{post_id}",
            "user_id": f"eq.{current_user_id}"
        }
        check_res = requests.get(check_url, headers=headers, params=params)
        
        if check_res.status_code != 200:
            return jsonify({"success": False, "message": "Database lookup error"}), 500
            
        existing_likes = check_res.json()

        if len(existing_likes) > 0:
            # UNLIKE ACTION: Delete the row
            requests.delete(check_url, headers=headers, params=params)
            return jsonify({"success": True, "action": "unliked"}), 200
        else:
            # LIKE ACTION: Insert a new row
            like_data = {"post_id": post_id, "user_id": current_user_id}
            requests.post(check_url, headers=headers, json=like_data)
            return jsonify({"success": True, "action": "liked"}), 200

    except Exception as e:
        logging.error(f"Error toggling post like: {str(e)}")
        return jsonify({"success": False, "message": "Internal server error"}), 500


@app.route('/api/webhook/supabase-likes', methods=['POST'])
def supabase_likes_webhook():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No payload received"}), 400

    print("DEBUG: Supabase Webhook payload received:", data)

    # 1. Safe extraction handling both INSERT (likes) and DELETE (unlikes)
    event_type = data.get('type')  # 'INSERT' or 'DELETE'
    
    # Python fallback trick to avoid the NoneType explicit null trap
    record = data.get('record') if data.get('record') is not None else data.get('old_record')
    
    if not record:
        return jsonify({"status": "error", "message": "No record found in payload"}), 400

    post_id = record.get('post_id')
    if not post_id:
        return jsonify({"status": "error", "message": "No post_id found in record"}), 400

    try:
        # 2. Fetch the fresh absolute live total from Supabase database
        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
        
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}"
        }
        
        # Querying the likes table where post_id matches
        response = requests.get(
            f"{supabase_url}/rest/v1/post_likes?post_id=eq.{post_id}&select=id",
            headers=headers
        )

        if response.status_code == 200:
            likes_list = response.json()
            total_likes = len(likes_list)  # Count up the actual active rows
            
            print(f"DEBUG: Broadcast to App -> Post: {post_id} now has {total_likes} likes")

            # ✨ THE MISSING PIECE: Update the main 'posts' table! ✨
            post_update_url = f"{supabase_url}/rest/v1/posts"
            update_res = requests.patch(
                post_update_url, 
                headers=headers, 
                params={"id": f"eq.{post_id}"}, 
                json={"likes": total_likes}
            )
            print(f"DEBUG: Post table update status: {update_res.status_code}")

            # 3. Broadcast real-time change to all connected Flutter apps via Socket.IO
            socketio.emit(
                'post_like_updated', 
                {
                    'post_id': str(post_id), 
                    'likes': int(total_likes)
                }
            )

            return jsonify({"status": "success", "likes": total_likes}), 200
        else:
            print(f"ERROR: Supabase returned code {response.status_code}: {response.text}")
            return jsonify({"status": "error", "message": "Failed to count likes from DB"}), 500

    except Exception as e:
        print(f"CRITICAL WEBHOOK EXCEPTION: {str(e)}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/verify_kyc', methods=['POST'])
@jwt_required()
@limiter.limit("1 per hour")
def verify_kyc():
    user_id = get_jwt_identity()
    data = request.get_json()

    nin_id = data.get('nin')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    dob = data.get('date_of_birth')
    selfie_base64 = data.get('selfie')  # already prefixed "data:image/jpeg;base64,..."

    if not all([nin_id, first_name, last_name, dob, selfie_base64]):
        return jsonify({"status": "error", "message": "Missing required fields"}), 400

    try:
        payload = {
            "id": nin_id,
            "verification_consent": True,
            "validation": {
                "first_name": first_name,
                "last_name": last_name,
                "date_of_birth": dob,
                "selfie": selfie_base64
            }
        }
        headers = {
            "Authorization": f"Bearer {os.getenv('KORAPAY_SECRET_KEY')}",
            "Content-Type": "application/json"
        }

        response = requests.post(
            "https://api.korapay.com/merchant/api/v1/identities/ng/nin",
            json=payload,
            headers=headers,
            timeout=30
        )
        result = response.json()

        if response.status_code != 200 or not result.get('status'):
            logging.error(f"Korapay verification failed for user {user_id}: {result}")
            return jsonify({"status": "error", "message": "Verification failed. Please check your details and try again."}), 400

        validation = result.get('data', {}).get('validation', {})
        first_name_match = validation.get('first_name', {}).get('match', False)
        last_name_match = validation.get('last_name', {}).get('match', False)
        dob_match = validation.get('date_of_birth', {}).get('match', False)
        selfie_confidence = validation.get('selfie', {}).get('confidence_rating', 0)

        if not (first_name_match and last_name_match and dob_match and selfie_confidence >= 90):
            logging.warning(f"KYC failed strict checks for user {user_id}: name={first_name_match}/{last_name_match}, dob={dob_match}, confidence={selfie_confidence}")
            return jsonify({"status": "error", "message": "Identity verification did not pass. Please try again in 1 hour."}), 400

        # Update kyc — this triggers your existing Supabase webhook,
        # which broadcasts user_kyc_verified over the socket automatically.
        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
        update_headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json"
        }
        update_response = requests.patch(
            f"{supabase_url}/rest/v1/users?id=eq.{user_id}",
            headers=update_headers,
            json={"kyc": True}
        )

        if update_response.status_code not in (200, 204):
            logging.error(f"Failed to update kyc for user {user_id}: {update_response.text}")
            return jsonify({"status": "error", "message": "Verification succeeded but failed to save. Contact support."}), 500

        return jsonify({"status": "success", "success": True, "message": "Identity verified successfully"}), 200

    except requests.exceptions.RequestException as e:
        logging.error(f"Korapay request error for user {user_id}: {e}")
        return jsonify({"status": "error", "message": "Verification service unavailable. Please try again in 1 hour."}), 503
    except Exception as e:
        logging.error(f"verify_kyc unexpected error for user {user_id}: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route('/api/webhook/kyc_status', methods=['POST'])
def kyc_status_webhook():
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "No payload received"}), 400

    old_record = data.get('old_record') if data.get('old_record') is not None else {}
    record = data.get('record') if data.get('record') is not None else {}

    if not record:
        return jsonify({"status": "error", "message": "No record found in payload"}), 400

    user_id = record.get('id')
    old_kyc = old_record.get('kyc')
    new_kyc = record.get('kyc')

    if not user_id:
        return jsonify({"status": "error", "message": "No user_id in record"}), 400

    if old_kyc != new_kyc:
        try:
            supabase_url = os.getenv('SUPABASE_URL')
            supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
            headers = {
                "apikey": supabase_key,
                "Authorization": f"Bearer {supabase_key}"
            }

            # Go back to Supabase to confirm the real current kyc_status
            response = requests.get(
                f"{supabase_url}/rest/v1/users?id=eq.{user_id}&select=kyc",
                headers=headers
            )

            if response.status_code == 200 and response.json():
                actual_kyc = response.json()[0].get('kyc')
                print(f"DEBUG: Confirmed KYC from Supabase for user {user_id}: {actual_kyc}")

                if actual_kyc == True:
                    socketio.emit('user_kyc_verified', {'user_id': str(user_id)})
                    print(f"DEBUG: Broadcast KYC verified for user: {user_id}")
            else:
                print(f"ERROR: Supabase returned {response.status_code}: {response.text}")
                return jsonify({"status": "error", "message": "Failed to verify KYC from DB"}), 500

        except Exception as e:
            print(f"CRITICAL KYC WEBHOOK EXCEPTION: {str(e)}")
            return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"status": "success"}), 200
    
@app.route('/api/webhook/supabase-posts', methods=['POST'])
def supabase_posts_webhook():
    data = request.get_json(silent=True) or {}
    
    if data.get('type') == 'INSERT':
        record = data.get('record', {})
        poster_user_id = str(record.get('user_id', ''))
        
        # Broadcast to everyone EXCEPT the poster (they already have it)
        for uid, sid in active_users.items():
            if uid != poster_user_id:
                socketio.emit('new_post_added', 
                    {"message": "New post added!"}, 
                    room=sid
                )
        
    return jsonify({"status": "success"}), 200

@app.route('/api/payout/initiate', methods=['POST'])
@jwt_required()
@limiter.limit("10 per hour")
def initiate_payout():
    try:
        user_id = get_jwt_identity()
        data = request.get_json(silent=True)

        if not data:
            return jsonify({"status": "error", "message": "Invalid request"}), 400

        amount = data.get('amount')
        customer_name = data.get('username')
        customer_email = data.get('email', 'customer@payme.app')
        recipient_id = data.get('recipient_id')
        
        if not recipient_id:
            return jsonify({"status": "error", "message": "Recipient ID is required"}), 400

        if not amount or not customer_name:
            return jsonify({"status": "error", "message": "Amount and username are required"}), 400

        try:
            amount = float(amount)
            if amount <= 0:
                raise ValueError
        except ValueError:
            return jsonify({"status": "error", "message": "Invalid amount"}), 400

        unique_reference = f"PAYME-{user_id[:8].upper()}-{uuid.uuid4().hex[:12].upper()}"

        payload = {
            "reference": unique_reference,
            "amount": amount,
            "currency": "NGN",
            "notification_url": f"{os.getenv('APP_BASE_URL')}/api/webhook/korapay",
            "customer": {
                "name": customer_name,
                "email": customer_email
            },
            "auto_complete": False
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.getenv('KORAPAY_SECRET_KEY')}"
        }

        response = requests.post(
            "https://api.korapay.com/merchant/api/v1/charges/bank-transfer",
            json=payload,
            headers=headers,
            timeout=10
        )

        response_data = response.json()

        if response.status_code == 200 and response_data.get('status') is True:
            bank = response_data['data']['bank_account']
            logging.info(f"Payout initiated for user {user_id}, reference: {unique_reference}")
            # Insert pending payment row into Supabase
            try:
                payments_url = f"{os.getenv('SUPABASE_URL')}/rest/v1/payments"
                payment_headers = {
                    "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
                    "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal"
                }
                payment_payload = {
                    "reference": unique_reference,
                    "payer_id": str(user_id),
                    "recipient_id": str(recipient_id),
                    "amount": amount,
                    "concluded": False,
                    "status": "pending"
                }
                pay_res = requests.post(payments_url, headers=payment_headers, json=payment_payload)
                if pay_res.status_code not in [200, 201]:
                    logging.error(f"Failed to insert payment row: {pay_res.text}")
            except Exception as pay_err:
                logging.error(f"Payment row insert error: {pay_err}")
            return jsonify({
                "status": "success",
                "reference": unique_reference,
                "amount_expected": response_data['data']['amount_expected'],
                "account_name": bank['account_name'],
                "account_number": bank['account_number'],
                "bank_name": bank['bank_name'],
                "expires_at": bank['expiry_date_in_utc']
            }), 200
        else:
            logging.error(f"Korapay error for user {user_id}: {response_data}")
            return jsonify({"status": "error", "message": "Payment provider error. Try again."}), 502

    except requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Payment provider timed out. Try again."}), 504
    except Exception as e:
        logging.error(f"Payout initiation error for user {user_id}: {e}")
        return jsonify({"status": "error", "message": "An internal error occurred"}), 500

@app.route('/api/webhook/korapay', methods=['POST'])
def korapay_webhook():
    try:
        received_sig = request.headers.get('X-Korapay-Signature', '')
        secret_key = os.getenv('KORAPAY_SECRET_KEY')

        data = request.get_json(silent=True)
        if not data:
            return jsonify({"status": "error", "message": "No payload"}), 400

        data_object = data.get('data', {})
        data_string = json.dumps(data_object, separators=(',', ':'), sort_keys=False)
        expected_sig = hmac.new(
            secret_key.encode('utf-8'),
            data_string.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        if received_sig and not hmac.compare_digest(received_sig, expected_sig):
            logging.warning("Korapay webhook signature mismatch")
            return jsonify({"status": "error", "message": "Invalid signature"}), 401

        event = data.get('event')
        payment_data = data.get('data', {})
        reference = payment_data.get('reference')
        status = payment_data.get('status')

        if not reference:
            return jsonify({"status": "error", "message": "No reference"}), 400

        if event != 'charge.success' or status != 'success':
            return jsonify({"status": "ok", "message": "Event ignored"}), 200

        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}",
            "Content-Type": "application/json"
        }

        pay_res = requests.get(
            f"{supabase_url}/rest/v1/payments?reference=eq.{reference}&select=*",
            headers=headers
        )
        if pay_res.status_code != 200 or not pay_res.json():
            logging.error(f"Korapay webhook: reference not found: {reference}")
            return jsonify({"status": "error", "message": "Reference not found"}), 404

        payment = pay_res.json()[0]

        if payment['status'] == 'success':
            logging.info(f"Korapay webhook: already confirmed: {reference}")
            return jsonify({"status": "ok", "message": "Already processed"}), 200

        update_res = requests.patch(
            f"{supabase_url}/rest/v1/payments?reference=eq.{reference}",
            headers=headers,
            json={
                "status": "success",
                "confirmed_at": datetime.now(timezone.utc).isoformat()
            }
        )
        if update_res.status_code not in [200, 204]:
            logging.error(f"Failed to update payment status: {update_res.text}")
            return jsonify({"status": "error", "message": "DB update failed"}), 500

        socketio.emit('payment_confirmed', {
            'reference': reference,
            'payer_id': payment['payer_id'],
            'recipient_id': payment['recipient_id'],
            'amount': str(payment['amount'])
        })

        # ── Push notification to recipient ─────────────────────────────────
        try:
            recipient_id = payment['recipient_id']
            payer_id = payment['payer_id']

            recipient_res = requests.get(
                f"{supabase_url}/rest/v1/users?id=eq.{recipient_id}&select=fcm_token",
                headers=headers
            )
            payer_res = requests.get(
                f"{supabase_url}/rest/v1/users?id=eq.{payer_id}&select=username,profile_pic_url",
                headers=headers
            )

            recipient_data = recipient_res.json()[0] if recipient_res.json() else {}
            payer_data = payer_res.json()[0] if payer_res.json() else {}

            recipient_token = recipient_data.get('fcm_token')
            payer_username = payer_data.get('username', 'Someone')
            payer_pic = payer_data.get('profile_pic_url', '')
            amount = payment['amount']

            if recipient_token:
                message = messaging.Message(
                    notification=messaging.Notification(
                        title='💰 Payment Received!',
                        body=f'{payer_username} paid ₦{amount} — funds are held in escrow until you both meet.',
                    ),
                    data={
                        'type': 'payment_received',
                        'sender_id': str(payer_id),
                        'sender_name': payer_username,
                        'sender_pic_url': payer_pic or '',
                        'amount': str(amount)
                    },
                    android=messaging.AndroidConfig(
                        notification=messaging.AndroidNotification(
                            image=payer_pic if payer_pic else None,
                        )
                    ),
                    webpush=messaging.WebpushConfig(
                        notification=messaging.WebpushNotification(
                            image=payer_pic if payer_pic else None,
                        )
                    ),
                    token=recipient_token,
                )
                messaging.send(message)
                logging.info(f"Payment notification sent to recipient {recipient_id}")
        except Exception as notif_err:
            logging.warning(f"Failed to send payment notification: {notif_err}")
        # ──────────────────────────────────────────────────────────────────

        logging.info(f"Payment confirmed and emitted for reference: {reference}")
        return jsonify({"status": "success"}), 200

    except Exception as e:
        logging.error(f"Korapay webhook error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/payments/check/<reference>', methods=['GET'])
@jwt_required()
def check_payment(reference):
    try:
        user_id = get_jwt_identity()
        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}"
        }
        res = requests.get(
            f"{supabase_url}/rest/v1/payments?reference=eq.{reference}&payer_id=eq.{user_id}&select=status",
            headers=headers
        )
        if res.status_code == 200 and res.json():
            return jsonify({"status": "success", "payment_status": res.json()[0]['status']}), 200
        return jsonify({"status": "error", "message": "Payment not found"}), 404
    except Exception as e:
        logging.error(f"Payment check error: {e}")
        return jsonify({"status": "error"}), 500

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
                'bank_no': bank_no,               # ✅ NEW
                'bank_institution': bank_institution  # ✅ NEW
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

# ==========================================
# ✨ PAYME POSTS FEED & WEBSOCKETS
# ==========================================

@app.route('/api/posts', methods=['GET'])
@jwt_required() # Keep this if you only want logged-in users to see the feed
def get_posts():
    try:
        # 1. Grab the ID of the person holding the phone
        current_user_id = get_jwt_identity()

        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/posts"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
        }
        
        # ✨ THE MAGIC FIX: Supabase JOIN in one query!
        # "*,users(username)" tells Supabase: 
        # "Get all post data (*), and JOIN the users table to get just the username"
        params = {
            "select": "*,users(username, longitude, latitude, price_naira, kyc)", 
            "order": "created_at.desc",     # Newest posts first
            "limit": "20"                   # Only grab 20 at a time to keep it lightning fast
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            posts = response.json()
            
            # --- ✨ THE NEW PERSONALIZATION LOGIC ✨ ---
            liked_post_ids = set()
            
            # Go ask the post_likes table what THIS user has liked
            likes_url = f"{os.getenv('SUPABASE_URL')}/rest/v1/post_likes"
            likes_params = {
                "user_id": f"eq.{current_user_id}",
                "select": "post_id"
            }
            likes_res = requests.get(likes_url, headers=headers, params=likes_params)
            
            if likes_res.status_code == 200:
                # Convert the response into a fast, searchable set of IDs
                likes_data = likes_res.json()
                liked_post_ids = {str(like['post_id']) for like in likes_data}

            # Loop through the feed and tag the ones they've liked!
            for post in posts:
                post_id_str = str(post.get('id'))
                post['is_liked'] = post_id_str in liked_post_ids
            # ------------------------------------------
            
            return jsonify({
                "success": True, 
                "posts": posts
            }), 200
        else:
            logging.error(f"Supabase fetch posts error: {response.text}")
            return jsonify({"success": False, "message": "Failed to load feed"}), 500

    except Exception as e:
        logging.error(f"Error fetching posts: {str(e)}")
        return jsonify({"success": False, "message": "Network error"}), 500

@app.route('/api/posts', methods=['POST'])
@jwt_required()
def create_post():
    data = request.get_json(silent=True) or {}
    poster_id = get_jwt_identity()
    price_res = requests.get(
        f"{os.getenv('SUPABASE_URL')}/rest/v1/users",
        headers={"apikey": os.getenv('SUPABASE_SERVICE_KEY'), "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"},
        params={"id": f"eq.{poster_id}", "select": "price_naira"}
    )
    price_naira = price_res.json()[0].get('price_naira', 0.0) if price_res.status_code == 200 and price_res.json() else 0.0
    
    video_url = data.get('video_url', '')
    caption = data.get('caption', '')
    target_gender = data.get('target_gender', 'Male')

    if not video_url:
        return jsonify({"status": "error", "message": "Video/Media URL is required"}), 400

    try:
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/posts"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json",
            "Prefer": "return=representation" 
        }
        
        payload = {
            "poster_id": str(poster_id),
            "video_url": video_url,
            "caption": caption,
            "target_gender": target_gender
        }
        
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code in (200, 201):
            new_post = response.json()[0]
            
            # --- THE MAGIC TRICK ---
            # Quickly fetch the user's data so the socket payload is 100% complete
            user_res = requests.get(
                f"{os.getenv('SUPABASE_URL')}/rest/v1/users",
                headers={"apikey": headers["apikey"], "Authorization": headers["Authorization"]},
                params={"id": f"eq.{poster_id}", "select": "username,profile_pic_url,price_naira"}
            )
            
            if user_res.status_code == 200 and len(user_res.json()) > 0:
                new_post['users'] = user_res.json()[0]
            else:
                new_post['users'] = {"username": "Unknown", "profile_pic_url": None}

            # ✨ Emit the FULL POST directly to all active apps!
            socketio.emit('new_post_added', {"post": new_post})
            
            return jsonify({"status": "success", "message": "Post published!", "post": new_post}), 201
        else:
            logging.error(f"Supabase create post error: {response.text}")
            return jsonify({"status": "error", "message": "Database action failed"}), 500

    except Exception as e:
        logging.error(f"Create post error: {e}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route('/api/posts/by_user/<string:user_id>', methods=['GET'])
@jwt_required()
def get_posts_by_user(user_id):
    """Returns every post belonging to a single user — powers the public profile grid."""
    try:
        supabase_url = os.getenv('SUPABASE_URL')
        supabase_key = os.getenv('SUPABASE_SERVICE_KEY')
        headers = {
            "apikey": supabase_key,
            "Authorization": f"Bearer {supabase_key}"
        }

        url = f"{supabase_url}/rest/v1/posts"
        params = {
            "poster_id": f"eq.{user_id}",
            "select": "*,users(username, profile_pic_url, kyc)",
            "order": "created_at.desc"
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            return jsonify({"success": True, "posts": response.json()}), 200
        else:
            logging.error(f"Supabase fetch user posts error: {response.text}")
            return jsonify({"success": False, "message": "Failed to load posts"}), 500

    except Exception as e:
        logging.error(f"get_posts_by_user error: {e}")
        return jsonify({"success": False, "message": "Internal server error"}), 500

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

        # ── 4.5. Re-sort by most recent activity ─────────────────────────────
        # Original RPC order only reflected message recency. Now that
        # payments can override the preview (step 3) or be the only reason
        # a conversation exists at all (step 1.5), we sort on the raw
        # datetime we tracked along the way instead of relying on row order.
        # Conversations with no timestamp at all sort to the bottom.
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
        bucket = storage.bucket()
        blob = bucket.blob(storage_path)
        signed_url = blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=15),
            method="PUT",
            content_type=mime_type,
        )
        public_url = f"https://storage.googleapis.com/{bucket.name}/{storage_path}"
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

        response = requests.post(url, headers=headers, json=payload)

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
            pay_res = requests.get(
                f"{os.getenv('SUPABASE_URL')}/rest/v1/payments",
                headers=pay_headers,
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
    reply_to_msg_id = data.get("reply_to_msg_id")
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
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            logging.error(f"Supabase Send RPC error: {response.text}")
            return jsonify({"status": "error", "message": "Failed to save message"}), 500

        db_data = response.json()
        is_stealth = db_data.get('is_stealth', False)
        sender_name = db_data.get('sender_name', 'Someone')
        target_token = db_data.get('fcm_token')

        # ---- Fetch sender profile pic (used in socket + push) ----
        sender_pic_url = None
        try:
            pic_res = requests.get(
                f"{os.getenv('SUPABASE_URL')}/rest/v1/users",
                headers={
                    "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
                    "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
                },
                params={"id": f"eq.{sender_id}", "select": "profile_pic_url"}
            )
            if pic_res.status_code == 200 and pic_res.json():
                sender_pic_url = pic_res.json()[0].get('profile_pic_url')
        except Exception as pic_err:
            logging.warning(f"Could not fetch sender pic: {pic_err}")

        # ---- Fetch real message ID ----
        message_id = None
        try:
            msg_res = requests.get(
                f"{os.getenv('SUPABASE_URL')}/rest/v1/messages",
                headers={
                    "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
                    "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
                },
                params={
                    "sender_id": f"eq.{sender_id}",
                    "receiver_id": f"eq.{receiver_id}",
                    "order": "sent_at.desc",
                    "limit": "1",
                    "select": "id"
                }
            )
            if msg_res.status_code == 200 and msg_res.json():
                message_id = msg_res.json()[0].get('id')
        except Exception as e:
            logging.error(f"Failed to fetch new message ID: {e}")

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

        # ---- Push notification (always fires if token exists) ----
        if target_token:
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

        return jsonify({
            "status": "success",
            "message": "Message sent",
            "is_stealth": is_stealth,
            "message_id": message_id
        }), 201

    except Exception as e:
        logging.error(f"Send message error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route("/api/messages/<int:message_id>", methods=["DELETE"])
@jwt_required()
def delete_message(message_id):
    current_user_id = get_jwt_identity()

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/messages"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
        }

        # 1. Fetch the message to check existence and ownership
        check_params = {
            "id": f"eq.{message_id}",
            "select": "sender_id"
        }
        check_response = requests.get(url, headers=headers, params=check_params)

        if check_response.status_code != 200:
            logging.error(f"Supabase GET message error: {check_response.text}")
            return jsonify({"status": "error", "message": "Database error"}), 500

        msg_data = check_response.json()

        if not msg_data or len(msg_data) == 0:
            return jsonify({"status": "error", "message": "Message not found"}), 404

        if str(msg_data[0].get('sender_id')) != str(current_user_id):
            return jsonify({"status": "error", "message": "Unauthorized"}), 403

        # 2. Issue the DELETE request
        delete_params = {
            "id": f"eq.{message_id}"
        }
        delete_response = requests.delete(url, headers=headers, params=delete_params)

        # Supabase usually returns 204 No Content for a successful deletion
        if delete_response.status_code in (200, 204):
            return jsonify({"status": "success", "message": "Message deleted successfully"}), 200
        else:
            logging.error(f"Supabase DELETE message error: {delete_response.text}")
            return jsonify({"status": "error", "message": "Failed to delete message"}), 500

    except Exception as e:
        logging.error(f"Delete message error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

# ==========================================
# ✨ GIF STASH API ENDPOINTS
# ==========================================

@app.route('/api/favorites/add', methods=['POST'])
@jwt_required()
def add_favorite_gif():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    user_id = data.get('user_id')
    gif_url = data.get('gif_url')

    if str(user_id) != get_jwt_identity():
        return jsonify({"status": "error", "message": "Unauthorized action"}), 403

    if not user_id or not gif_url:
        return jsonify({"status": "error", "message": "Missing user_id or gif_url"}), 400

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/favorite_gifs"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json",
            "Prefer": "return=minimal"  # Tells Supabase not to send the whole row back, saves bandwidth
        }

        payload = {
            "user_id": str(user_id),
            "gif_url": str(gif_url)
        }

        response = requests.post(url, headers=headers, json=payload)

        # 201 Created means the row was successfully inserted
        if response.status_code == 201:
            return jsonify({"status": "success", "message": "GIF added to favorites"}), 201

        # 409 Conflict means the UNIQUE(user_id, gif_url) constraint caught a duplicate
        elif response.status_code == 409:
            return jsonify({"status": "exists", "message": "GIF is already in favorites"}), 200

        else:
            logging.error(f"Supabase add favorite GIF error: {response.text}")
            return jsonify({"status": "error", "message": "Database action failed"}), 500

    except Exception as e:
        logging.error(f"Add favorite GIF error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

@app.route('/api/favorites/<string:user_id>', methods=['GET'])
@jwt_required()
def get_favorite_gifs(user_id):
    if str(user_id) != get_jwt_identity():
        return jsonify({"status": "error", "message": "Unauthorized action"}), 403

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/favorite_gifs"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
        }

        # Map the SQL query directly into URL parameters
        params = {
            "user_id": f"eq.{user_id}",
            "select": "id,gif_url",
            "order": "created_at.desc"
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            gifs = response.json()
            return jsonify(gifs), 200
        else:
            logging.error(f"Supabase GET favorite GIFs error: {response.text}")
            return jsonify({"status": "error", "message": "Database error"}), 500

    except Exception as e:
        logging.error(f"Get favorite GIFs error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500


# ✨ NEW: The missing DELETE route for your Triple-Tap Stash Removal!
@app.route('/api/favorites/remove', methods=['DELETE'])
@jwt_required()
def remove_favorite_gif():
    data = request.get_json(silent=True)
    if not data or not data.get('url'):
        return jsonify({"status": "error", "message": "Invalid request"}), 400

    user_id = get_jwt_identity()
    gif_url = data.get('url')

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/favorite_gifs"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
        }

        # Map the WHERE clause directly into URL parameters
        params = {
            "user_id": f"eq.{user_id}",
            "gif_url": f"eq.{gif_url}"
        }

        response = requests.delete(url, headers=headers, params=params)

        # PostgREST usually returns 204 No Content for a successful deletion
        if response.status_code in (200, 204):
            return jsonify({"status": "success", "message": "Removed from stash"}), 200
        else:
            logging.error(f"Supabase remove favorite GIF error: {response.text}")
            return jsonify({"status": "error", "message": "Database action failed"}), 500

    except Exception as e:
        logging.error(f"Remove favorite GIF error: {e}")
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

@app.route("/api/set_stealth_mode", methods=["POST"])
@jwt_required()
def set_stealth_mode():
    data = request.get_json(silent=True) or {}
    user_id = data.get("user_id")
    other_id = data.get("other_id")

    # Safely parse the stealth value (handle 1/0 or true/false)
    raw_stealth = data.get("delete_after_read")
    is_stealth = True if str(raw_stealth).lower() in ['1', 'true'] else False

    # Security check: Ensure the requester is who they say they are
    if str(user_id) != str(get_jwt_identity()):
        return jsonify({"status": "error", "message": "Unauthorized"}), 403

    try:
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/conversation_prefs"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json"
        }

        if str(other_id) == "0":
            # ✨ THE GLOBAL KILL-SWITCH (HTTPS PATCH)
            # Updates every row where user_id OR other_id matches this user
            params = {
                "or": f"(user_id.eq.{user_id},other_id.eq.{user_id})"
            }
            payload = {
                "stealth_on": is_stealth
            }
            response = requests.patch(url, headers=headers, params=params, json=payload)

        else:
            # ✨ STANDARD MUTUAL TOGGLE (Bulk UPSERT)
            # We send both rows in an array, and Supabase merges them instantly
            headers["Prefer"] = "resolution=merge-duplicates"
            payload = [
                {"user_id": str(user_id), "other_id": str(other_id), "stealth_on": is_stealth},
                {"user_id": str(other_id), "other_id": str(user_id), "stealth_on": is_stealth}
            ]
            response = requests.post(url, headers=headers, json=payload)

        # PostgREST returns 200, 201, or 204 on success depending on exact operation
        if response.status_code in (200, 201, 204):
            # Return the raw_stealth back so Flutter gets exactly what it expects (e.g., 1 or 0)
            return jsonify({"status": "success", "mode": raw_stealth}), 200
        else:
            logging.error(f"Supabase stealth toggle error: {response.text}")
            return jsonify({"status": "error", "message": "Database action failed"}), 500

    except Exception as e:
        logging.error(f"Stealth toggle error: {e}")
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

@app.route('/api/user/<string:user_id>/premium', methods=['GET'])
@jwt_required()
def check_premium_status(user_id):
    """Check if a user has premium status"""
    if str(user_id) != get_jwt_identity():
        return jsonify({"status": "error", "message": "Unauthorized action"}), 403

    try:
        # ✨ HTTPS FIREWALL BYPASS ✨
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/users"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
        }

        # Ask Supabase to only SELECT the is_premium column WHERE id = user_id
        params = {
            "id": f"eq.{user_id}",
            "select": "is_premium"
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json()
            is_premium = False

            # If we got data back, read the boolean value
            if data and len(data) > 0:
                is_premium = bool(data[0].get('is_premium', False))

            return jsonify({
                "status": "success",
                "is_premium": is_premium
            }), 200
        else:
            logging.error(f"Supabase check premium error: {response.text}")
            return jsonify({"status": "error", "message": "Database error"}), 500

    except Exception as e:
        logging.error(f"Check premium error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500
