import os
os.environ['EVENTLET_NO_GREENDNS'] = 'yes'

import eventlet
eventlet.monkey_patch()

from flask import Flask, request, jsonify
from database_connector import generate_reset_code
from flask_limiter import Limiter
from flask_socketio import SocketIO
from flask_limiter.util import get_remote_address
import logging
import requests
from dotenv import load_dotenv
from email_security import send_reset_email, send_verify_email
from datetime import datetime, timedelta, timezone
from flask_cors import CORS
import firebase_admin
from firebase_admin import credentials, messaging
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from cryptography.fernet import Fernet
import uuid    
from security import (
    hash_password, is_valid_email_format, is_valid_username,
    verify_bot_token, generate_pow_challenge, verify_pow, is_suspicious_request,
    dummy_verify, verify_password
)

load_dotenv(os.path.expanduser("~/flas/.env"))

FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FIREBASE_KEY_PATH = os.path.join(BASE_DIR, "flutterv2", "firebase", "firebase-key.json")
if not firebase_admin._apps:
    try:
        cred = credentials.Certificate(FIREBASE_KEY_PATH)
        firebase_admin.initialize_app(cred)
        print("🔥 Firebase initialized successfully!")
    except Exception as e:
        print(f"⚠️ Firebase initialization failed: {e}")

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

try:
    if FIREBASE_KEY_PATH and os.path.exists(FIREBASE_KEY_PATH):
        cred = credentials.Certificate(FIREBASE_KEY_PATH)
        firebase_admin.initialize_app(cred)
        print("🔥 Firebase Admin initialized successfully!")
    else:
        print("⚠️ Firebase init failed: Path not found or not set in .env")
except Exception as e:
    print(f"⚠️ Firebase init failed (Check your JSON file): {e}")

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
        if str(sender_id) in active_users:
            sender_sid = active_users[str(sender_id)]
            socketio.emit('message_read_update', {
                'message_id': message_id
            }, room=sender_sid)
            
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

@app.route('/api/webhook/supabase-posts', methods=['POST'])
def supabase_posts_webhook():
    data = request.get_json(silent=True) or {}
    
    # Check if a new row was inserted into Supabase
    if data.get('type') == 'INSERT':
        # Emit the event to all Flutter apps!
        # Flutter just uses this to run _fetchFeed(), so the payload structure doesn't matter much
        socketio.emit('new_post_added', {"message": "New post added in Supabase!"})
        
    return jsonify({"status": "success"}), 200

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

    # 2. PROOF OF WORK VERIFICATION
    # if not verify_pow(pow_challenge_id, pow_answer):
    #     logging.warning(f"Failed PoW challenge from IP: {client_ip}")
    #     return jsonify({"status": "error", "message": "Security verification failed."}), 403

    # 3. BOT PROTECTION
    # if not verify_bot_token(bot_token, client_ip):
    #     logging.warning(f"Failed bot challenge from IP: {client_ip}")
    #     return jsonify({"status": "error", "message": "Security verification failed."}), 403

    # Input length limits to prevent extreme payload DoS
    if len(identifier) < 3 or not (1 <= len(password) <= 128):
        return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

    try:
        # ✨ NEW SUPABASE HTTPS BYPASS ✨
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
            logging.info(f"Successful login for user ID: {user['id']}")

            return jsonify({
                'status': 'success',
                'username': user['username'],
                'id': user['id'],
                'access_token': access_token
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
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/posts"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
        }
        
        # ✨ THE MAGIC FIX: Supabase JOIN in one query!
        # "*,users(username)" tells Supabase: 
        # "Get all post data (*), and JOIN the users table to get just the username"
        params = {
            "select": "*,users(username)", 
            "order": "created_at.desc",     # Newest posts first
            "limit": "20"                   # Only grab 20 at a time to keep it lightning fast
        }

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            posts = response.json()
            
            # (Optional) Flatten the data so Flutter reads it easily
            # Supabase returns users as a nested dictionary: {"users": {"username": "John"}}
            # Flutter expects it the exact way you wrote it in post_feed.dart, so this is perfect!
            
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
    
    video_url = data.get('video_url', '')
    caption = data.get('caption', '')
    target_gender = data.get('target_gender', 'Male')
    price_naira = data.get('price_naira', 0.0)

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
            "target_gender": target_gender,
            "price_naira": price_naira
        }
        
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code in (200, 201):
            new_post = response.json()[0]
            
            # --- THE MAGIC TRICK ---
            # Quickly fetch the user's data so the socket payload is 100% complete
            user_res = requests.get(
                f"{os.getenv('SUPABASE_URL')}/rest/v1/users",
                headers={"apikey": headers["apikey"], "Authorization": headers["Authorization"]},
                params={"id": f"eq.{poster_id}", "select": "username,profile_pic_url"}
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

@app.route('/api/conversations/<string:user_id>', methods=['GET'])
@jwt_required()
def get_conversations(user_id):
    if str(user_id) != get_jwt_identity():
        return jsonify({"status": "error", "message": "Unauthorized action"}), 403

    try:
        # ✨ THE HTTPS FIREWALL BYPASS ✨
        url = f"{os.getenv('SUPABASE_URL')}/rest/v1/rpc/get_user_conversations"
        headers = {
            "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
            "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
            "Content-Type": "application/json"
        }

        # Tell the Supabase database function which user we are looking up
        payload = {"p_user_id": user_id}

        # Send the request over standard Port 443 Web Traffic!
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            logging.error(f"Supabase RPC error: {response.text}")
            return jsonify({"status": "error", "message": "Database error"}), 500

        conversations = response.json()

        # You might need to update this to the HTTPS version too if it still uses cursors!
        current_user_premium = bool(is_premium_user(None, user_id))

        # Format the data for Flutter exactly like before
        for conv in conversations:
            if conv.get('last_msg_time'):
                dt = parse_supabase_ts(conv['last_msg_time'])
                conv['last_msg_time'] = dt.strftime('%H:%M')

            conv['is_other_typing'] = bool(conv.get('is_other_typing', False))
            conv['is_read'] = bool(conv.get('is_read', False))
            conv['is_premium'] = bool(conv.get('is_premium', False))

            if not current_user_premium:
                conv['other_typing_text'] = None

            if conv.get('message_content') and fernet:
                try:
                    conv['message_content'] = fernet.decrypt(conv['message_content'].encode()).decode()
                except:
                    pass

        return jsonify({
            "status": "success",
            "conversations": conversations,
            "current_user_is_premium": current_user_premium
        }), 200

    except Exception as e:
        logging.error(f"Get conversations error: {e}")
        return jsonify({"status": "error", "message": "An internal server error occurred"}), 500

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

    # Clean up the reply ID logic
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

    # ---- Insert the message via RPC ----
    try:
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

        # ---- 🔍 Fetch the real message ID (the one just inserted) ----
        message_id = None
        try:
            url_msg = f"{os.getenv('SUPABASE_URL')}/rest/v1/messages"
            headers_msg = {
                "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
                "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}"
            }
            params_msg = {
                "sender_id": f"eq.{sender_id}",
                "receiver_id": f"eq.{receiver_id}",
                "order": "sent_at.desc",
                "limit": "1",
                "select": "id"
            }
            msg_res = requests.get(url_msg, headers=headers_msg, params=params_msg)
            if msg_res.status_code == 200:
                msg_data = msg_res.json()
                if msg_data and len(msg_data) > 0:
                    message_id = msg_data[0].get('id')
        except Exception as e:
            logging.error(f"Failed to fetch new message ID: {e}")

        # ---- WebSocket delivery (if receiver is online) ----
        receiver_id_str = str(receiver_id)

        if receiver_id_str in active_users:
            try:
                receiver_sid = active_users[receiver_id_str]
                socket_payload = {
                    "id": message_id,                     # ✅ Added real ID
                    "sender_id": str(sender_id),
                    "sender_name": sender_name,
                    "message": message_content,
                    "media_content": media_content,
                    "reply_to_msg_id": reply_to_msg_id,
                    "is_stealth": is_stealth
                }
                socketio.emit('receive_message', socket_payload, to=receiver_sid)

                # Also notify the sender with the same payload (or just the ID)
                sender_sid = active_users.get(str(sender_id))
                if sender_sid:
                    socketio.emit('message_sent_success', {
                        "id": message_id                 # Sender only needs the ID
                    }, to=sender_sid)

                print(f"Message delivered via WebSocket to {receiver_id}")
            except Exception as e:
                logging.error(f"WebSocket delivery failed: {e}")

        elif target_token:
            # Offline: Firebase push
            try:
                if is_stealth:
                    display_body = "🕶️ Ultra Stealth Message received"
                else:
                    display_body = message_content if message_content else "📎 Sent an attachment"
                    if reply_to_msg_id:
                        display_body = f"↩️ Replying: {display_body}"

                push_msg = messaging.Message(
                    notification=messaging.Notification(
                        title=f"New message from {sender_name}",
                        body=display_body
                    ),
                    data={
                        "type": "chat_message",
                        "sender_id": str(sender_id),
                        "is_stealth": "true" if is_stealth else "false"
                    },
                    token=target_token,
                )
                messaging.send(push_msg)
            except Exception as e:
                logging.error(f"Firebase error: {e}")

        # ---- Final HTTP response with the real ID ----
        return jsonify({
            "status": "success",
            "message": "Message sent",
            "is_stealth": is_stealth,
            "message_id": message_id        # Now it's the real ID
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

