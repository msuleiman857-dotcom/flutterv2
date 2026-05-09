import requests
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os
import random
import string
import logging

load_dotenv(os.path.expanduser("~/flas/.env"))
RESET_LIMIT_PER_HOUR = 4

# ✨ HELPER FUNCTIONS FOR REST API
def get_headers():
    return {
        "apikey": os.getenv('SUPABASE_SERVICE_KEY'),
        "Authorization": f"Bearer {os.getenv('SUPABASE_SERVICE_KEY')}",
        "Content-Type": "application/json"
    }

def get_url():
    return os.getenv('SUPABASE_URL')

def create_connection():
    # We return a dummy string so if your old routes check `if not conn:`, it passes!
    # (But you still need to eventually rewrite old routes that use .cursor())
    return "dummy_https_connection"

def execute_add(conn, user_id, email, username, password):
    url = f"{get_url()}/rest/v1/users"
    payload = {
        "id": user_id,
        "email": email,
        "username": username,
        "password": password
    }
    try:
        response = requests.post(url, headers=get_headers(), json=payload)
        response.raise_for_status()
    except Exception as e:
        print(f"Query failed: {e}")
        # Re-raise to match your original retry/error logic
        raise e

def execute_send(conn, sender_id, receiver_id, message_content, media_content, reply_to_msg_id, is_stealth):
    url = f"{get_url()}/rest/v1/messages"
    should_delete = True if is_stealth else False
    
    payload = {
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "message_content": message_content,
        "reply_to_msg_id": reply_to_msg_id,
        "media_content": media_content,
        "delete_after_read": should_delete
    }
    
    try:
        response = requests.post(url, headers=get_headers(), json=payload)
        response.raise_for_status()
        return True
    except Exception as e:
        print(f"Error: {e}")
        return False

def update_typing_status(conn, sender_id, receiver_id, is_typing, typing_text=""):
    url = f"{get_url()}/rest/v1/typing_status"
    headers = get_headers()
    typing_bool = True if str(is_typing).lower() == 'true' else False

    try:
        if not typing_bool or not typing_text:
            # DELETE REQUEST
            params = {
                "sender_id": f"eq.{sender_id}",
                "receiver_id": f"eq.{receiver_id}"
            }
            requests.delete(url, headers=headers, params=params)
        else:
            # UPSERT REQUEST (Insert or Update)
            headers["Prefer"] = "resolution=merge-duplicates"
            payload = {
                "sender_id": sender_id,
                "receiver_id": receiver_id,
                "is_typing": True,
                "typing_text": typing_text,
                "updated_at": datetime.now().isoformat()
            }
            requests.post(url, headers=headers, json=payload)
        return True
    except Exception as e:
        print(f"Typing status update error: {e}")
        return False

def generate_reset_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def can_request_reset(email):
    url = f"{get_url()}/rest/v1/password_reset_requests"
    one_hour_ago = (datetime.now() - timedelta(hours=1)).isoformat()
    
    params = {
        "email": f"eq.{email}",
        "request_time": f"gt.{one_hour_ago}",
        "select": "id"  # We only need to count the rows, not fetch all data
    }
    
    try:
        response = requests.get(url, headers=get_headers(), params=params)
        if response.status_code == 200:
            data = response.json()
            return len(data) < RESET_LIMIT_PER_HOUR
        return False
    except Exception as e:
        print(f"Reset check error: {e}")
        return False

def log_reset_request(email):
    url = f"{get_url()}/rest/v1/password_reset_requests"
    payload = {
        "email": email,
        "request_time": datetime.now().isoformat()
    }
    try:
        requests.post(url, headers=get_headers(), json=payload)
    except Exception as e:
        print(f"Log reset error: {e}")