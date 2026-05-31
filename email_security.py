import requests
import os
from dotenv import load_dotenv

load_dotenv(os.path.expanduser("~/flas/.env"))
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
BREVO_SEND_URL = "https://api.brevo.com/v3/smtp/email"
SENDER_EMAIL = "msuleiman857@gmail.com"
APP_NAME = "PayMe"

def send_reset_email(email, reset_code):
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }

    data = {
        "sender": {"name": APP_NAME, "email": SENDER_EMAIL},
        "to": [{"email": email}],
        "subject": f"Your {APP_NAME} Password Reset Code",
        "htmlContent": f"""
        <!DOCTYPE html>
        <html>
          <head>
            <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
          </head>
          <body style="margin:0; padding:0; background-color:#F9F9F9; font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;">
            <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="padding: 40px 20px;">
              <tr>
                <td align="center">
                  <table border="0" cellpadding="0" cellspacing="0" width="100%"
                         style="max-width: 600px; background-color:#FFFFFF; border-radius:20px; overflow:hidden; box-shadow: 0 20px 40px -15px rgba(156,184,152,0.15);">

                    <tr>
                      <td style="padding: 40px 40px 20px 40px;">
                        <span style="font-size: 28px; font-weight: 700; color: #9CB898; letter-spacing: -1px;">
                          {APP_NAME}.
                        </span>
                      </td>
                    </tr>

                    <tr>
                      <td style="padding: 0 40px 20px 40px;">
                        <p style="margin: 0 0 8px 0; font-size: 11px; font-weight: 500; letter-spacing: 0.18em; color: #EE8980; text-transform: uppercase;">
                          ACCOUNT · RECOVERY
                        </p>
                        
                        <h1 style="margin: 0 0 16px 0; font-size: 36px; line-height: 1.1;">
                          <span style="font-weight: 300; color: #9CB898;">Forgot</span> 
                          <span style="font-weight: 700; color: #F14666;">Password?</span>
                        </h1>
                        
                        <p style="margin: 0 0 32px 0; font-size: 15px; color: #1A1C20; line-height: 1.6; font-weight: 400;">
                          We received a request to reset the password for your {APP_NAME} account. Enter the secure 6-digit code below to continue. This code will expire in <strong>10 minutes</strong>.
                        </p>

                        <table border="0" cellpadding="0" cellspacing="0" width="100%">
                          <tr>
                            <td align="center" style="background-color: #FFFDFB; padding: 32px; border-radius: 12px; border: 2px solid #F14666;">
                              <span style="display: block; font-size: 12px; font-weight: 600; letter-spacing: 1px; color: #EE8980; margin-bottom: 12px; text-transform: uppercase;">
                                Secure Reset Code
                              </span>
                              <span style="display: inline-block; font-size: 42px; font-weight: 700; letter-spacing: 12px; color: #1A1C20;">
                                {reset_code}
                              </span>
                            </td>
                          </tr>
                        </table>

                        <p style="margin: 32px 0 0 0; font-size: 14px; color: #9CB898; line-height: 1.5;">
                          If you didn't request this action, you can safely ignore this email. Your account remains secure.
                        </p>
                      </td>
                    </tr>

                    <tr>
                      <td align="left" style="padding: 30px 40px; background-color: #FFFFFF; border-top: 1px solid rgba(156,184,152,0.15);">
                        <p style="margin: 0; font-size: 12px; color: #9CB898; font-weight: 500;">
                          &copy; 2026 {APP_NAME}. All rights reserved.
                        </p>
                      </td>
                    </tr>

                  </table>
                </td>
              </tr>
            </table>
          </body>
        </html>
        """
    }

    try:
        response = requests.post(BREVO_SEND_URL, headers=headers, json=data)
        if response.status_code == 201:
            print("✅ Password reset email sent successfully!")
        else:
            print(f"❌ Failed to send reset email: {response.status_code} → {response.text}")    
    except Exception as e:
        print(f"⚠️ Error sending reset email: {e}")


def send_verify_email(email, verify_code):
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }

    data = {
        "sender": {"name": APP_NAME, "email": SENDER_EMAIL},
        "to": [{"email": email}],
        "subject": f"Verify your {APP_NAME} Email Address",
        "htmlContent": f"""
        <!DOCTYPE html>
        <html>
          <head>
            <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
          </head>
          <body style="margin:0; padding:0; background-color:#F9F9F9; font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;">
            <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="padding: 40px 20px;">
              <tr>
                <td align="center">
                  <table border="0" cellpadding="0" cellspacing="0" width="100%"
                         style="max-width: 600px; background-color:#FFFFFF; border-radius:20px; overflow:hidden; box-shadow: 0 40px 40px -15px rgba(156,184,152,0.15);">

                    <tr>
                      <td style="padding: 40px 40px 20px 40px;">
                        <span style="font-size: 28px; font-weight: 700; color: #9CB898; letter-spacing: -1px;">
                          {APP_NAME}.
                        </span>
                      </td>
                    </tr>

                    <tr>
                      <td style="padding: 0 40px 20px 40px;">
                        <p style="margin: 0 0 8px 0; font-size: 11px; font-weight: 500; letter-spacing: 0.18em; color: #EE8980; text-transform: uppercase;">
                          SECURITY · VERIFY
                        </p>
                        
                        <h1 style="margin: 0 0 16px 0; font-size: 36px; line-height: 1.1;">
                          <span style="font-weight: 300; color: #9CB898;">Check Your</span> 
                          <span style="font-weight: 700; color: #F14666;">Email</span>
                        </h1>
                        
                        <p style="margin: 0 0 32px 0; font-size: 15px; color: #1A1C20; line-height: 1.6; font-weight: 400;">
                          We need to verify the email address for your {APP_NAME} account. Enter the secure 6-digit code below to unlock full access. This code will expire in <strong>10 minutes</strong>.
                        </p>

                        <table border="0" cellpadding="0" cellspacing="0" width="100%">
                          <tr>
                            <td align="center" style="background-color: #FEF6F5; padding: 32px; border-radius: 12px; border: 2px solid #EE8980;">
                              <span style="display: block; font-size: 12px; font-weight: 600; letter-spacing: 1px; color: #EE8980; margin-bottom: 12px; text-transform: uppercase;">
                                Verification Code
                              </span>
                              <span style="display: inline-block; font-size: 42px; font-weight: 700; letter-spacing: 12px; color: #1A1C20;">
                                {verify_code}
                              </span>
                            </td>
                          </tr>
                        </table>

                        <p style="margin: 32px 0 0 0; font-size: 14px; color: #9CB898; line-height: 1.5;">
                          If you didn't create an account with {APP_NAME}, you can safely delete this email.
                        </p>
                      </td>
                    </tr>

                    <tr>
                      <td align="left" style="padding: 30px 40px; background-color: #FFFFFF; border-top: 1px solid rgba(156,184,152,0.15);">
                        <p style="margin: 0; font-size: 12px; color: #9CB898; font-weight: 500;">
                          &copy; 2026 {APP_NAME}. All rights reserved.
                        </p>
                      </td>
                    </tr>

                  </table>
                </td>
              </tr>
            </table>
          </body>
        </html>
        """
    }

    try:
        response = requests.post(BREVO_SEND_URL, headers=headers, json=data)
        if response.status_code == 201:
            print("✅ Verification email sent successfully!")
        else:
            print(f"❌ Failed to send verification email: {response.status_code} → {response.text}")
    except Exception as e:
        print(f"⚠️ Error sending verification email: {e}")
