import requests
import os
from dotenv import load_dotenv

load_dotenv(os.path.expanduser("~/flas/.env"))
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
BREVO_SEND_URL = "https://api.brevo.com/v3/smtp/email"

# Defaults only — every value below can be overridden per call, so this
# same file works for any app, not just this one.
DEFAULT_APP_NAME = "sapahost"
DEFAULT_SENDER_EMAIL = "msuleiman857@gmail.com"

# Monochrome palette — black/white/gray only.
DEFAULT_TEXT_COLOR = "#1A1C20"
DEFAULT_MUTED_COLOR = "#6B6F76"
DEFAULT_BORDER_COLOR = "#1A1C20"
DEFAULT_BACKGROUND_COLOR = "#F5F5F5"


def _build_otp_email_html(
    app_name,
    code,
    text_color,
    muted_color,
    border_color,
    background_color,
):
    """Shared OTP email template. Deliberately generic — no mention of
    what the code is for (reset, verify, login, etc.), just a clean,
    professional 'your requested code' layout."""
    return f"""
    <!DOCTYPE html>
    <html>
      <head>
        <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
      </head>
      <body style="margin:0; padding:0; background-color:{background_color}; font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;">
        <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="padding: 40px 20px;">
          <tr>
            <td align="center">
              <table border="0" cellpadding="0" cellspacing="0" width="100%"
                     style="max-width: 600px; background-color:#FFFFFF; border-radius:12px; overflow:hidden; border: 1px solid #E5E5E5;">

                <tr>
                  <td style="padding: 40px 40px 20px 40px;">
                    <span style="font-size: 24px; font-weight: 700; color: {text_color}; letter-spacing: -0.5px;">
                      {app_name}
                    </span>
                  </td>
                </tr>

                <tr>
                  <td style="padding: 0 40px 20px 40px;">
                    <p style="margin: 0 0 24px 0; font-size: 15px; color: {text_color}; line-height: 1.6; font-weight: 400;">
                      Your requested code is below. This code will expire in <strong>10 minutes</strong>.
                    </p>

                    <table border="0" cellpadding="0" cellspacing="0" width="100%">
                      <tr>
                        <td align="center" style="background-color: #FFFFFF; padding: 32px; border-radius: 8px; border: 1px solid {border_color};">
                          <span style="display: inline-block; font-size: 40px; font-weight: 700; letter-spacing: 12px; color: {text_color};">
                            {code}
                          </span>
                        </td>
                      </tr>
                    </table>

                    <p style="margin: 32px 0 0 0; font-size: 14px; color: {muted_color}; line-height: 1.5;">
                      If you didn't request this code, you can safely ignore this email.
                    </p>
                  </td>
                </tr>

                <tr>
                  <td align="left" style="padding: 30px 40px; background-color: #FFFFFF; border-top: 1px solid #E5E5E5;">
                    <p style="margin: 0; font-size: 12px; color: {muted_color}; font-weight: 500;">
                      &copy; 2026 {app_name}. All rights reserved.
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


def _send(email, subject, html_content, sender_name, sender_email):
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json",
    }
    data = {
        "sender": {"name": sender_name, "email": sender_email},
        "to": [{"email": email}],
        "subject": subject,
        "htmlContent": html_content,
    }
    try:
        response = requests.post(BREVO_SEND_URL, headers=headers, json=data)
        if response.status_code == 201:
            print(f"✅ Email sent successfully to {email}")
            return True
        print(f"❌ Failed to send email: {response.status_code} → {response.text}")
        return False
    except Exception as e:
        print(f"⚠️ Error sending email: {e}")
        return False


def send_reset_email(
    email,
    reset_code,
    app_name=DEFAULT_APP_NAME,
    sender_email=DEFAULT_SENDER_EMAIL,
    text_color=DEFAULT_TEXT_COLOR,
    muted_color=DEFAULT_MUTED_COLOR,
    border_color=DEFAULT_BORDER_COLOR,
    background_color=DEFAULT_BACKGROUND_COLOR,
):
    html = _build_otp_email_html(
        app_name=app_name,
        code=reset_code,
        text_color=text_color,
        muted_color=muted_color,
        border_color=border_color,
        background_color=background_color,
    )
    return _send(email, f"Your {app_name} code", html, app_name, sender_email)


def send_verify_email(
    email,
    verify_code,
    app_name=DEFAULT_APP_NAME,
    sender_email=DEFAULT_SENDER_EMAIL,
    text_color=DEFAULT_TEXT_COLOR,
    muted_color=DEFAULT_MUTED_COLOR,
    border_color=DEFAULT_BORDER_COLOR,
    background_color=DEFAULT_BACKGROUND_COLOR,
):
    html = _build_otp_email_html(
        app_name=app_name,
        code=verify_code,
        text_color=text_color,
        muted_color=muted_color,
        border_color=border_color,
        background_color=background_color,
    )
    return _send(email, f"Your {app_name} code", html, app_name, sender_email)
