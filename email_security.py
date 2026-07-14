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
DEFAULT_PRIMARY_COLOR = "#9CB898"     # headline accent / footer text
DEFAULT_ACCENT_COLOR = "#F14666"      # bold headline word / code box border
DEFAULT_TAG_COLOR = "#EE8980"         # eyebrow label + code label
DEFAULT_BACKGROUND_COLOR = "#F9F9F9"


def _build_otp_email_html(
    app_name,
    eyebrow,
    heading_light,
    heading_bold,
    body_text,
    code,
    code_label,
    footer_text,
    primary_color,
    accent_color,
    tag_color,
    background_color,
):
    """Shared OTP email template. Any two-word heading + code layout can
    reuse this — reset code, verify code, login code, whatever."""
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
                     style="max-width: 600px; background-color:#FFFFFF; border-radius:20px; overflow:hidden; box-shadow: 0 20px 40px -15px rgba(0,0,0,0.12);">

                <tr>
                  <td style="padding: 40px 40px 20px 40px;">
                    <span style="font-size: 28px; font-weight: 700; color: {primary_color}; letter-spacing: -1px;">
                      {app_name}.
                    </span>
                  </td>
                </tr>

                <tr>
                  <td style="padding: 0 40px 20px 40px;">
                    <p style="margin: 0 0 8px 0; font-size: 11px; font-weight: 500; letter-spacing: 0.18em; color: {tag_color}; text-transform: uppercase;">
                      {eyebrow}
                    </p>

                    <h1 style="margin: 0 0 16px 0; font-size: 36px; line-height: 1.1;">
                      <span style="font-weight: 300; color: {primary_color};">{heading_light}</span>
                      <span style="font-weight: 700; color: {accent_color};"> {heading_bold}</span>
                    </h1>

                    <p style="margin: 0 0 32px 0; font-size: 15px; color: #1A1C20; line-height: 1.6; font-weight: 400;">
                      {body_text}
                    </p>

                    <table border="0" cellpadding="0" cellspacing="0" width="100%">
                      <tr>
                        <td align="center" style="background-color: #FFFDFB; padding: 32px; border-radius: 12px; border: 2px solid {accent_color};">
                          <span style="display: block; font-size: 12px; font-weight: 600; letter-spacing: 1px; color: {tag_color}; margin-bottom: 12px; text-transform: uppercase;">
                            {code_label}
                          </span>
                          <span style="display: inline-block; font-size: 42px; font-weight: 700; letter-spacing: 12px; color: #1A1C20;">
                            {code}
                          </span>
                        </td>
                      </tr>
                    </table>

                    <p style="margin: 32px 0 0 0; font-size: 14px; color: {primary_color}; line-height: 1.5;">
                      {footer_text}
                    </p>
                  </td>
                </tr>

                <tr>
                  <td align="left" style="padding: 30px 40px; background-color: #FFFFFF; border-top: 1px solid rgba(0,0,0,0.06);">
                    <p style="margin: 0; font-size: 12px; color: {primary_color}; font-weight: 500;">
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
    primary_color=DEFAULT_PRIMARY_COLOR,
    accent_color=DEFAULT_ACCENT_COLOR,
    tag_color=DEFAULT_TAG_COLOR,
    background_color=DEFAULT_BACKGROUND_COLOR,
):
    html = _build_otp_email_html(
        app_name=app_name,
        eyebrow="ACCOUNT · RECOVERY",
        heading_light="Forgot",
        heading_bold="Password?",
        body_text=(
            f"We received a request to reset the password for your {app_name} account. "
            f"Enter the secure 6-digit code below to continue. This code will expire in "
            f"<strong>10 minutes</strong>."
        ),
        code=reset_code,
        code_label="Secure Reset Code",
        footer_text="If you didn't request this action, you can safely ignore this email. Your account remains secure.",
        primary_color=primary_color,
        accent_color=accent_color,
        tag_color=tag_color,
        background_color=background_color,
    )
    return _send(email, f"Your {app_name} Password Reset Code", html, app_name, sender_email)


def send_verify_email(
    email,
    verify_code,
    app_name=DEFAULT_APP_NAME,
    sender_email=DEFAULT_SENDER_EMAIL,
    primary_color=DEFAULT_PRIMARY_COLOR,
    accent_color=DEFAULT_ACCENT_COLOR,
    tag_color=DEFAULT_TAG_COLOR,
    background_color=DEFAULT_BACKGROUND_COLOR,
):
    html = _build_otp_email_html(
        app_name=app_name,
        eyebrow="SECURITY · VERIFY",
        heading_light="Check Your",
        heading_bold="Email",
        body_text=(
            f"We need to verify the email address for your {app_name} account. "
            f"Enter the secure 6-digit code below to unlock full access. This code will expire in "
            f"<strong>10 minutes</strong>."
        ),
        code=verify_code,
        code_label="Verification Code",
        footer_text=f"If you didn't create an account with {app_name}, you can safely delete this email.",
        primary_color=primary_color,
        accent_color=accent_color,
        tag_color=tag_color,
        background_color=background_color,
    )
    return _send(email, f"Verify your {app_name} Email Address", html, app_name, sender_email)
