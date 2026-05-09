import requests
import os
from dotenv import load_dotenv

load_dotenv(os.path.expanduser("~/flas/.env"))
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
BREVO_SEND_URL = "https://api.brevo.com/v3/smtp/email"

def send_reset_email(email, reset_code):
    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }

    data = {
        "sender": {"name": "TetherX", "email": "msuleiman857@gmail.com"},
        "to": [{"email": email}],
        "subject": "Your TetherX Password Reset Code",
        "htmlContent": f"""
        <html>
          <body style="margin:0; padding:0; background-color:#F9F9F9; font-family: 'Poppins', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
            <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%" style="padding: 40px 20px;">
              <tr>
                <td align="center">
                  <table border="0" cellpadding="0" cellspacing="0" width="100%"
                         style="max-width: 600px; background-color:#FFFFFF; border-radius:24px; overflow:hidden; border: 1px solid #E5E5E5;">

                    <tr>
                      <td style="padding: 40px 40px 20px 40px;">
                        <span style="font-size: 24px; font-weight: 800; color: #000000; letter-spacing: -1px;">
                          TetherX.
                        </span>
                      </td>
                    </tr>

                    <tr>
                      <td style="padding: 0 40px 20px 40px;">
                        <p style="margin: 0 0 8px 0; font-size: 11px; font-weight: bold; letter-spacing: 1.5px; color: #999999; text-transform: uppercase;">
                          Security Verification
                        </p>
                        <h1 style="margin: 0 0 16px 0; font-size: 32px; font-weight: bold; color: #000000; letter-spacing: -0.5px;">
                          Reset Password
                        </h1>
                        <p style="margin: 0 0 32px 0; font-size: 15px; color: #666666; line-height: 1.6;">
                          We received a request to reset the password for your TetherX account. Enter the secure 6-digit code below to continue. This code will expire in <strong>10 minutes</strong>.
                        </p>

                        <table border="0" cellpadding="0" cellspacing="0" width="100%">
                          <tr>
                            <td align="center" style="background-color: #F4F4F4; padding: 32px; border-radius: 16px; border: 1px solid #EEEEEE;">
                              <span style="display: block; font-size: 12px; font-weight: 600; letter-spacing: 1px; color: #888888; margin-bottom: 12px; text-transform: uppercase;">
                                Your Reset Code
                              </span>
                              <span style="display: inline-block; font-size: 36px; font-weight: 800; letter-spacing: 12px; color: #000000;">
                                {reset_code}
                              </span>
                            </td>
                          </tr>
                        </table>

                        <p style="margin: 32px 0 0 0; font-size: 14px; color: #999999; line-height: 1.5;">
                          If you didn't request this action, you can safely ignore this email. Your account remains secure.
                        </p>
                      </td>
                    </tr>

                    <tr>
                      <td align="left" style="padding: 30px 40px; background-color: #FFFFFF; border-top: 1px solid #F0F0F0;">
                        <p style="margin: 0; font-size: 12px; color: #AAAAAA; font-weight: 500;">
                          &copy; 2024 TetherX. All rights reserved.
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
            print("✅ Email sent successfully!")
        else:
            print(f"❌ Failed to send email: {response.status_code} → {response.text}")
    except Exception as e:
        print(f"⚠️ Error sending email: {e}")
