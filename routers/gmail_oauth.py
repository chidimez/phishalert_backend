# routers/gmail_auth.py
import os
from datetime import datetime, timedelta

import requests
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session

from services.auth import get_current_user
from services.mailbox import upsert_mailbox_connection
from services.session import get_db
from utils.gmail_oauth import get_google_auth_flow

router = APIRouter(prefix="/auth/gmail", tags=["Gmail Auth"])

@router.get("/initiate")
def initiate_gmail_auth():
    flow = get_google_auth_flow()
    print("Using redirect_uri:", flow.redirect_uri)
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline", include_granted_scopes="true")
    return RedirectResponse(auth_url)


@router.get("/callback")
def gmail_auth_callback(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user)):
    flow = get_google_auth_flow()
    flow.fetch_token(authorization_response=str(request.url))
    credentials = flow.credentials

    # Get user's Gmail address
    user_info = requests.get(
        "https://www.googleapis.com/oauth2/v1/userinfo",
        headers={"Authorization": f"Bearer {credentials.token}"}
    ).json()

    email = user_info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Failed to fetch email from Google.")

    mailbox = upsert_mailbox_connection(
        db=db,
        user_id=user.id,
        email=email,
        provider="gmail",
        credentials=credentials
    )

    html_content = f"""
    <html>
      <body>
        <script>
          const mailboxData = {{
            type: "gmail-connected",
            email: "{email}",
            provider: "gmail",
            mailboxId: {mailbox.id}
          }};
          window.opener.postMessage(mailboxData, "*");
          window.close();
        </script>
        <p>Connecting...</p>
      </body>
    </html>
    """
    return HTMLResponse(content=html_content)

def refresh_gmail_access_token(refresh_token: str):
    """
    Refresh Gmail OAuth access token using `requests` and return new access token and expiry.
    """
    token_url = "https://oauth2.googleapis.com/token"
    client_id = os.getenv("GOOGLE_CLIENT_ID")
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET")

    payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }

    response = requests.post(token_url, data=payload)
    if response.status_code != 200:
        raise Exception(f"Failed to refresh Gmail token: {response.text}")

    data = response.json()
    return {
        "access_token": data["access_token"],
        "expires_at": datetime.utcnow() + timedelta(seconds=data.get("expires_in", 3600))
    }

