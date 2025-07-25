# routers/gmail_auth.py
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.responses import RedirectResponse,HTMLResponse


from services.mailbox import upsert_mailbox_connection
from utils.gmail_oauth import get_google_auth_flow
import os
import json
from models.mailbox import MailboxConnection
from services.auth import get_current_user
from services.session import get_db
from sqlalchemy.orm import Session

import requests
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


