# routers/gmail_auth.py
import os
from datetime import datetime, timedelta

import requests
from fastapi import APIRouter, Depends, Request, HTTPException, BackgroundTasks
from fastapi.responses import RedirectResponse, HTMLResponse
from sqlalchemy.orm import Session

from services.auth import get_current_user
from services.mailbox import upsert_mailbox_connection
from services.session import get_db
from utils.gmail_oauth import get_google_auth_flow

from workers.scan_mailbox import fetch_and_scan_mailbox_background
from services.scan_first_emails import fetch_first_30_emails

router = APIRouter(prefix="/auth/gmail", tags=["Gmail Auth"])

@router.get("/initiate")
def initiate_gmail_auth():
    flow = get_google_auth_flow()
    print("Using redirect_uri:", flow.redirect_uri)
    auth_url, _ = flow.authorization_url(prompt="consent", access_type="offline", include_granted_scopes="true")
    return RedirectResponse(auth_url)




@router.get("/callback")
def gmail_auth_callback(
    request: Request,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    background_tasks: BackgroundTasks
):
    flow = get_google_auth_flow()
    flow.fetch_token(authorization_response=str(request.url))
    credentials = flow.credentials

    # Get Gmail user info
    user_info = requests.get(
        "https://www.googleapis.com/oauth2/v1/userinfo",
        headers={"Authorization": f"Bearer {credentials.token}"}
    ).json()

    email = user_info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Failed to fetch email from Google.")

    # Create mailbox record
    mailbox = upsert_mailbox_connection(
        db=db,
        user_id=user.id,
        email=email,
        provider="gmail",
        credentials=credentials
    )

    # ✅ Step 1: Sync first 30 emails instantly
    fetch_first_30_emails(credentials, mailbox.id, db)

    # ✅ Step 2: Background scan remaining
    background_tasks.add_task(fetch_and_scan_mailbox_background, mailbox.id)

    # Send mailbox info to frontend
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
        <p>Connecting and scanning...</p>
      </body>
    </html>
    """
    return HTMLResponse(content=html_content)


