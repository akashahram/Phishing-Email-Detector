import os
import base64
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

def fetch_latest_emails(limit=5):
    """
    Fetch latest Gmail emails using OAuth2.
    Handles login, token saving, and Gmail API calls.
    Returns a list of {'subject': ..., 'body': ...}
    """

    creds = None

    # File paths
    current_dir = os.path.dirname(__file__)
    token_path = os.path.join(current_dir, "token.json")
    creds_path = os.path.join(current_dir, "credentials.json")

    # Load saved token
    if os.path.exists(token_path):
        creds = Credentials.from_authorized_user_file(token_path, SCOPES)

    # If no valid token → authenticate
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(creds_path, SCOPES)
        creds = flow.run_local_server(port=0)

        # Save token
        with open(token_path, "w") as token_file:
            token_file.write(creds.to_json())

    # Connect to Gmail API
    service = build("gmail", "v1", credentials=creds)

    # Fetch email list
    results = service.users().messages().list(
        userId="me", maxResults=limit
    ).execute()

    messages = results.get("messages", [])
    emails = []

    for msg in messages:
        msg_data = service.users().messages().get(
            userId="me", id=msg["id"], format="full"
        ).execute()

        payload = msg_data.get("payload", {})
        headers = payload.get("headers", [])
        subject = ""
        body = ""

        # Extract subject
        for header in headers:
            if header["name"] == "Subject":
                subject = header["value"]

        # Extract body
        parts = payload.get("parts", [])
        if parts:
            for part in parts:
                try:
                    if part.get("mimeType") == "text/plain":
                        data = part["body"]["data"]
                        decoded = base64.urlsafe_b64decode(data)
                        body = decoded.decode("utf-8")
                except:
                    body = "(Unable to decode email body)"

        emails.append({
            "subject": subject,
            "body": body
        })

    return emails
