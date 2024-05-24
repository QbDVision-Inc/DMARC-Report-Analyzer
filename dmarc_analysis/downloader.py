import os
import imaplib
import email
from email.policy import default
from tqdm import tqdm
import logging
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class EmailDownloader:
    def __init__(self, imap_server, email_user, email_pass=None, save_dir=None, use_mfa=False, credentials_json=None,
                 token_json=None, scopes=None, redirect_uri=None):
        self.imap_server = imap_server
        self.email_user = email_user
        self.email_pass = email_pass
        self.save_dir = save_dir
        self.use_mfa = use_mfa
        self.credentials_json = credentials_json
        self.token_json = token_json
        self.scopes = [scopes] if scopes else ['https://mail.google.com/']
        self.redirect_uri = redirect_uri
        self.credentials = None

    def authenticate(self):
        creds = None

        if os.path.exists(self.token_json):
            creds = Credentials.from_authorized_user_file(self.token_json, self.scopes)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_json, self.scopes)
                creds = flow.run_local_server(port=0)
            with open(self.token_json, 'w') as token:
                token.write(creds.to_json())

        self.credentials = creds

    def download_attachments(self):
        """
        Connect to an email account and download all DMARC report attachments.
        """
        if self.use_mfa:
            self.authenticate()

        try:
            logging.info(f"Connecting to IMAP server: {self.imap_server}")
            mail = imaplib.IMAP4_SSL(self.imap_server)
            if self.use_mfa and self.credentials:
                mail.login(self.email_user, self.credentials.token)
            else:
                mail.login(self.email_user, self.email_pass)
            mail.select('inbox')

            # Use a more specific and simpler search criteria
            result, data = mail.search(None, '(HEADER Subject "report domain")')
            if result != 'OK':
                logging.error(f"Failed to search emails: {result} {data}")
                return

            email_ids = data[0].split()

            for email_id in tqdm(email_ids, desc="Downloading attachments"):
                result, msg_data = mail.fetch(email_id, '(RFC822)')
                raw_email = msg_data[0][1]
                msg = email.message_from_bytes(raw_email, policy=default)

                for part in msg.iter_attachments():
                    if part.get_content_type() in ['application/xml', 'application/gzip', 'application/zip']:
                        filename = part.get_filename()
                        if filename:
                            filepath = os.path.join(self.save_dir, filename)
                            with open(filepath, 'wb') as f:
                                f.write(part.get_payload(decode=True))
                            logging.info(f"Downloaded {filename}")

            mail.logout()
        except Exception as e:
            logging.error(f"Failed to download attachments: {e}")
