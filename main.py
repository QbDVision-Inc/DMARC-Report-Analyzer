import os
import configparser
from dmarc_analysis.analyzer import DMARCAnalyzer
from dmarc_analysis.downloader import EmailDownloader

# Load configuration
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'config/config.ini'))

spamhaus_query_key = config.get('spamhaus', 'query_key')
spamhaus_domain = config.get('spamhaus', 'domain')
spamhaus_full_domain = f"{spamhaus_query_key}.{spamhaus_domain}"
imap_server = config.get('email', 'imap_server')
email_user = config.get('email', 'email_user')
email_pass = config.get('email', 'email_pass')
use_mfa = config.getboolean('email', 'use_mfa')
credentials_json = config.get('email', 'credentials_json')
token_json = config.get('email', 'token_json')
scopes = config.get('email', 'scopes')
redirect_uri = config.get('email', 'redirect_uri')

# Ask user if they want to download DMARC reports from email
download_from_email = input("Do you want to download DMARC reports from an email account? (yes/no): ").strip().lower()
if download_from_email == 'yes':
    download_dir = 'dmarc_check'
    os.makedirs(download_dir, exist_ok=True)
    if use_mfa:
        email_downloader = EmailDownloader(
            imap_server,
            email_user,
            save_dir=download_dir,
            use_mfa=use_mfa,
            credentials_json=credentials_json,
            token_json=token_json,
            scopes=scopes,
            redirect_uri=redirect_uri
        )
    else:
        email_downloader = EmailDownloader(
            imap_server,
            email_user,
            email_pass,
            save_dir=download_dir,
            use_mfa=use_mfa
        )
    email_downloader.download_attachments()

# Analyze DMARC reports
directory = 'dmarc_check'
dmarc_analyzer = DMARCAnalyzer(directory, spamhaus_full_domain)
dmarc_analyzer.analyze_reports()
