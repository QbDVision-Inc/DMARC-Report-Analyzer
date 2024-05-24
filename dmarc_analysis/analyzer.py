import platform
import subprocess
import xml.etree.ElementTree as ET
import pandas as pd
import os
import dns.resolver
import spf
import gzip
import zipfile
from tqdm import tqdm
import logging
from io import BytesIO

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class DMARCAnalyzer:
    def __init__(self, directory, spamhaus_domain):
        self.directory = directory
        self.spamhaus_domain = spamhaus_domain
        self.all_records = []
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']  # Use Google DNS servers

    @staticmethod
    def parse_dmarc_report(file_path):
        """
        Parse DMARC report from an XML file.
        This function tries to parse the XML like it's deciphering hieroglyphics.
        """
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()

            records = []
            for record in root.findall('.//record'):
                row = record.find('row')
                policy_evaluated = row.find('policy_evaluated') if row is not None else None
                identifiers = record.find('identifiers')

                if row is not None and policy_evaluated is not None:
                    source_ip = row.find('source_ip').text if row.find('source_ip') is not None else 'unknown'
                    count = int(row.find('count').text) if row.find('count') is not None else 0
                    spf_result = policy_evaluated.find('spf').text if policy_evaluated.find(
                        'spf') is not None else 'none'
                    dkim_result = policy_evaluated.find('dkim').text if policy_evaluated.find(
                        'dkim') is not None else 'none'
                    header_from = identifiers.find('header_from').text if identifiers is not None and identifiers.find(
                        'header_from') is not None else 'unknown'
                    envelope_from = identifiers.find(
                        'envelope_from').text if identifiers is not None and identifiers.find(
                        'envelope_from') is not None else 'unknown'

                    records.append({
                        'source_ip': source_ip,
                        'count': count,
                        'spf_result': spf_result,
                        'dkim_result': dkim_result,
                        'header_from': header_from,
                        'envelope_from': envelope_from
                    })
            return records
        except ET.ParseError:
            logging.error(f"Error parsing {file_path}")
            return []

    def extract_gz(self, file_path):
        """
        Extract a .gz file.
        It's like opening a can of compressed spam, but with less sodium.
        """
        try:
            with gzip.open(file_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logging.error(f"Error extracting {file_path}: {e}")
            return None

    def extract_zip(self, file_path):
        """
        Extract a .zip file.
        Because who doesn't love unzipping compressed chaos?
        """
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                xml_files = [name for name in zip_ref.namelist() if name.endswith('.xml')]
                extracted_files = []
                for xml_file in xml_files:
                    with zip_ref.open(xml_file) as f:
                        extracted_files.append(f.read())
                return extracted_files
        except Exception as e:
            logging.error(f"Error extracting {file_path}: {e}")
            return []

    def check_blacklist(self, ip):
        """
        Check if an IP is blacklisted.
         We ask the blacklist, 'Hey, you seen this guy around here?'.
        """
        try:
            query = '.'.join(reversed(ip.split('.'))) + '.' + self.spamhaus_domain
            answers = self.resolver.resolve(query, 'A')
            return True, answers.rrset.to_text()
        except dns.resolver.NXDOMAIN:
            return False, "Not listed"
        except dns.resolver.Timeout:
            return False, "Timeout"
        except dns.resolver.NoNameservers as e:
            logging.error(f"DNS resolution error for {ip}: {e}")
            return False, "DNS resolution error"
        except dns.exception.DNSException as e:
            logging.error(f"General DNS error for {ip}: {e}")
            return False, "General DNS error"

    @staticmethod
    def check_spf_alignment(header_from, envelope_from):
        """
        Check SPF alignment.
        Like checking if your tie matches your socks.
        """
        return header_from.split('@')[-1] == envelope_from.split('@')[-1]

    @staticmethod
    def get_spf_failure_reason(ip, envelope_from):
        """
        Get SPF failure reason.
        Because knowing why you failed is half the battle.
        """
        try:
            result, explanation = spf.check2(i=ip, s=envelope_from, h=envelope_from.split('@')[-1])
            return f"{result}: {explanation}"
        except spf.SPFError as e:
            return f"SPF check error: {e}"

    def analyze_reports(self):
        """
        Analyze DMARC reports in the given directory.
        We scan, we parse, we laugh, we cry... it's a whole process.
        """
        # Scan directory and parse reports
        logging.info(f"Scanning directory {self.directory} for XML files...")
        for root, dirs, files in os.walk(self.directory):
            for file in files:
                file_path = os.path.join(root, file)
                if file.endswith('.xml'):
                    logging.info(f"Parsing {file_path}...")
                    records = self.parse_dmarc_report(file_path)
                    self.all_records.extend(records)
                elif file.endswith('.gz'):
                    logging.info(f"Extracting {file_path}...")  # Extracting .gz file, because why make it easy?
                    content = self.extract_gz(file_path)
                    if content:
                        logging.info(f"Parsing extracted content from {file_path}...")
                        records = self.parse_dmarc_report(BytesIO(content))
                        self.all_records.extend(records)
                elif file.endswith('.zip'):
                    logging.info(f"Extracting {file_path}...")  # Unzipping like it's 1999
                    contents = self.extract_zip(file_path)
                    for content in contents:
                        if content:
                            logging.info(f"Parsing extracted content from {file_path}...")
                            records = self.parse_dmarc_report(BytesIO(content))
                            self.all_records.extend(records)

        if self.all_records:
            df = pd.DataFrame(self.all_records)

            # Filter records that fail SPF, DKIM, or both checks
            df_failed = df[(df['spf_result'] == 'fail') | (df['dkim_result'] == 'fail')].copy()

            if not df_failed.empty:
                # Analyze the data
                logging.info("Analyzing DMARC records...")  # Time to do some real work, finally
                total_emails = df['count'].sum()
                failed_spf = df_failed[df_failed['spf_result'] == 'fail']['count'].sum()
                failed_dkim = df_failed[df_failed['dkim_result'] == 'fail']['count'].sum()
                failed_both = df_failed[(df_failed['spf_result'] == 'fail') & (df_failed['dkim_result'] == 'fail')][
                    'count'].sum()

                logging.info(f"Total emails: {total_emails}")  # Numbers, numbers everywhere
                logging.info(f"Emails failed SPF: {failed_spf}")  # SPF failure party
                logging.info(f"Emails failed DKIM: {failed_dkim}")  # DKIM failure fiesta
                logging.info(f"Emails failed both SPF and DKIM: {failed_both}")  # Double the fun, double the failure

                # Calculate the number and ratio of emails lost if DMARC had p=reject
                total_failed = df_failed['count'].sum()
                lost_emails_ratio = total_failed / total_emails if total_emails > 0 else 0
                logging.info(f"Total emails that would have been lost with DMARC p=reject: {total_failed}")
                logging.info(f"Ratio of emails that would have been lost with DMARC p=reject: {lost_emails_ratio:.2%}")

                # Calculate lost emails due to each specific failure
                lost_emails_spf = failed_spf - failed_both
                lost_emails_dkim = failed_dkim - failed_both
                lost_emails_both = failed_both

                # Calculate total emails lost because of blacklisting
                logging.info("Checking blacklists for IP addresses...")  # Let's see who's been naughty
                total_blacklisted_emails = 0
                df_failed['blacklisted'] = False
                df_failed['spf_failure_reason'] = ''
                df_failed['dkim_failure_reason'] = ''

                for index, row in tqdm(df_failed.iterrows(), total=df_failed.shape[0]):
                    ip = row['source_ip']
                    spf_failure_reason = ''
                    dkim_failure_reason = ''

                    if row['spf_result'] == 'fail':
                        spf_failure_reason = self.get_spf_failure_reason(ip, row['envelope_from'])

                    if row['dkim_result'] == 'fail':
                        dkim_failure_reason = "Failed DKIM check (details not implemented)"

                    df_failed.at[index, 'spf_failure_reason'] = spf_failure_reason
                    df_failed.at[index, 'dkim_failure_reason'] = dkim_failure_reason

                    is_listed, _ = self.check_blacklist(ip)
                    if is_listed:
                        df_failed.at[index, 'blacklisted'] = True
                        total_blacklisted_emails += row['count']

                # Check SPF alignment
                df_failed['spf_alignment'] = df_failed.apply(
                    lambda x: self.check_spf_alignment(x['header_from'], x['envelope_from']), axis=1)

                # Print report
                summary = (
                    f"Total emails: {total_emails}\n"
                    f"Emails that would have been lost if DMARC had p=reject: {total_failed}\n"
                    f"Ratio of emails that would have been lost if DMARC had p=reject: {lost_emails_ratio:.2%}\n"
                    f"Emails lost due to SPF failure: {lost_emails_spf}\n"
                    f"Emails lost due to DKIM failure: {lost_emails_dkim}\n"
                    f"Emails lost due to both SPF and DKIM failure: {lost_emails_both}\n"
                    f"Total emails lost due to blacklisting: {total_blacklisted_emails}\n"
                )

                print(summary)

                # Save the summary to a text file
                summary_file = os.path.join(os.getcwd(), 'summary.txt')
                with open(summary_file, 'w') as f:
                    f.write(summary)
                logging.info(f"Summary saved to {summary_file}")

                # Save the dataframe to a CSV file for further analysis if needed
                output_file = os.path.join(os.getcwd(), 'dmarc_report_analysis.csv')
                df_failed.to_csv(output_file, index=False)
                logging.info(f"Analysis complete. Results saved to {output_file}")

                # Ask user if they want to open the CSV and Resume file
                open_csv = input("Do you want to open the CSV and Resume file? (yes/no): ").strip().lower()
                if open_csv == 'yes':
                    if platform.system() == 'Windows':
                        os.startfile(output_file)
                    elif platform.system() == 'Darwin':  # macOS
                        subprocess.call(['open', output_file])
                    else:  # Linux and other OS
                        subprocess.call(['xdg-open', output_file])

                return df_failed
            else:
                logging.info("No records found that fail SPF or DKIM.")  # All clear, folks!
                return None
        else:
            logging.warning("No valid DMARC records found.")  # Well, that was disappointing
            return None
