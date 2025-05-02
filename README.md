# DMARC Report Analyzer

Welcome to the DMARC Report Analyzer! 
This little gem is your one-stop-shop for parsing, analyzing, and reporting on DMARC reports, with the added bonus of 
fetching these reports directly from your email. 

BUT if you don't like to put email and password into a script, i feel you.

So, just put your files inside the folder `dmarc_checks` and when asked to connect simply say "no".


Think of it like a Swiss Army knife, but for email security nerds. 
And like all good Swiss Army knives, it's sharp, versatile, and slightly dangerous if handled improperly.

## Features

- **Parse and Analyze DMARC Reports**: Because deciphering XML files manually is about as fun as a root canal.
- **Download Attachments from Email**: Automatically fetch DMARC reports from your email account. Supports both basic authentication and OAuth2 for those fancy MFA setups.
- **Detailed Reporting**: Calculates the number and ratio of emails that would be lost if DMARC had p=reject. Also tells you which IPs are blacklisted, because who doesn't love a good blacklist?
- **CSV and Summary Output**: Save your analysis results to a CSV file and a summary text file. Perfect for impressing your boss or confusing your enemies.

## Installation

First, clone this repository to your local machine. You know the drill:

```bash
git clone https://github.com/QbDVision-Inc/DMARC-Report-Analyzer
cd DMARC-Report-Analyzer
# Optional 
python3 -m venv env
source env/bin/activate  # On Windows use `env\Scripts\activate`
# Mandatory
pip install -r requirements.txt
```

## Configuration
Before you run the analyzer, you'll need to set up your configuration file. 
Because nothing says "I'm ready to analyze" like a well-configured `config.ini`.

```bash
cd config/
cp config.ini.example config.ini
```

Open the config.ini with your favourite editor and fill all the fields :)

### Tips
#### Spamhaus
- Visit this page https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account/
- Once you registered and confirmed your account go to https://portal.spamhaus.com/
- Go to Products -> DQS
- Here you will find your **Query Key**
#### Gmail and Password
- Visit https://myaccount.google.com/
- Click on **Security** (on left menu)
- Go to **How you sign in to Google** part and click on **2-Step Verification**
- Scroll down to **App Password** and add one for this script 
- Copy and paste in the config the password

## Usage
To run the analyzer, simply execute the main.py script. It will ask if you want to download DMARC reports from an email account, and then proceed to analyze the reports in the specified directory.

```bash
python main.py
```

## Example
Here's a quick rundown of what you'll see:

- The script will ask if you want to download DMARC reports from an email account.
- If you say no to the question above it will check files inside the `dmarc_checks`
- If you say "yes", it will fetch the reports and save them in the dmarc_check directory.
- It will then analyze the reports and produce a summary of emails that failed SPF/DKIM checks, blacklisted IPs, and the potential impact if DMARC had p=reject.
- Results are saved to dmarc_report_analysis.csv and summary.txt because we believe in both precision and verbosity.

## License
This project is licensed under the MIT License. Because sharing is caring.

## Disclaimer
This tool is provided as-is, without any guarantees. Use at your own risk. Side effects may include enhanced email security knowledge and a sudden appreciation for XML parsing.

Remember, folks, if you don't document it, it didn't happen. So keep those logs handy and those configs tight. Happy analyzing!
