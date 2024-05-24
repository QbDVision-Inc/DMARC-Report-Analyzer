# DMARC Report Analyzer

## Introduction

Welcome to the DMARC Report Analyzer! 
This little script will sift through your DMARC reports like a prospector panning for gold. 

It's going to parse, extract, and analyze those reports, and when it's all done, it'll give you a shiny CSV file.

So, grab a drink, sit back, and let this script do the heavy lifting.

## What It Does

This script will:
1. **Scan your directory** for any DMARC report files. It can handle `.xml`, `.gz`, and `.zip` files, because we like to cover all bases.
2. **Parse the reports** and extract the important stuff. Think of it like Antonio in foreign land looking for where to drink Guinness.
3. **Analyze the data** to find out which emails failed SPF, DKIM, or both.
4. **Check blacklists** for IP addresses that have been naughty. We’ll see who’s on the blacklist, just like Santa.
5. **Generate a CSV file** with all the juicy details and ask if you want to open it. Because we care about your user experience.

## How It Works

1. **Requirements**:
   - Make sure you have `Python 3.x` installed. If you don’t, you’re going to have a bad time.
   - Install the required libraries by running: `pip install -r requirements.txt`
   - Spamhouse Query key

2. **Running the Script**:
   - Place your DMARC report files in a directory and call it `dmarc_check`.
   - Update the script at line 18 where you add the Spamhouse query key
   - Open your terminal or command prompt.
   - Navigate to the directory where the script is located.
   - Run the script by typing: `python dmarc_report_analyzer.py`
   - Sit back, relax, and enjoy a beverage of your choice. The script will take care of the rest.

3. **Output**:
   - The script will create a CSV file named `dmarc_report_analysis.csv` in the current working directory.
   - It will log the progress and results, showing you the path to the final CSV file.
   - You’ll be prompted if you want to open the CSV file. Type `yes` if you do, or `no` if you want to keep the suspense.

## Example Usage

Here’s a quick rundown of how to use the script:

```sh
# Navigate to your script directory
cd path/to/your/script

# Run the script
python dmarc_report_analyzer.py
```

## Contact
If you run into any issues or have any questions, you’re probably not alone. 

Feel free to reach out !