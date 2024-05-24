# CHANGELOG



## v0.1.0 (2024-05-24)

### Chore

* chore: fix branch name in ci config ([`cb51469`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/cb514695ff4b746ec31c84ecd3cd345482604b22))

* chore: versioning ([`bb3caf4`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/bb3caf4b989c7d86b840143e8c99453c84fa2c9c))

* chore: forgot the dmarc_check folder....and code reformat ([`6743519`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/67435192484e00390d3fa173c527201884adea51))

### Feature

* feat(dmarc): Enhance DMARC report analysis with detailed failure stats and summary

- Added detailed analysis for DMARC reports with counts for SPF, DKIM, and combined failures.
- Calculated and reported total emails that would be lost if DMARC policy was p=reject.
- Integrated blacklist checking for IP addresses and reported total emails lost due to blacklisting.
- Generated both a CSV file for detailed report and a summary text file for key statistics.
- Added a .gitignore

Now, you&#39;ll know exactly how many emails would be kicked out like an unruly guest at a honky-tonk bar. Who knew analyzing DMARC reports could be this much fun? ([`a50652f`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/a50652f846adc936cb38c22195c8ee52c0e14398))

* feat: initial commit and release

Initial commit of the DMARC Report Analyzer script. This release includes:
- Parsing DMARC XML reports
- Handling .gz and .zip compressed files
- Checking SPF and DKIM results
- Blacklist checks using Spamhaus
- Generating a detailed CSV report

This script scans a specified directory for DMARC reports, processes them, and outputs a CSV with detailed analysis results. ([`9445342`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/9445342d75610840b86a6641c71303146d64ef5b))

### Unknown

* Initial commit ([`78b71cb`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/78b71cbbcf56aff5a45f8f6fa8ffb76a1936d443))
