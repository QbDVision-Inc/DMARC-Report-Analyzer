# CHANGELOG



## v0.2.0 (2024-05-24)

### Chore

* chore: license change ([`949be3d`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/949be3d2239ab276e3bcf8de11ab54aea44807bd))

### Feature

* feat: merge experimental branch for total code refactor and new functionality

This merge pull request includes a comprehensive refactor of the codebase, introducing new features and improvements. ([`e4bb4af`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/e4bb4af3d1d3fced315c8629767fa28dd6021482))

### Unknown

* Merge remote-tracking branch &#39;origin/main&#39; into experimental ([`5644c82`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/5644c8268399ec6bec996693b49700b576aed1a1))


## v0.1.0 (2024-05-24)

### Chore

* chore: fix branch name in ci config ([`cb51469`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/cb514695ff4b746ec31c84ecd3cd345482604b22))

* chore: versioning ([`bb3caf4`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/bb3caf4b989c7d86b840143e8c99453c84fa2c9c))

* chore: forgot the dmarc_check folder....and code reformat ([`6743519`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/67435192484e00390d3fa173c527201884adea51))

### Feature

* feat: split the code into classes and added OAuth2 support for MFA

* Refactored the monolithic script into modular classes for better maintainability.
* Added EmailDownloader class to handle email fetching and attachment downloading with support for both basic authentication and OAuth2.
* Created DMARCAnalyzer class to handle parsing and analysis of DMARC reports.
* Introduced configuration via config.ini for cleaner configuration management.
* Enhanced error handling and logging across the board.
* Added functionality to calculate and report the ratio and number of emails that would have been lost if DMARC had p=reject, along with blacklisting statistics.

I wrote this stone-cold sober, which is impressive considering the code still works. ([`693bca1`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/693bca1348272054d908633ed1228004ecf962f6))

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
