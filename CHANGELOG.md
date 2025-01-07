# CHANGELOG


## v0.3.0 (2025-01-07)

### Chores

- Url fix [Skip CI]
  ([`a5848d1`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/a5848d1675286c5e8635eac3e9c4cec5e5415b14))

### Features

- Added parsing and show of report dates
  ([`28b16d0`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/28b16d0329b159e933241d7d728d8b3136869055))

The DMARC reports contains a date field in order to know which period has been covered in that
  reports.


## v0.2.0 (2024-05-24)

### Features

- Merge experimental branch for total code refactor and new functionality
  ([`e4bb4af`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/e4bb4af3d1d3fced315c8629767fa28dd6021482))

This merge pull request includes a comprehensive refactor of the codebase, introducing new features
  and improvements.


## v0.1.0 (2024-05-24)

### Chores

- Fix branch name in ci config
  ([`cb51469`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/cb514695ff4b746ec31c84ecd3cd345482604b22))

- Forgot the dmarc_check folder....and code reformat
  ([`6743519`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/67435192484e00390d3fa173c527201884adea51))

- License change
  ([`949be3d`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/949be3d2239ab276e3bcf8de11ab54aea44807bd))

- Versioning
  ([`bb3caf4`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/bb3caf4b989c7d86b840143e8c99453c84fa2c9c))

### Features

- Initial commit and release
  ([`9445342`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/9445342d75610840b86a6641c71303146d64ef5b))

Initial commit of the DMARC Report Analyzer script. This release includes: - Parsing DMARC XML
  reports - Handling .gz and .zip compressed files - Checking SPF and DKIM results - Blacklist
  checks using Spamhaus - Generating a detailed CSV report

This script scans a specified directory for DMARC reports, processes them, and outputs a CSV with
  detailed analysis results.

- Split the code into classes and added OAuth2 support for MFA
  ([`693bca1`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/693bca1348272054d908633ed1228004ecf962f6))

* Refactored the monolithic script into modular classes for better maintainability. * Added
  EmailDownloader class to handle email fetching and attachment downloading with support for both
  basic authentication and OAuth2. * Created DMARCAnalyzer class to handle parsing and analysis of
  DMARC reports. * Introduced configuration via config.ini for cleaner configuration management. *
  Enhanced error handling and logging across the board. * Added functionality to calculate and
  report the ratio and number of emails that would have been lost if DMARC had p=reject, along with
  blacklisting statistics.

I wrote this stone-cold sober, which is impressive considering the code still works.

- **dmarc**: Enhance DMARC report analysis with detailed failure stats and summary
  ([`a50652f`](https://github.com/QbDVision-Inc/DMARC-Report-Analyzer/commit/a50652f846adc936cb38c22195c8ee52c0e14398))

- Added detailed analysis for DMARC reports with counts for SPF, DKIM, and combined failures. -
  Calculated and reported total emails that would be lost if DMARC policy was p=reject. - Integrated
  blacklist checking for IP addresses and reported total emails lost due to blacklisting. -
  Generated both a CSV file for detailed report and a summary text file for key statistics. - Added
  a .gitignore

Now, you'll know exactly how many emails would be kicked out like an unruly guest at a honky-tonk
  bar. Who knew analyzing DMARC reports could be this much fun?
