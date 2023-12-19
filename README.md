# NetSleuthXplorer
A Python3 script for analyzing netflow data, performing z-score statistical analysis, and doing passive DNS and IP reputation lookups utilizing Microsoft Defender Threat Intelligence (MDTI).

This script will process CSV data from Team Cymru's Pure Signal Recon (PSR) tool, perform Z-score analysis, 
resolve DNS names and check IP reputation using the MDTI API, and exclude any IP addresses with a history of `zpath.net` (ZScaler).

The final output displays the top 10 results based on Z-scores, excluding IPs with histories of `zpath.net` or failed DNS resolutions.

## Why use this?
For threat hunting in netflow data, high Z-scores can be particularly useful for identifying unusual data transfer patterns that 
might warrant further investigation for potential security incidents.

## Requirements
`pip install -r requirements.txt`

- pandas
- numpy
- requests
- azure-identity
- tqdm
- pytz
- python-dateutil

In the NetSleuthXplorer script, replace the following with your own values:

- `client_id = 'YOUR_CLIENT_ID'`
- `client_secret = 'YOUR_CLIENT_SECRET'`
- `tenant_id = 'YOUR_TENANT_ID'`
- `file_path = 'your_csv_file.csv'`

You will also need to make sure your Client ID has `ThreatIntelligence.Read.All` permissions in order to perform the DNS lookups with MDTI.
