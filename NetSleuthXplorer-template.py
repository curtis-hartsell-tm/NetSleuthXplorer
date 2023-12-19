import pandas as pd
import numpy as np
import requests
from azure.identity import ClientSecretCredential
from tqdm import tqdm
import json
from datetime import datetime
import pytz
from dateutil.parser import parse

# Azure AD credentials
client_id = 'YOUR_CLIENT_ID'
client_secret = 'YOUR_CLIENT_SECRET'
tenant_id = 'YOUR_TENANT_ID'

# Function to get access token
def get_access_token(client_id, client_secret, tenant_id):
    token_url = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': 'https://graph.microsoft.com/.default'
    }
    token_r = requests.post(token_url, data=token_data)
    token = token_r.json().get("access_token")
    return token

# Function to perform DNS resolution using Microsoft Defender Threat Intelligence API
def resolve_dns(ip, access_token):
    url = f'https://graph.microsoft.com/v1.0/security/threatIntelligence/hosts/{ip}/passiveDns'
    headers = {'Authorization': 'Bearer ' + access_token}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        try:
            data = response.json()
            records = data.get('value', [])
            if not records:  # If no records, DNS resolution is considered failed
                return False, "DNS resolution failed"

            for record in records:
                artifact = record.get('artifact', {})
                hostname = artifact.get('id', '')
                if 'zpath.net' in hostname:
                    return False, "Contains zpath.net"

            # If zpath.net is not found, return the most recent hostname
            most_recent_record = max(records, key=lambda r: r.get('lastSeenDateTime', ''))
            most_recent_hostname = most_recent_record.get('artifact', {}).get('id', 'Unknown hostname')
            return True, most_recent_hostname

        except json.JSONDecodeError:
            return False, "Failed to parse JSON response"
    else:
        return False, f"DNS resolution failed with status code {response.status_code}"

# Function to calculate Z-score
def calculate_z_score(dataframe, value_column, group_columns):
    df_grouped = dataframe.groupby(group_columns)[value_column].agg(['mean', 'std'])
    df_merged = dataframe.merge(df_grouped, left_on=group_columns, right_on=group_columns, how='left')
    
    # Handling cases where standard deviation is zero
    df_merged['z_score'] = df_merged.apply(
        lambda row: ((row[value_column] - row['mean']) / row['std']) 
                    if row['std'] != 0 else np.nan, axis=1)
    
    return df_merged

# Replace with the path to your CSV file
file_path = 'your_csv_file.csv'

# Read the CSV file
df = pd.read_csv(file_path)

# Perform Z-score analysis on num_octets
df_with_zscore = calculate_z_score(df, 'num_octets', ['src_ip_addr', 'dst_ip_addr'])

# Filter out rows with significant deviation (e.g., Z-score > 2) and non-NaN Z-scores
significant_deviation = df_with_zscore[(np.abs(df_with_zscore['z_score']) > 2) & (~np.isnan(df_with_zscore['z_score']))].copy()

# Get unique DST_IP_ADDR for DNS resolution to avoid redundant lookups
unique_dst_ip_addresses = significant_deviation['dst_ip_addr'].unique()

# Get access token
access_token = get_access_token(client_id, client_secret, tenant_id)

# Perform DNS resolution with progress bar
dns_results = {}
for ip in tqdm(unique_dst_ip_addresses, desc="Resolving DNS", unit="IP"):
    success, hostname = resolve_dns(ip, access_token)
    if success:
        dns_results[ip] = hostname

# Map the DNS results back to the DataFrame
significant_deviation['dst_ip_dns'] = significant_deviation['dst_ip_addr'].apply(dns_results.get)

# Filter out rows with failed or unwanted DNS resolutions
significant_deviation = significant_deviation[significant_deviation['dst_ip_dns'].notna()]

# Sort by Z-score and get the top 10 results
top_10_results = significant_deviation.nlargest(10, 'z_score')

# Display the top 10 results
print(top_10_results[['src_ip_addr', 'dst_ip_addr', 'num_octets', 'z_score', 'dst_ip_dns']])