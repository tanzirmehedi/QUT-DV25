import os
import pandas as pd
import vt
import time
import asyncio
import nest_asyncio
import hashlib
import logging
import aiohttp
from datetime import datetime, timedelta

# Apply nest_asyncio to allow re-entering the event loop
nest_asyncio.apply()

# Set up logging
log_file = 'benign_scan_process.log'
logging.basicConfig(
    filename=log_file,
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)

# VirusTotal API key
API_KEY = '0cb4de4eb946dbc69fd11f845adca6ed011f86451cf2ca2e69ffd464478026a2'  # Replace with your actual VirusTotal API key

# Folder containing extracted files from the provided directory
extracted_folder = 'Benign_Dataset'

# CSV file to save results progressively
csv_file = 'benign_scan_results.csv'

# Initialize lists to store results and package information
results = []
api_request_count = 0
daily_request_limit = 20000  # VirusTotal daily limit
start_of_day = datetime.now().date()

# Function to wait until the next day at midnight
def wait_until_next_day():
    now = datetime.now()
    next_day = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    wait_seconds = (next_day - now).total_seconds()
    logging.info(f"Daily limit reached. Waiting until midnight to resume. Waiting {wait_seconds / 3600:.2f} hours.")
    time.sleep(wait_seconds)

# Function to recursively get all files in directory
def get_all_files(directory):
    file_paths = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_paths.append(os.path.join(root, file))
    return file_paths

# Function to compute SHA-256 hash of a file
def compute_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to save results to CSV progressively
def save_results():
    df = pd.DataFrame(results)
    df.to_csv(csv_file, mode='a', header=not os.path.exists(csv_file), index=False)
    results.clear()  # Clear results after saving to avoid duplicates
    logging.info("Results saved to CSV.")

# Get all files in the extracted folder
all_files = get_all_files(extracted_folder)

# Asynchronous function to scan files with retry logic for API errors
async def scan_files(all_files, start_index=0):
    global api_request_count, start_of_day
    conn = aiohttp.TCPConnector(ssl=False)  # Disable SSL verification
    async with vt.Client(API_KEY, connector=conn) as client:  # Use custom connector
        for i, file_path in enumerate(all_files[start_index:], start=start_index):
            # Check if the daily limit is reached
            if api_request_count >= daily_request_limit:
                wait_until_next_day()  # Wait until the next day at midnight
                api_request_count = 0  # Reset the request count
                start_of_day = datetime.now().date()  # Reset the day start

            try:
                # Calculate the SHA-256 hash of the file
                file_hash = compute_sha256(file_path)
                logging.info(f"Starting scan for {file_path}")

                # Retry logic for API errors with exponential backoff
                retries = 3
                wait_time = 30
                for attempt in range(retries):
                    try:
                        with open(file_path, 'rb') as f:
                            analysis = await client.scan_file_async(f)
                        api_request_count += 1  # Increment the request count
                        logging.info(f"Scan started for {file_path}, Request count: {api_request_count}")
                        break  # Exit loop if scan is successful
                    except vt.error.APIError:
                        logging.error(f"API error on attempt {attempt + 1} for {file_path}. Retrying in {wait_time} seconds...")
                        time.sleep(wait_time)
                        wait_time *= 2  # Exponential backoff
                else:
                    logging.error(f"Max retries reached for {file_path}. Marking as 'APIError'.")
                    results.append({
                        'file_path': file_path,
                        'malicious_count': 'APIError',
                        'suspicious_count': '',
                        'undetected_count': '',
                        'harmless_count': '',
                        'popular_threat_name': '',
                        'popular_threat_category': '',
                        'suggested_threat_label': ''
                    })
                    continue  # Move to the next file if max retries reached

                # Wait for the analysis to complete using the file's hash
                analysis = await client.get_object_async(f"/analyses/{analysis.id}")
                while analysis.status == 'queued':
                    logging.info(f"Waiting for analysis to complete for {file_path}...")
                    time.sleep(30)
                    analysis = await client.get_object_async(f"/analyses/{analysis.id}")
                
                # Retrieve the report using the computed hash
                file_report = await client.get_object_async(f"/files/{file_hash}")
                api_request_count += 1  # Increment request count for the retrieval
                                
                # Extract relevant data
                last_analysis_stats = file_report.last_analysis_stats if 'last_analysis_stats' in dir(file_report) else {}
                malicious_count = last_analysis_stats.get('malicious', 0)
                suspicious_count = last_analysis_stats.get('suspicious', 0)
                undetected_count = last_analysis_stats.get('undetected', 0)
                harmless_count = last_analysis_stats.get('harmless', 0)

                # Check if 'popular_threat_classification' is present
                if hasattr(file_report, 'popular_threat_classification'):
                    popular_threat_name = ', '.join([threat['value'] for threat in file_report.popular_threat_classification.get('popular_threat_name', [])])
                    popular_threat_category = ', '.join([cat['value'] for cat in file_report.popular_threat_classification.get('popular_threat_category', [])])
                    suggested_threat_label = file_report.popular_threat_classification.get('suggested_threat_label', '')
                else:
                    popular_threat_name = ''
                    popular_threat_category = ''
                    suggested_threat_label = ''

                # Append the result
                results.append({
                    'file_path': file_path,
                    'malicious_count': malicious_count,
                    'suspicious_count': suspicious_count,
                    'undetected_count': undetected_count,
                    'harmless_count': harmless_count,
                    'popular_threat_name': popular_threat_name,
                    'popular_threat_category': popular_threat_category,
                    'suggested_threat_label': suggested_threat_label
                })
                
                # Log the successful processing of the file
                logging.info(f"Processed file {file_path}")

                # Save progress every 5 files
                if (i + 1) % 5 == 0:
                    logging.info(f"Saving results for files processed up to index {i}...")
                    save_results()
                
                # Respect the API rate limit
                time.sleep(15)

            except Exception as e:
                # Log the error
                logging.error(f"Error processing {file_path}: {e}")
                results.append({
                    'file_path': file_path,
                    'malicious_count': 'Error',
                    'suspicious_count': '',
                    'undetected_count': '',
                    'harmless_count': '',
                    'popular_threat_name': '',
                    'popular_threat_category': '',
                    'suggested_threat_label': ''
                })

        # Final save for remaining results after the loop ends
        if results:
            save_results()
            logging.info("Final results saved after processing all files.")

# Run the async function to scan files starting from 0
loop = asyncio.get_event_loop()
loop.run_until_complete(scan_files(all_files, start_index=0))

print("Scanning complete. Results saved to scan_results.csv. Log saved to scan_process.log.")
