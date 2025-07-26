import requests
import pandas as pd
import re
import logging
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Initialize logging
logging.basicConfig(
    filename='CosineSimilarity.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load the Excel file
file_path = 'Similarity_Matching.xlsx'
s_df = pd.read_excel(file_path)

# Log the total number of packages
total_rows = len(s_df)
logging.info(f"Total number of packages to process: {total_rows}")
#print(f"Total number of packages to process: {total_rows}")  # Debugging output

# Initialize columns for results
s_df['Benign Package Name'] = ""
s_df['Benign Package Version'] = ""
s_df['Benign Release Date'] = ""
s_df['Similarity Score'] = 0.0

# Set the similarity and logging thresholds
SIMILARITY_THRESHOLD = 0.20
BEST_LOG_THRESHOLD = 0.50
LOG_THRESHOLD = 0.90

# Counter for total similarities found
total_similarities = 0

# Function to ensure all package names are strings
def sanitize_and_convert(package_list):
    sanitized = []
    for pkg in package_list:
        # Convert to string if not already
        if not isinstance(pkg, str):
            pkg = str(pkg)
        # Remove any HTML tags or unwanted content
        pkg = re.sub(r'<.*?>', '', pkg)
        sanitized.append(pkg)
    return sanitized

# Function to find similar package names using cosine similarity
def get_similar_package(malicious_name, malicious_version):
    global total_similarities
    
    try:
        response = requests.get("https://pypi.org/simple/")
        response.raise_for_status()
        logging.info("Fetched PyPI package list successfully")
        #print("Fetched PyPI package list successfully")  # Debugging output
    except requests.RequestException as e:
        logging.error(f"Error fetching PyPI package list: {e}")
        #print(f"Error fetching PyPI package list: {e}")  # Debugging output
        return None, None, None, 0.0

    packages = response.text.splitlines()
    logging.info(f"Total packages retrieved from PyPI: {len(packages)}")
    #print(f"Total packages retrieved from PyPI: {len(packages)}")  # Debugging output

    # Sanitize and ensure all package names are strings
    package_names = sanitize_and_convert(packages)

    # Ensure malicious_name is a string
    if not isinstance(malicious_name, str):
        malicious_name = str(malicious_name)

    # Vectorize the package names and the malicious package name
    vectorizer = TfidfVectorizer()
    # Combine package_names and malicious_name into one list for vectorization
    documents = package_names + [malicious_name]
    
    # Fit and transform the documents
    try:
        vectors = vectorizer.fit_transform(documents)
    except ValueError as e:
        logging.error(f"Error during vectorization: {e}")
        #print(f"Error during vectorization: {e}")  # Debugging output
        return None, None, None, 0.0

    # Compute cosine similarity between the malicious package and all others
    cosine_similarities = cosine_similarity(vectors[-1:], vectors[:-1]).flatten()
    
    # Find the best matches
    best_matches = [
        (package_names[i], cosine_similarities[i])
        for i in range(len(package_names))
        if cosine_similarities[i] >= SIMILARITY_THRESHOLD
    ]

    # Check if any matches were found
    if not best_matches:
        logging.info(f"No matches found for malicious package: {malicious_name} | version: {malicious_version}")
        #print(f"No matches found for malicious package: {malicious_name} | version: {malicious_version}")  # Debugging output
        return None, None, None, 0.0

    # Sort matches by similarity in descending order
    best_matches.sort(key=lambda x: x[1], reverse=True)

    if best_matches:
        logging.info(f"A total of: {len(best_matches)} benign packages were found for malicious package: {malicious_name} | version: {malicious_version} with at least 20% similarity")
        #print(f"A total of: {len(best_matches)} benign packages were found for malicious package: {malicious_name} | version: {malicious_version} with at least 20% similarity")  # Debugging output

        # Print all similar packages with their similarity scores
        logging.info("List of benign packages with more than 90% similarity")
        #print("List of benign packages with more than 90% similarity")  # Debugging output
        logging.info("________________________________________________________")
        #print("________________________________________________________")  # Debugging output
        
        for match in best_matches:
            if match[1] > LOG_THRESHOLD:
                logging.info(f"Similar benign package: {match[0]} with similarity: {match[1]:.2f}")
                #print(f"Similar benign package: {match[0]} with similarity: {match[1]:.2f}")  # Debugging output
        
        logging.info("________________________________________________________")
        #print("________________________________________________________")  # Debugging output
        
        best_match = best_matches[0][0]
        best_similarity = best_matches[0][1]  # Get the best similarity score

        # Increment the total similarities counter if the similarity is above the threshold
        if best_similarity >= SIMILARITY_THRESHOLD:
            total_similarities += 1
            logging.info(f"Best match benign package: {best_match} with similarity: {best_similarity}")
            #print(f"Best match benign package: {best_match} with similarity: {best_similarity}")  # Debugging output
        
        try:
            package_info = requests.get(f"https://pypi.org/pypi/{best_match}/json").json()
            releases = package_info.get('releases', {})
            if releases:
                latest_version = max(releases.keys())
                if releases[latest_version]:
                    release_date = releases[latest_version][0].get('upload_time')
                    return best_match, latest_version, release_date, best_similarity
                else:
                    return best_match, latest_version, None, best_similarity
            else:
                logging.warning(f"No releases found for benign package: {best_match}")
                #print(f"No releases found for benign package: {best_match}")  # Debugging output
                return best_match, None, None, best_similarity
        except (requests.RequestException, KeyError, ValueError) as e:
            logging.error(f"Error fetching version info for benign package: {best_match}: {e}")
            #print(f"Error fetching version info for benign package: {best_match}: {e}")  # Debugging output
            return None, None, None, 0.0

    return None, None, None, 0.0

# Function to process each row
def process_row(index, row):
    malicious_name = row['Malicious Package Name']
    malicious_version = row['Malicious Package Version']
    logging.info("---------------------------------------------------------------------------")
    #print("---------------------------------------------------------------------------")  # Debugging output
    logging.info(f"Processing malicious package: {malicious_name} version: {malicious_version}")
    #print(f"Processing malicious package: {malicious_name} version: {malicious_version}")  # Debugging output
    benign_name, benign_version, benign_date, best_similarity = get_similar_package(malicious_name, malicious_version)
    if benign_name:
        s_df.at[index, 'Benign Package Name'] = benign_name
        s_df.at[index, 'Benign Package Version'] = benign_version
        s_df.at[index, 'Benign Release Date'] = benign_date
        s_df.at[index, 'Similarity Score'] = best_similarity

        # Log if the best similarity score exceeds the threshold
        if best_similarity >= BEST_LOG_THRESHOLD:
            logging.info(f"High similarity ({best_similarity:.2f}) found in malicious package: {malicious_name} | version: {malicious_version} with benign package: {benign_name} | version: {benign_version}")
            #print(f"High similarity ({best_similarity:.2f}) found in malicious package: {malicious_name} | version: {malicious_version} with benign package: {benign_name} | version: {benign_version}")  # Debugging output
    else:
        logging.info(f"No similar benign package found for malicious package: {malicious_name} | version: {malicious_version}") 
        #print(f"No similar benign package found for malicious package: {malicious_name} | version: {malicious_version}")  # Debugging output
        
    # Calculate and log the progress every 1%
    progress = ((index + 1) / total_rows) * 100
    if progress - process_row.last_printed_progress >= 1:
        logging.info(f"------------ Progress: {progress:.2f}% completed ------------")
        #print(f"------------  Progress: {progress:.2f}% completed ------------")  # Debugging output
        process_row.last_printed_progress = progress

process_row.last_printed_progress = 0  # Initialize static variable

# Iterate through each row in the dataframe
for index, row in s_df.iterrows():
    process_row(index, row)

# Log the total number of similarities found
logging.info(f"Total similarities found: {total_similarities}")
#print(f"Total similarities found: {total_similarities}")  # Debugging output

# Save the updated DataFrame back to an Excel file
output_file_path = 'CosineSimilarityOutput.xlsx'
s_df.to_excel(output_file_path, index=False)
logging.info(f"Results saved to {output_file_path}")
#print(f"Results saved to {output_file_path}")  # Debugging output