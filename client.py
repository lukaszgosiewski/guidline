import requests
import os
import logging

# We don't need to configure logging here as it will be configured in the main script
# Just use the logger that's already configured

def get_token(url, username, password, client_id, grant_type='password'):
    """
    Get OAuth token using password grant type

    Args:
        url (str): The OAuth token endpoint URL
        username (str): The username for authentication
        password (str): The password for authentication
        client_id (str): The OAuth client ID
        grant_type (str, optional): The grant type. Defaults to 'password'

    Returns:
        dict or None: The token response as a dictionary, or None if the request failed
    """
    # Headers
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # Form data
    data = {
        'username': username,
        'password': password,
        'client_id': client_id,
        'grant_type': grant_type
    }
    logging.info(f"Attempt to authenticate on URL: {url}")
    logging.info(f"User: {username}")
    # Make the POST request
    response = requests.post(url, headers=headers, data=data)

    # Check if the request was successful
    if response.status_code == 200:
        logging.info("Authentication complete")
        return response.json()
    else:
        logging.error(f"Request failed with status code: {response.status_code}")
        logging.error(f"Response: {response.text}")
        return None


def send_project_data(url, token, project_name, branch, commit_hash, csv_file_path):
    """
    Send project data including text fields and a CSV file to the specified URL

    Args:
        url (str): The API endpoint URL
        token (str): OAuth access token
        project_name (str): Name of the project
        branch (str): Branch name
        commit_hash (str): Commit hash
        csv_file_path (str): Path to the CSV file to upload

    Returns:
        dict or None: The response as a dictionary, or None if the request failed
    """
    # Verify the file exists
    if not os.path.exists(csv_file_path):
        logging.error(f"CSV file not found: {csv_file_path}")
        raise FileNotFoundError(f"CSV file not found: {csv_file_path}")

    # Set up authorization header with the token
    headers = {
        'Authorization': f'Bearer {token}'
    }

    # Create multipart form data
    form_data = {
        'project': (None, project_name),
        'branch': (None, branch),
        'commit': (None, commit_hash),
        'hash': (None, commit_hash)
    }

    # Add the CSV file to the form data
    with open(csv_file_path, 'rb') as csv_file:
        form_data['file'] = (os.path.basename(csv_file_path), csv_file, 'text/csv')

        # Send the POST request with the form data and file
        response = requests.post(
            url,
            headers=headers,
            files=form_data,
            verify=False
        )

    logging.info(f"Attempt to send data tp URL: {url}")

    # Check if the request was successful
    if response.status_code in [200, 201, 202]:
        logging.info(f"Successfully sent project data: {project_name}, branch: {branch}")
        try:
            return response.json()
        except:
            # If the response is not JSON
            return {"status": "success", "response_text": response.text}
    else:
        logging.error(f"Request failed with status code: {response.status_code}")
        logging.error(f"Response: {response.text}")
        return None

def test_request():

    # URL of a publicly available test server
    url = 'https://httpbin.org/post'

    # Data to be sent in the POST request
    data = {
        'name': 'John Doe',
        'email': 'john.doe@example.com',
        'message': 'This is a test message'
    }

    # Send the POST request
    response = requests.post(url, data=data)

    # Check if the request was successful
    if response.status_code == 200:
        print('Success! Server responded with:')
        print(response.json())
    else:
        print(f'Failed with status code: {response.status_code}')
        print(response.text)