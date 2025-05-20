import subprocess
import sys
import os
from pathlib import Path
import platform
import shutil
import requests
import tarfile
import zipfile
import stat
import magic
import client
import logging
import glob

import csv
import os
import io


def merge_codeql_csvs(file_suite_map: dict, output_path: str):
    """
    Merge multiple CSV files into a single file with an added Suite column.

    Parameters:
    - file_suite_map: dictionary mapping file paths to suite names
    - output_path: path for the merged output file

    This function:
    - Properly handles CSV parsing to preserve quoting
    - Replaces any newlines inside field values with spaces
    - Adds a Suite column with the appropriate suite name
    - Writes to a single output file with all fields quoted
    """
    header = [
        "Name", "Description", "Severity", "Message", "Path",
        "Start line", "Start column", "End line", "End column", "Suite"
    ]

    with open(output_path, "w", encoding="utf-8", newline="") as out_file:
        # Use QUOTE_ALL to quote every field
        writer = csv.writer(out_file, quoting=csv.QUOTE_ALL)
        writer.writerow(header)

        for file_path, suite_name in file_suite_map.items():
            try:
                with open(file_path, "r", encoding="utf-8", newline="") as in_file:
                    # First read the entire file content
                    content = in_file.read()

                    # Create a StringIO object to use with csv.reader
                    csv_io = io.StringIO(content)
                    reader = csv.reader(csv_io)

                    # Skip header
                    next(reader, None)

                    for row in reader:
                        # Skip empty rows
                        if not any(row):
                            continue

                        # Replace newlines in each field with spaces
                        cleaned_row = [field.replace('\n', ' ').replace('\r', ' ') for field in row]

                        # Add suite name
                        cleaned_row.append(suite_name)

                        # Write the row with quoting
                        writer.writerow(cleaned_row)
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")


def download_file(url, output_path):
    """Download a file with simple progress indication."""
    response = requests.get(url, stream=True)
    response.raise_for_status()
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024  # 1 KB
    downloaded = 0

    logging.info(f"Downloading {os.path.basename(output_path)}...")
    with open(output_path, 'wb') as file:
        for data in response.iter_content(block_size):
            file.write(data)
            downloaded += len(data)
            if total_size > 0:
                percentage = (downloaded / total_size) * 100
                # Progress updates are too frequent for a log file, so we'll omit them
    logging.info("Download complete!")

def check_and_reassemble_split_archive(install_dir, filename_prefix, output_filename):
    """
    Check for split archives with the given prefix and reassemble them if found.
    Returns True if reassembled successfully, False otherwise.
    """
    # Look for split parts with the given prefix
    split_parts = sorted(glob.glob(os.path.join(install_dir, f"{filename_prefix}*")))

    if not split_parts:
        logging.info(f"No split archive parts found with prefix '{filename_prefix}'")
        return False

    output_path = os.path.join(install_dir, output_filename)

    # If output file already exists, check if we should overwrite
    if os.path.exists(output_path):
        logging.info(f"Archive {output_filename} already exists in {install_dir}")
        return True

    logging.info(f"Found {len(split_parts)} split archive parts. Reassembling to {output_filename}...")

    try:
        # Reassemble the file parts
        with open(output_path, 'wb') as outfile:
            for part in split_parts:
                with open(part, 'rb') as infile:
                    shutil.copyfileobj(infile, outfile)

        logging.info(f"Successfully reassembled split archive into {output_filename}")
        return True
    except Exception as e:
        logging.error(f"Error reassembling split archive: {str(e)}")
        if os.path.exists(output_path):
            os.remove(output_path)
        return False

def ensure_package_directory_exists():
    """
    Ensure the ~/.codeql/packages/codeql directory exists.
    Returns the path to the directory.
    """
    os_name = platform.system().lower()
    if os_name == 'windows':
        packages_dir = os.path.expandvars(r'%LOCALAPPDATA%\codeql\packages\codeql')
    else:
        packages_dir = os.path.expanduser('~/.codeql/packages/codeql')

    os.makedirs(packages_dir, exist_ok=True)
    return packages_dir

def copy_coding_standards():
    """
    Extract coding standards archive if it exists and copy only the 2.43.0 version
    to the user's packages directory.
    """
    # Check for the standards archive
    standards_zip = os.path.join(Path.cwd(), 'codeql/codeql_coding_standards.zip')
    if not os.path.exists(standards_zip):
        logging.info("Coding standards archive not found. Will be downloaded during analysis.")
        return False

    # Create a temporary directory for extraction
    temp_extract_dir = os.path.join(Path.cwd(), 'codeql/temp_standards_extract')
    os.makedirs(temp_extract_dir, exist_ok=True)
    coding_standards_dir = os.path.join(temp_extract_dir, "codeql_coding_standards")

    try:
        # Extract the standards archive
        logging.info(f"Extracting coding standards archive...")
        with zipfile.ZipFile(standards_zip, 'r') as zip_ref:
            zip_ref.extractall(temp_extract_dir)

        # Ensure the target packages directory exists
        packages_dir = ensure_package_directory_exists()

        # Copy only the specific version directory
        logging.info(f"Copying coding standards to {packages_dir}...")
        shutil.copytree(coding_standards_dir, packages_dir, dirs_exist_ok=True)

        logging.info("Coding standards copied successfully.")

        # Clean up the temporary extraction directory
        shutil.rmtree(temp_extract_dir)
        return True
    except Exception as e:
        logging.error(f"Error processing CERT C standards: {str(e)}")
        if os.path.exists(temp_extract_dir):
            shutil.rmtree(temp_extract_dir)
        return False

def install_codeql():
    """
    Download and install CodeQL CLI.
    Returns the path to the installed CodeQL executable.
    """
    os_name = platform.system().lower()
    machine = platform.machine().lower()

    # Determine download URL based on OS and architecture
    base_url = "https://github.com/github/codeql-cli-binaries/releases/latest/download/"

    if os_name == 'windows':
        if machine in ['amd64', 'x86_64']:
            filename = "codeql-win64.zip"
        else:
            raise SystemError(f"Unsupported Windows architecture: {machine}")
    elif os_name == 'linux':
        if machine in ['amd64', 'x86_64']:
            filename = "codeql-linux64.zip"
        else:
            raise SystemError(f"Unsupported Linux architecture: {machine}")
    elif os_name == 'darwin':
        if machine in ['arm64', 'aarch64']:
            filename = "codeql-osx-arm64.zip"
        elif machine in ['amd64', 'x86_64']:
            filename = "codeql-osx64.zip"
        else:
            raise SystemError(f"Unsupported macOS architecture: {machine}")
    else:
        raise SystemError(f"Unsupported operating system: {os_name}")

    download_url = base_url + filename

    # Create installation directory
    if os_name == 'windows':
        install_dir = os.path.expandvars(r'%LOCALAPPDATA%\Programs\codeql')
    else:
        #install_dir = os.path.expanduser('~/codeql')
        install_dir = './codeql'

    os.makedirs(install_dir, exist_ok=True)

    # Check for split archive parts for Linux (most common use case)
    temp_file = os.path.join(install_dir, filename)
    if os_name == 'linux' and machine in ['amd64', 'x86_64']:
        split_archive_reassembled = check_and_reassemble_split_archive(
            install_dir,
            "codeql-linux64_",
            filename
        )
        if split_archive_reassembled:
            logging.info(f"Using reassembled archive {filename}")
        elif os.path.exists(temp_file):
            logging.info(f"Archive {filename} already exists in {install_dir}. Skipping download.")
        else:
            # Download CodeQL
            logging.info(f"Downloading CodeQL CLI from {download_url}...")
            download_file(download_url, temp_file)
    else:
        # For other platforms, follow the original logic
        if os.path.exists(temp_file):
            logging.info(f"Archive {filename} already exists in {install_dir}. Skipping download.")
        else:
            # Download CodeQL
            logging.info(f"Downloading CodeQL CLI from {download_url}...")
            download_file(download_url, temp_file)

    # Extract files
    logging.info("Extracting files...")
    extraction_dir = os.path.join(install_dir, 'temp_extract')
    os.makedirs(extraction_dir, exist_ok=True)

    if filename.endswith('.zip'):
        with zipfile.ZipFile(temp_file, 'r') as zip_ref:
            zip_ref.extractall(extraction_dir)
    else:
        with tarfile.open(temp_file, 'r:gz') as tar_ref:
            tar_ref.extractall(extraction_dir)

    # Find the extracted codeql directory
    codeql_extracted_dir = None
    for item in os.listdir(extraction_dir):
        item_path = os.path.join(extraction_dir, item)
        if os.path.isdir(item_path) and ('codeql' in item.lower() or 'codeql' in os.listdir(item_path)):
            codeql_extracted_dir = item_path
            break

    if not codeql_extracted_dir:
        # If we can't find it, just use the extraction directory
        codeql_extracted_dir = extraction_dir

    # Create or replace the target codeql directory
    target_codeql_dir = os.path.join(install_dir, 'codeql')
    if os.path.exists(target_codeql_dir):
        shutil.rmtree(target_codeql_dir)

    # Move the extracted content to the target directory
    if os.path.basename(codeql_extracted_dir).lower() == 'codeql':
        # If the extracted dir is already named 'codeql', move its contents directly
        shutil.move(codeql_extracted_dir, target_codeql_dir)
    else:
        # Otherwise, create the target dir and move contents there
        os.makedirs(target_codeql_dir, exist_ok=True)
        for item in os.listdir(codeql_extracted_dir):
            src = os.path.join(codeql_extracted_dir, item)
            dst = os.path.join(target_codeql_dir, item)
            shutil.move(src, dst)

    # Clean up the temporary extraction directory
    if os.path.exists(extraction_dir):
        shutil.rmtree(extraction_dir)

    # Set up executable path
    codeql_exec = os.path.join(install_dir, 'codeql', 'codeql.exe' if os_name == 'windows' else 'codeql')

    # Make executable on Unix-like systems
    if os_name != 'windows':
        make_executables_executable(install_dir)

    # Add to PATH if on Windows
    if os_name == 'windows':
        try:
            subprocess.run(['setx', 'PATH', f"%PATH%;{os.path.dirname(codeql_exec)}"], check=True)
            logging.info("Added CodeQL to PATH. Please restart your terminal for the changes to take effect.")
        except subprocess.CalledProcessError:
            logging.warning("Warning: Could not add CodeQL to PATH automatically.")

    logging.info(f"CodeQL CLI installed successfully at: {codeql_exec}")
    return codeql_exec

def check_os_and_codeql():
    """
    Check the operating system and verify CodeQL CLI installation.
    Returns tuple of (os_name, codeql_path) or attempts to install if not found.
    """
    os_name = platform.system().lower()
    if os_name not in ['windows', 'linux', 'darwin']:
        raise SystemError(f"Unsupported operating system: {os_name}")

    # Check for CodeQL CLI installation
    codeql_cmd = 'codeql.exe' if os_name == 'windows' else 'codeql'
    codeql_path = shutil.which(codeql_cmd)

    if not codeql_path:
        # Check common installation locations
        common_locations = {
            'windows': [
                os.path.expandvars(r'%LOCALAPPDATA%\Programs\codeql\codeql'),
                os.path.expandvars(r'%PROGRAMFILES%\codeql\codeql'),
            ],
            'linux': [
                '/usr/local/bin/codeql',
                '/usr/bin/codeql',
                os.path.expanduser('~/.codeql/cli/codeql/codeql'),
                str(Path.cwd()) + '/codeql/codeql/codeql',
                str(Path.cwd()) + '/codeql/codeql',
            ],
            'darwin': [
                '/usr/local/bin/codeql',
                os.path.expanduser('~/.codeql/cli/codeql/codeql'),
                './codeql/codeql',
            ]
        }

        for location in common_locations.get(os_name, []):
            if os_name == 'windows':
                full_path = location + '.exe'
            else:
                full_path = location
            logging.info(full_path)
            if os.path.isfile(full_path):
                codeql_path = full_path
                break

    if not codeql_path:
        logging.info("CodeQL CLI not found. Attempting to install...")
        try:
            codeql_path = install_codeql()
        except Exception as e:
            raise RuntimeError(f"Failed to install CodeQL CLI: {str(e)}")

    copy_coding_standards()

    # Verify CodeQL version
    try:
        version_output = subprocess.check_output([codeql_path, "version"],
                                               stderr=subprocess.STDOUT,
                                               universal_newlines=True)
        logging.info(f"Found CodeQL CLI: {codeql_path}")
        logging.info(f"Version information:\n{version_output.strip()}")
        return os_name, codeql_path
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Error checking CodeQL version: {e.output}")

def run_codeql_analysis(c_path, script_path):
    try:
        # Check OS and CodeQL installation first
        os_name, codeql_path = check_os_and_codeql()

        # Convert paths to absolute paths
        c_path = os.path.abspath(c_path)
        script_path = os.path.abspath(script_path)

        # Verify paths exist
        if not os.path.exists(c_path):
            raise FileNotFoundError(f"C source path does not exist: {c_path}")
        if not os.path.exists(script_path):
            raise FileNotFoundError(f"Shell script does not exist: {script_path}")

        # Create database
        logging.info("Creating CodeQL database...")
        create_cmd = [
            codeql_path, "database", "create", "codeql_db", "--overwrite",
            "--language=c",
            f"--command={script_path}",
            "--source-root", c_path
        ]
        subprocess.run(create_cmd, check=True)


        # Analyze database
        logging.info("Analyzing database...")
        analyze_cmd = [
            codeql_path, "database", "analyze",
            "--format=csv",
            "--output=./output/results_cert.csv",
            "--download",
            "codeql_db",
            "codeql/cert-c-coding-standards@2.43.0",
            # "codeql/cert-cpp-coding-standards@2.43.0",
        ]
        subprocess.run(analyze_cmd, check=True)

        analyze_cmd = [
            codeql_path, "database", "analyze",
            "--format=csv",
            "--output=./output/results_misra.csv",
            "--download",
            "codeql_db",
            # "codeql/misra-cpp-coding-standards@2.43.0",
            "codeql/misra-c-coding-standards@2.43.0",
        ]

        subprocess.run(analyze_cmd, check=True)

        files = {
            "./output/results_cert.csv": "Cert-C",
            "./output/results_misra.csv": "Misra"
        }

        merge_codeql_csvs(files, "./output/results.csv")

        logging.info(f"Analysis complete. Results saved to results.csv")

    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing CodeQL command: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        logging.error(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)


def make_executables_executable(directory_path, recursive=True):
    """
    Add executable permissions to all files that appear to be executables
    in the specified directory and optionally its subdirectories.

    Args:
        directory_path: Path to the directory to process
        recursive: Whether to recursively process subdirectories
    """
    for entry in os.listdir(directory_path):
        entry_path = os.path.join(directory_path, entry)

        # If it's a directory and we're in recursive mode, process it
        if os.path.isdir(entry_path) and recursive:
            make_executables_executable(entry_path, recursive)
            continue

        # Skip if it's not a file
        if not os.path.isfile(entry_path):
            continue

        # Check if file is an executable using python-magic
        file_type = magic.from_file(entry_path)
        is_executable = any(exec_type in file_type.lower() for exec_type in
                          ['executable', 'elf', 'script', 'python', 'shell'])

        if is_executable:
            # Get current permissions
            current_permissions = os.stat(entry_path).st_mode

            # Add executable bit for user, group, and others
            new_permissions = current_permissions | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH

            # Set new permissions
            os.chmod(entry_path, new_permissions)
            logging.info(f"Made executable: {entry_path}")

def main():
    # Check for the correct number of arguments
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'output')
    if not os.path.exists(output_path):
        os.makedirs(output_path)
        print(f"Directory created: {output_path}")
    log_path = os.path.join(output_path, 'log.txt')
    result_path = os.path.join(output_path, 'results.csv')


    # Configure logging to write to log.txt
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        handlers=[
            logging.FileHandler(log_path),
            logging.StreamHandler(sys.stdout)
        ]
    )

    logging.info(sys.argv)
    if len(sys.argv) < 10:
        logging.error("Usage: python wrap.py <code_path> <build_script> <repo_name> <branch_name> <commit_hash> <auth_url> <app_url> <username> <password> [user_archive]")
        sys.exit(1)

    # Get positional arguments
    code_path = sys.argv[1]
    build_script = sys.argv[2]
    repo_name = sys.argv[3]
    branch_name = sys.argv[4]
    commit_hash = sys.argv[5]
    auth_url = sys.argv[6]
    app_url = sys.argv[7]
    username = sys.argv[8]
    password = sys.argv[9]

    # Check if user_archive is provided (optional 10th argument)
    user_archive = sys.argv[10] if len(sys.argv) > 10 else None

    # Set paths based on whether user provided an archive
    if user_archive:
        base_path = f"/workspace/usercode/{user_archive}"
        c_path = code_path if code_path else f"{base_path}"
        script_path = build_script if build_script else f"{base_path}"
    else:
        c_path = code_path if code_path else "/workspace/testproject/code"
        script_path = build_script if build_script else "/workspace/testproject/script.sh"

    logging.info(f"Using code path: {c_path}")
    logging.info(f"Using build script: {script_path}")
    logging.info(f"Repository: {repo_name}")
    logging.info(f"Branch: {branch_name}")
    logging.info(f"Commit: {commit_hash}")

    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    run_codeql_analysis(c_path, script_path)

    # Add https:// prefix to app_url if not present
    if app_url and not app_url.startswith(('http://', 'https://')):
        endpoint = f"https://{app_url}"
    else:
        endpoint = app_url

    client.test_request()

    for item in Path(output_path).iterdir():
        print(item.absolute())

    token_response = client.get_token(auth_url, username, password, 'argus_api')
    if token_response:
        client.send_project_data(endpoint, token_response.get('access_token'),
                                repo_name, branch_name, commit_hash, Path(result_path))
    else:
        logging.error("Failed to get authentication token. Cannot send project data.")

    files = os.listdir(output_path)

    for item in Path(output_path).iterdir():
        print(item.absolute())

if __name__ == "__main__":
    main()