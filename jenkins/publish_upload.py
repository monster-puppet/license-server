import os
import requests
import argparse

UPLOAD_URL = "https://hub.monster-puppet.com/upload/latest"
DEFAULT_ZIP_FILE = "mk.zip"


def upload_zip_file(zip_file_path, upload_url, token, maya_version=None):
    """
    Uploads a zip file to the specified URL with the given authorization token.

    Args:
        zip_file_path (str): Path to the zip file to upload.
        upload_url (str): URL to upload the file to.
        token (str): Authorization token for the upload.
        maya_version (str, optional): Maya version (e.g., '2024', '2025').
                                       If provided, uploads to version-specific endpoint.
    """
    try:
        if not os.path.exists(zip_file_path):
            print(f"Error: File {zip_file_path} does not exist.")
            return

        # Build URL with maya_version parameter if provided
        url = upload_url
        if maya_version:
            url = f"{upload_url}?maya_version={maya_version}"
            print(f"Uploading {zip_file_path} to {url} (Maya {maya_version})...")
        else:
            print(f"Uploading {zip_file_path} to {url}...")

        # Open the zip file for upload
        with open(zip_file_path, "rb") as file:
            headers = {"Authorization": token}
            # Also add Maya version as header for redundancy
            if maya_version:
                headers["X-Maya-Version"] = maya_version
            files = {"file": (os.path.basename(zip_file_path), file)}
            response = requests.post(url, headers=headers, files=files)

        # Check the response status
        if response.status_code == 200:
            print(f"File uploaded successfully: {response.json()}")
        else:
            print(
                f"Failed to upload file. Status code: {response.status_code}, Response: {response.text}"
            )
    except Exception as e:
        print(f"An error occurred during upload: {e}")
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Upload a zip file to the server.")
    parser.add_argument(
        "root_path", type=str, help="Root path where the zip file is located."
    )
    parser.add_argument("token", type=str, help="Authorization token for the upload.")
    parser.add_argument(
        "maya_version", 
        type=str, 
        nargs="?",  # Makes it optional
        default=None,
        help="Maya version (e.g., 2024, 2025). If provided, uploads to version-specific endpoint."
    )
    args = parser.parse_args()

    # Parse arguments
    root_path = args.root_path
    secret_token = args.token
    maya_version = args.maya_version

    # Define the zip file path
    zip_file_path = os.path.normpath(os.path.join(root_path, DEFAULT_ZIP_FILE))

    if not os.path.isfile(zip_file_path):
        raise FileNotFoundError(f"File not found: {zip_file_path}")

    zip_size_bytes = os.path.getsize(zip_file_path)
    zip_size_mb = round(zip_size_bytes / (1024 * 1024.0), 2)
    print(f"ZIP_SIZE_MB:{zip_size_mb}")

    upload_zip_file(zip_file_path, UPLOAD_URL, secret_token, maya_version)
