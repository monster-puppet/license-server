#!/usr/bin/env python
"""
publish_upload.py - Upload mk.zip to hub server with Maya version support

Usage: publish_upload.py <scripts_path> <upload_token> [maya_version]

Arguments:
  scripts_path   Path to the Maya scripts directory containing mk.zip
  upload_token   Authentication token for upload
  maya_version   Optional Maya version (e.g., 2024, 2025). If provided,
                 uploads to version-specific endpoint.
"""

import os
import sys
import urllib.request
import urllib.error

UPLOAD_URL = "https://hub.monster-puppet.com/upload/latest"


def main():
    if len(sys.argv) < 3:
        print("Usage: publish_upload.py <scripts_path> <upload_token> [maya_version]")
        sys.exit(1)
    
    scripts_path = sys.argv[1]
    upload_token = sys.argv[2]
    maya_version = sys.argv[3] if len(sys.argv) > 3 else None
    
    zip_path = os.path.join(scripts_path, "mk.zip")
    
    if not os.path.exists(zip_path):
        print(f"Error: mk.zip not found at {zip_path}")
        sys.exit(1)
    
    # Get file size
    file_size = os.path.getsize(zip_path)
    size_mb = file_size / (1024 * 1024)
    print(f"ZIP_SIZE_MB:{size_mb:.2f}")
    
    # Build URL with maya_version parameter if provided
    url = UPLOAD_URL
    if maya_version:
        url = f"{UPLOAD_URL}?maya_version={maya_version}"
        print(f"Uploading mk.zip for Maya {maya_version}...")
    else:
        print("Uploading mk.zip (generic)...")
    
    # Read file
    with open(zip_path, "rb") as f:
        file_data = f.read()
    
    # Create multipart form data
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="mk.zip"\r\n'
        f"Content-Type: application/zip\r\n\r\n"
    ).encode("utf-8") + file_data + f"\r\n--{boundary}--\r\n".encode("utf-8")
    
    headers = {
        "Authorization": upload_token,
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }
    
    # Add Maya version header as well for redundancy
    if maya_version:
        headers["X-Maya-Version"] = maya_version
    
    try:
        request = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(request, timeout=60) as response:
            result = response.read().decode("utf-8")
            print(f"Upload successful: {result}")
    except urllib.error.HTTPError as e:
        print(f"Upload failed: HTTP {e.code} - {e.read().decode('utf-8')}")
        sys.exit(1)
    except Exception as e:
        print(f"Upload failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
