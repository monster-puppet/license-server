import os
import urllib.request
import hashlib
import shutil
import socket
import zipfile
import maya.cmds as cmds
import settings

URL_LATEST = "https://hub.monster-puppet.com/download/latest"

def get_maya_version():
    """Get the Maya major version (e.g., '2024', '2025')."""
    try:
        version = cmds.about(version=True)
        return version.split()[0] if version else None
    except Exception:
        return None

def calculate_checksum(file_path):
    if not os.path.exists(file_path):
        return None
    hasher = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def run_update():    
    bin_path = os.path.normpath(os.path.join(settings.paths.root, "bin"))
    scripts_path = os.path.normpath(os.path.join(settings.paths.root, "scripts"))
    mk_path = os.path.normpath(os.path.join(scripts_path, "mk"))

    os.makedirs(bin_path, exist_ok=True)

    # Get Maya version for version-specific download
    maya_version = get_maya_version()
    
    local_zip_path = os.path.join(bin_path, "latest")
    token_file_path = os.path.join(bin_path, "token")

    if not os.path.exists(token_file_path):
        print("[MONSTER PUPPET] Error: No token found")
        return

    try:
        with open(token_file_path, "r") as token_file:
            client_token = token_file.read().strip()
            if not client_token:
                print("[MONSTER PUPPET] Error: Token is empty")
                return
    except Exception as e:
        print(f"[MONSTER PUPPET] Error reading token: {e}")
        return

    # Build URL with Maya version parameter
    url = URL_LATEST
    if maya_version:
        url = f"{URL_LATEST}?maya_version={maya_version}"
        print(f"[MONSTER PUPPET] Checking for library updates (Maya {maya_version})...")
    else:
        print(f"[MONSTER PUPPET] Checking for library updates...")
    
    try:
        headers = {
            "Authorization": client_token,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
        }
        # Also add Maya version as header for redundancy
        if maya_version:
            headers["X-Maya-Version"] = maya_version
            
        request = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(request, timeout=5) as response:
            remote_zip_data = response.read()
            remote_checksum = hashlib.md5(remote_zip_data).hexdigest()

            local_checksum = calculate_checksum(local_zip_path)

            if remote_checksum == local_checksum:
                print("[MONSTER PUPPET] No updates available")
                return

            with open(local_zip_path, "wb") as f:
                f.write(remote_zip_data)
            print(f"[MONSTER PUPPET] Downloaded update to {local_zip_path}")

            # Remove only the mk folder, not the entire scripts folder
            if os.path.exists(mk_path):
                shutil.rmtree(mk_path)

            print(f"[MONSTER PUPPET] Unpacking update to {scripts_path}...")
            with zipfile.ZipFile(local_zip_path, "r") as zip_ref:
                zip_ref.extractall(scripts_path)

            print(f"[MONSTER PUPPET] Successfully unpacked update")
    except urllib.error.HTTPError as e:
        print(f"[MONSTER PUPPET] Error {e.code}: {e.read().decode('utf-8')}")
    except socket.timeout:
        print("[MONSTER PUPPET] Error: The request timed out after 5 seconds.")
    except Exception as e:
        print(f"[MONSTER PUPPET] Unexpected error: {e}")
