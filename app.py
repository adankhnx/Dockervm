import os
import uuid
import logging
from io import BytesIO
from flask import Flask, request, send_file, jsonify
from werkzeug.utils import secure_filename
import requests
import netifaces
import threading
import time
from datetime import datetime

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)

# ==================== IP Address & Role Determination ====================

def get_ipv4_addresses():
    ipv4_list = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr.get('addr')
                if ip and ip != "127.0.0.1":
                    ipv4_list.append(ip)
    return ipv4_list

def get_ipv6_addresses():
    ipv6_list = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                ip = addr.get('addr')
                if ip:
                    ip = ip.split('%')[0]  # remove zone index if any
                    if ip != "::1" and not ip.startswith("fe80"):
                        ipv6_list.append(ip)
    return ipv6_list

def get_public_ipv4():
    try:
        # Use a public API to get your public IPv4 address.
        response = requests.get("https://api.ipify.org", timeout=2)
        if response.status_code == 200:
            public_ip = response.text.strip()
            app.logger.debug(f"Public IPv4 address obtained: {public_ip}")
            return public_ip
    except Exception as e:
        app.logger.exception("Error fetching public IPv4 address:")
    return None

def get_public_ipv6():
    try:
        # Use a public API to get your public IPv6 address.
        response = requests.get("https://api64.ipify.org", timeout=2)
        if response.status_code == 200:
            public_ip = response.text.strip()
            # Validate that the response looks like an IPv6 address.
            if ":" in public_ip:
                app.logger.debug(f"Public IPv6 address obtained: {public_ip}")
                return public_ip
    except Exception as e:
        app.logger.exception("Error fetching public IPv6 address:")
    return None

def determine_role():
    # If any non-loopback IPv6 exists, designate as Relay.
    ipv6s = get_ipv6_addresses()
    if ipv6s:
        return "Relay"
    return "Adept"

# Automatically determine role based on IPs.
ROLE = determine_role()
app.logger.debug(f"Determined node role: {ROLE}")

# ==================== Configuration & Node Identification ====================

PORT = int(os.environ.get("PORT", 8080))
STORAGE_DIR = os.environ.get("STORAGE_DIR", "./storage")

# Supabase settings (update with your actual values)
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://your-project.supabase.co/rest/v1/users")
SUPABASE_API_KEY = os.environ.get("SUPABASE_API_KEY", "your_supabase_api_key")
NODE_NICKNAME = os.environ.get("NODE_NICKNAME", "FlaskNode")

if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)
    app.logger.debug(f"Created storage directory: {STORAGE_DIR}")
else:
    app.logger.debug(f"Using existing storage directory: {STORAGE_DIR}")

NODE_ID_FILE = "node_id.txt"
if os.path.exists(NODE_ID_FILE):
    with open(NODE_ID_FILE, "r") as f:
        NODE_ID = f.read().strip()
else:
    NODE_ID = str(uuid.uuid4())
    with open(NODE_ID_FILE, "w") as f:
        f.write(NODE_ID)
app.logger.debug(f"Node ID: {NODE_ID}")

def register_node_in_supabase():
    app.logger.info(">> Starting Supabase registration")
    app.logger.info(f"SUPABASE_URL: {SUPABASE_URL}, SUPABASE_API_KEY: {SUPABASE_API_KEY}")

    # Try to get public IPv6 first, then public IPv4.
    public_ipv6 = get_public_ipv6()
    if public_ipv6:
        real_ip = public_ipv6
    else:
        public_ipv4 = get_public_ipv4()
        if public_ipv4:
            real_ip = public_ipv4
        else:
            # If no public IP is available, use local addresses.
            if ROLE.lower() == "relay":
                ips = get_ipv6_addresses() or get_ipv4_addresses()
            else:
                ips = get_ipv4_addresses()
            real_ip = ips[0] if ips else "Unknown"

    data = {
        "id": NODE_ID,
        "nickname": NODE_NICKNAME,
        "role": ROLE,
        "ip_address": real_ip,
        "active": True,
        "locked_parameter": "InitialConfig",
        "shard_count": 0
    }

    app.logger.info(f"Registering node in Supabase: {data}")
    headers = {
        "apikey": SUPABASE_API_KEY,
        "Content-Type": "application/json",
        "Prefer": "return=representation,resolution=merge-duplicates"
    }
    try:
        r = requests.post(SUPABASE_URL, headers=headers, json=data)
        app.logger.debug(f"Supabase POST status: {r.status_code}")
        if r.status_code in (200, 201):
            app.logger.info(f"Node registered successfully in Supabase. Response: {r.json()}")
        elif r.status_code == 409:
            app.logger.info("Node already exists; proceeding to update its dynamic fields.")
            patch_headers = {
                "apikey": SUPABASE_API_KEY,
                "Content-Type": "application/json",
                "Prefer": "return=representation"
            }
            patch_url = SUPABASE_URL + f"?id=eq.{NODE_ID}"
            patch_data = {
                "ip_address": real_ip,
                "active": True
            }
            r_patch = requests.patch(patch_url, headers=patch_headers, json=patch_data)
            app.logger.debug(f"Supabase PATCH status: {r_patch.status_code}")
            if r_patch.status_code in (200, 201):
                app.logger.info(f"Node updated successfully in Supabase. Response: {r_patch.json()}")
            else:
                app.logger.error(f"Failed to update node in Supabase: {r_patch.text}")
        else:
            app.logger.error(f"Failed to register node in Supabase: {r.text}")
    except Exception as e:
        app.logger.exception("Exception during Supabase registration:")

register_node_in_supabase()

# ==================== DHT Manager ====================
class DHTManager:
    def __init__(self):
        self.shard_map = {}   # Mapping: shard_id -> destination Adept node UUID
        self.node_map = {}    # Mapping: node UUID -> real IP address
        self.adept_nodes = [] # List of available Adept node UUIDs
        self.current_adept_index = 0

    def register_node(self, uuid_val, real_ip):
        self.node_map[uuid_val] = real_ip
        if uuid_val not in self.adept_nodes:
            self.adept_nodes.insert(0, uuid_val)
        app.logger.debug(f"[DHTManager] Registered node {uuid_val} with IP {real_ip}")

    def register_shard(self, shard_id, adept_node_uuid):
        self.shard_map[shard_id] = adept_node_uuid
        app.logger.debug(f"[DHTManager] Registered shard {shard_id} with Adept node {adept_node_uuid}")

    def get_shard_location(self, shard_id):
        node_uuid = self.shard_map.get(shard_id)
        app.logger.debug(f"[DHTManager] Shard {shard_id} is registered to node {node_uuid}")
        return node_uuid

    def get_all_shards(self):
        app.logger.debug(f"[DHTManager] Current shard map: {self.shard_map}")
        return self.shard_map.copy()

    def find_available_adept_node(self):
        if not self.adept_nodes:
            app.logger.warning("[DHTManager] No Adept nodes available!")
            return None
        node_uuid = self.adept_nodes[self.current_adept_index]
        app.logger.debug(f"[DHTManager] Selected Adept node: {node_uuid}")
        self.current_adept_index = (self.current_adept_index + 1) % len(self.adept_nodes)
        return node_uuid

    def log_state(self):
        app.logger.debug("=== DHT STATE ===")
        app.logger.debug(f"Node Map: {self.node_map}")
        app.logger.debug(f"Shard Map: {self.shard_map}")
        app.logger.debug(f"Adept Nodes: {self.adept_nodes}")
        app.logger.debug(f"Current Adept Index: {self.current_adept_index}")
        app.logger.debug("=================")

dht_manager = DHTManager()

# Determine our prioritized IP address for DHT registration:
# 1. Prefer public IPv6, then public IPv4.
public_ipv6 = get_public_ipv6()
if public_ipv6:
    my_ip = public_ipv6
else:
    public_ipv4 = get_public_ipv4()
    if public_ipv4:
        my_ip = public_ipv4
    else:
        if ROLE.lower() == "adept":
            ips = get_ipv4_addresses()
        else:
            ips = get_ipv6_addresses() or get_ipv4_addresses()
        my_ip = ips[0] if ips else "Unknown"

dht_manager.register_node(NODE_ID, my_ip)
dht_manager.log_state()

# ==================== Shard Manager ====================
def shard_file(file_obj, chunk_size=64*1024):
    """
    Splits the uploaded file into shards.
    Returns a list of tuples: (shard_id, BytesIO object)
    """
    content = file_obj.read()
    shards = []
    base_filename = os.path.splitext(secure_filename(file_obj.filename))[0]
    for i in range(0, len(content), chunk_size):
        chunk = content[i:i+chunk_size]
        shard_id = f"{base_filename}_shard_{i//chunk_size}"
        shards.append((shard_id, BytesIO(chunk)))
    app.logger.debug(f"File sharded into {len(shards)} shards.")
    return shards

# ==================== Flask Endpoints ====================

@app.route("/")
def index():
    return jsonify({
        "message": f"Hello from the {ROLE} node!",
        "role": ROLE,
        "storage_dir": STORAGE_DIR,
        "ipv4": get_ipv4_addresses(),
        "ipv6": get_ipv6_addresses(),
        "node_id": NODE_ID
    })

@app.route("/store", methods=["POST"])
def store():
    if "file" not in request.files:
        return "No file part", 400
    file = request.files["file"]
    if file.filename == "":
        return "No selected file", 400
    filename = secure_filename(file.filename)
    app.logger.debug(f"Received file: {filename}")

    # Check for header that marks forwarded requests.
    is_forwarded = request.headers.get("X-Forwarded", "false").lower() == "true"

    if is_forwarded:
        # This is a forwarded shard. Only Adept nodes should store forwarded shards.
        if ROLE.lower() != "adept":
            return "Relay nodes do not store forwarded shards", 403
        destination = os.path.join(STORAGE_DIR, filename)
        file.save(destination)
        app.logger.info(f"Stored forwarded shard locally at: {destination}")
        return "Forwarded shard stored successfully", 200

    # Original upload.
    if ROLE.lower() == "adept":
        # An Adept node: shard its own uploaded file and forward each shard to a Relay.
        shards = shard_file(file)
        relay_endpoint = os.environ.get("RELAY_ENDPOINT", "http://localhost:8080")
        for shard_id, shard_stream in shards:
            files = {"file": (f"{filename}_{shard_id}", shard_stream, "application/octet-stream")}
            try:
                r = requests.post(f"{relay_endpoint}/store", files=files, headers={"X-Forwarded": "true"})
                if r.status_code != 200:
                    app.logger.error(f"Error forwarding shard {shard_id}: {r.text}")
            except Exception as e:
                app.logger.exception(f"Exception forwarding shard {shard_id}: {e}")
        return "File sharded and forwarded to Relay", 200

    elif ROLE.lower() == "relay":
        # A Relay node: forward the uploaded file (or shard) to a designated Adept node.
        content = file.read()
        files = {"file": (filename, BytesIO(content), file.content_type)}
        target_adept_endpoint = os.environ.get("ADEPT_ENDPOINT", "http://localhost:8081")
        try:
            r = requests.post(f"{target_adept_endpoint}/store", files=files, headers={"X-Forwarded": "true"})
            if r.status_code == 200:
                # Update the DHT: assign this file (or shard) to a chosen Adept node.
                target_uuid = dht_manager.find_available_adept_node()
                if target_uuid:
                    dht_manager.register_shard(filename, target_uuid)
                return "File forwarded to Adept", 200
            else:
                app.logger.error(f"Error forwarding file to Adept: {r.text}")
                return f"Error: {r.text}", 500
        except Exception as e:
            app.logger.exception("Exception during file forwarding:")
            return "Exception during file forwarding", 500

    else:
        return "Unknown role", 403

@app.route("/download", methods=["GET"])
def download():
    filename = request.args.get("file")
    if not filename:
        return "File parameter missing", 400
    filepath = os.path.join(STORAGE_DIR, filename)
    if not os.path.exists(filepath):
        app.logger.error(f"File not found: {filepath}")
        return "File not found", 404
    try:
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        app.logger.exception("Error serving file:")
        return "Error serving file", 500

@app.route("/dht", methods=["GET"])
def dht():
    return jsonify({
        "node_map": dht_manager.node_map,
        "shard_map": dht_manager.shard_map,
        "adept_nodes": dht_manager.adept_nodes,
        "current_adept_index": dht_manager.current_adept_index
    })
import threading
import time
from datetime import datetime

# ---------------- Heartbeat Functionality ----------------

# Configure the endpoint for heartbeat updates. 
# You can use the same SUPABASE_URL if your table is the same,
# or a dedicated endpoint if you've set one up.
SUPABASE_HEARTBEAT_URL = SUPABASE_URL  # or set a different endpoint if needed

headers = {
    "apikey": SUPABASE_API_KEY,
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

def send_heartbeat():
    # Create the heartbeat payload with last_seen as an array
    heartbeat_data = {
        "id": NODE_ID,
        "active": True,
        "last_seen": [datetime.utcnow().isoformat() + "Z"]
    }
    try:
        # Use PATCH to update only the fields that change.
        response = requests.patch(
            f"{SUPABASE_HEARTBEAT_URL}?id=eq.{NODE_ID}",
            headers=headers,
            json=heartbeat_data,
            timeout=5
        )
        if response.status_code in (200, 201):
            app.logger.debug("Heartbeat sent successfully.")
        else:
            app.logger.error(f"Heartbeat update failed: {response.text}")
    except Exception as e:
        app.logger.exception("Exception sending heartbeat:")

def heartbeat_loop(interval=60):
    """Continuously send heartbeat updates every 'interval' seconds."""
    while True:
        send_heartbeat()
        time.sleep(interval)

# Start the heartbeat loop in a daemon thread so it runs in the background.
heartbeat_thread = threading.Thread(target=heartbeat_loop, args=(60,), daemon=True)
heartbeat_thread.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
