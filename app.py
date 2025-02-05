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

# ==================== Helper Functions ====================
def format_ip_for_url(ip):
    """Wrap IPv6 addresses in square brackets for URL usage."""
    if ":" in ip:
        return f"[{ip}]"
    return ip

def normalize_ip(ip):
    """
    Normalize IP addresses:
    - If an IPv4-mapped IPv6 address is detected (starts with "::ffff:"), strip the prefix.
    - Otherwise, return the IP as is.
    """
    if not ip:
        return ""
    if ip.startswith("::ffff:"):
        return ip.replace("::ffff:", "")
    return ip

# ==================== IP Address & Role Determination ====================
def get_ipv4_addresses():
    ipv4_list = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr.get('addr')
                if ip and ip != "127.0.0.1":
                    ipv4_list.append(normalize_ip(ip))
    app.logger.debug(f"Local IPv4 addresses: {ipv4_list}")
    return ipv4_list

def get_ipv6_addresses():
    ipv6_list = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET6 in addrs:
            for addr in addrs[netifaces.AF_INET6]:
                ip = addr.get('addr')
                if ip:
                    ip = ip.split('%')[0]
                    if ip != "::1" and not ip.startswith("fe80"):
                        ipv6_list.append(normalize_ip(ip))
    app.logger.debug(f"Local IPv6 addresses: {ipv6_list}")
    return ipv6_list

def get_public_ipv4():
    try:
        response = requests.get("https://api.ipify.org", timeout=2)
        if response.status_code == 200:
            public_ip = normalize_ip(response.text.strip())
            app.logger.debug(f"Public IPv4 address obtained: {public_ip}")
            return public_ip
    except Exception as e:
        app.logger.exception("Error fetching public IPv4 address:")
    return None

def get_public_ipv6():
    try:
        response = requests.get("https://api64.ipify.org", timeout=2)
        if response.status_code == 200:
            public_ip = response.text.strip()
            if ":" in public_ip:
                public_ip = normalize_ip(public_ip)
                app.logger.debug(f"Public IPv6 address obtained: {public_ip}")
                return public_ip
    except Exception as e:
        app.logger.exception("Error fetching public IPv6 address:")
    return None

def get_public_ips():
    """Return a tuple (ipv4, ipv6) based on public queries (with fallback to local addresses)."""
    ipv4 = get_public_ipv4()
    if not ipv4:
        ipv4s = get_ipv4_addresses()
        ipv4 = ipv4s[0] if ipv4s else "Unknown"
    ipv6 = get_public_ipv6()
    if not ipv6:
        ipv6s = get_ipv6_addresses()
        ipv6 = ipv6s[0] if ipv6s else ""
    app.logger.debug(f"Public IPs determined as: IPv4={ipv4}, IPv6={ipv6}")
    return ipv4, ipv6

def get_preferred_ip():
    """Returns the preferred IP address for communication, prioritizing IPv6."""
    ipv4, ipv6 = get_public_ips()
    if ipv6:
        app.logger.debug(f"Preferred IP (IPv6): {ipv6}")
        return ipv6
    app.logger.debug(f"Preferred IP (IPv4): {ipv4}")
    return ipv4

def determine_role():
    """Auto-detect role based on presence of non-loopback IPv6 addresses."""
    ipv6s = get_ipv6_addresses()
    if ipv6s:
        app.logger.info("Determined node role as Relay based on available IPv6 addresses.")
        return "Relay"
    app.logger.info("Determined node role as Adept (no non-loopback IPv6 addresses found).")
    return "Adept"

ROLE = os.environ.get("ROLE", determine_role())
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
    app.logger.debug(f"Loaded existing Node ID: {NODE_ID}")
else:
    NODE_ID = str(uuid.uuid4())
    with open(NODE_ID_FILE, "w") as f:
        f.write(NODE_ID)
    app.logger.debug(f"Generated new Node ID: {NODE_ID}")

# Global variable for Adept's shard count.
adept_shard_count = 0

def update_shard_count_in_supabase():
    """Update the shard_count field for this node in Supabase."""
    data = {"shard_count": adept_shard_count}
    headers = {
        "apikey": SUPABASE_API_KEY,
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }
    patch_url = SUPABASE_URL + f"?id=eq.{NODE_ID}"
    try:
        app.logger.debug(f"Updating shard count in Supabase with data: {data}")
        r = requests.patch(patch_url, headers=headers, json=data, timeout=5)
        if r.status_code in (200, 201):
            app.logger.debug(f"Shard count updated in Supabase: {adept_shard_count}")
        else:
            app.logger.error(f"Failed to update shard count in Supabase: {r.status_code} - {r.text}")
    except Exception as e:
        app.logger.exception("Exception updating shard count in Supabase:")

def register_node_in_supabase():
    app.logger.info(">> Starting Supabase registration")
    app.logger.info(f"SUPABASE_URL: {SUPABASE_URL}, SUPABASE_API_KEY: {SUPABASE_API_KEY}")

    public_ipv4, public_ipv6 = get_public_ips()
    data = {
        "id": NODE_ID,
        "nickname": NODE_NICKNAME,
        "role": ROLE.capitalize(),
        "ipv4": public_ipv4,
        "ipv6": public_ipv6,
        "locked_parameter": "InitialConfig",
        "active": True,
        "shard_count": adept_shard_count
    }

    app.logger.info(f"Registering node in Supabase with data: {data}")
    headers = {
        "apikey": SUPABASE_API_KEY,
        "Content-Type": "application/json",
        "Prefer": "return=representation,resolution=merge-duplicates"
    }
    try:
        r = requests.post(SUPABASE_URL, headers=headers, json=data, timeout=5)
        app.logger.debug(f"Supabase POST status: {r.status_code}")
        if r.status_code in (200, 201):
            app.logger.info(f"Node registered successfully in Supabase. Response: {r.json()}")
        elif r.status_code == 409:
            app.logger.info("Node already exists; attempting to update dynamic fields.")
            patch_headers = {
                "apikey": SUPABASE_API_KEY,
                "Content-Type": "application/json",
                "Prefer": "return=representation"
            }
            patch_url = SUPABASE_URL + f"?id=eq.{NODE_ID}"
            patch_data = {
                "ipv4": public_ipv4,
                "ipv6": public_ipv6,
                "active": True,
                "shard_count": adept_shard_count
            }
            r_patch = requests.patch(patch_url, headers=patch_headers, json=patch_data, timeout=5)
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

# ==================== Query Peers from Supabase & Registration with Them ====================
def query_peers_from_supabase(peer_role):
    """
    Query Supabase for all nodes with a given role.
    """
    try:
        headers = {"apikey": SUPABASE_API_KEY}
        url = SUPABASE_URL + f"?role=eq.{peer_role.capitalize()}"
        app.logger.debug(f"Querying Supabase for peers with role {peer_role.capitalize()} using URL: {url}")
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            peers = response.json()
            app.logger.debug(f"Queried {peer_role} nodes from Supabase: {peers}")
            return peers
        else:
            app.logger.error(f"Failed to query {peer_role} nodes: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        app.logger.exception(f"Exception querying {peer_role} nodes from Supabase:")
        return []

registered_peers = []

def register_with_peers():
    """
    If this node is Relay, register with Adept nodes.
    If this node is Adept, register with Relay nodes.
    """
    global registered_peers
    target_role = "adept" if ROLE.lower() == "relay" else "relay"
    app.logger.info(f"Attempting to register with {target_role} nodes.")
    peers = query_peers_from_supabase(target_role)
    for peer in peers:
        peer_id = peer.get("id")
        if not peer_id:
            app.logger.warning("Peer without an id found; skipping.")
            continue

        # Skip self-registration.
        if peer_id == NODE_ID:
            app.logger.debug(f"Skipping self-registration for node {peer_id}")
            continue

        # Use IPv6 if available; otherwise, fall back to IPv4.
        if ":" in get_preferred_ip():
            peer_ip = peer.get("ipv6") if peer.get("ipv6") else peer.get("ipv4")
        else:
            peer_ip = peer.get("ipv4")

        if peer_ip and peer_id:
            try:
                url = f"http://{format_ip_for_url(peer_ip)}:{PORT}/registerPeer"
                # Updated payload: include both ipv4 and ipv6
                public_ipv4, public_ipv6 = get_public_ips()
                payload = {
                    "id": NODE_ID,
                    "role": ROLE.capitalize(),
                    "ipv4": public_ipv4,
                    "ipv6": public_ipv6
                }
                app.logger.debug(f"Sending registration to {url} with payload: {payload}")
                resp = requests.post(url, json=payload, timeout=5)
                if resp.status_code in (200, 201):
                    registered_peers.append({"id": peer_id, "ip": peer_ip})
                    app.logger.info(f"Registered with {target_role} node {peer_id} at {peer_ip}")
                else:
                    app.logger.error(f"Failed to register with {target_role} node {peer_id} at {peer_ip}: {resp.status_code} - {resp.text}")
            except Exception as e:
                app.logger.exception(f"Exception registering with {target_role} node {peer_id} at {peer_ip}")
        else:
            app.logger.error(f"Missing IP or ID for peer: {peer}")

if ROLE.lower() in ["adept", "relay"]:
    register_with_peers()

# ==================== DHT Manager ====================
class DHTManager:
    def __init__(self):
        # Mapping: shard_id -> {"owner": owner_uuid, "distributed_to": [peer_uuid, ...]}
        self.shard_map = {}
        # Mapping: node UUID -> dictionary with "ipv4" and "ipv6" addresses.
        self.node_map = {}
        # List of peer node UUIDs (only peers of the opposite type are stored)
        self.peer_nodes = []
        self.current_peer_index = 0

    def register_node(self, uuid_val, ipv4, ipv6, role):
        ipv4 = normalize_ip(ipv4)
        ipv6 = normalize_ip(ipv6)
        self.node_map[uuid_val] = {"ipv4": ipv4, "ipv6": ipv6}
        app.logger.debug(f"[DHTManager] Added/Updated node {uuid_val} in node_map: {{'ipv4': {ipv4}, 'ipv6': {ipv6}}}")
        # Only add to peer_nodes if the registering role is opposite to our own.
        if ROLE.lower() == "relay" and role.lower() == "adept":
            if uuid_val not in self.peer_nodes:
                self.peer_nodes.insert(0, uuid_val)
                app.logger.debug(f"[DHTManager] Added adept node {uuid_val} to peer_nodes.")
        elif ROLE.lower() == "adept" and role.lower() == "relay":
            if uuid_val not in self.peer_nodes:
                self.peer_nodes.insert(0, uuid_val)
                app.logger.debug(f"[DHTManager] Added relay node {uuid_val} to peer_nodes.")
        else:
            app.logger.debug(f"[DHTManager] Node {uuid_val} with role {role} not added to peer_nodes (our role: {ROLE}).")

    def register_shard(self, shard_id, owner_uuid, peer_node_uuid):
        if shard_id in self.shard_map:
            entry = self.shard_map[shard_id]
            if peer_node_uuid not in entry["distributed_to"]:
                entry["distributed_to"].append(peer_node_uuid)
        else:
            self.shard_map[shard_id] = {"owner": owner_uuid, "distributed_to": [peer_node_uuid]}
        app.logger.debug(f"[DHTManager] Registered shard {shard_id}: {self.shard_map[shard_id]}")

    def get_shard_location(self, shard_id):
        node_info = self.shard_map.get(shard_id)
        app.logger.debug(f"[DHTManager] Shard {shard_id} info: {node_info}")
        return node_info

    def get_all_shards(self):
        app.logger.debug(f"[DHTManager] Current shard map: {self.shard_map}")
        return self.shard_map.copy()

    def find_available_peer_node(self):
        if not self.peer_nodes:
            app.logger.warning("[DHTManager] No peer nodes available!")
            return None
        node_uuid = self.peer_nodes[self.current_peer_index]
        app.logger.debug(f"[DHTManager] Selected peer node: {node_uuid} (index: {self.current_peer_index})")
        self.current_peer_index = (self.current_peer_index + 1) % len(self.peer_nodes)
        return node_uuid

    def log_state(self):
        app.logger.debug("=== DHT STATE ===")
        app.logger.debug(f"Node Map: {self.node_map}")
        app.logger.debug(f"Shard Map: {self.shard_map}")
        app.logger.debug(f"Peer Nodes: {self.peer_nodes}")
        app.logger.debug(f"Current Peer Index: {self.current_peer_index}")
        app.logger.debug("=================")

dht_manager = DHTManager()

# Register the local node in the DHT.
local_ipv4, local_ipv6 = get_public_ips()
if ROLE.lower() == "adept":
    dht_manager.register_node(NODE_ID, local_ipv4, local_ipv6, "adept")
else:  # ROLE == relay
    dht_manager.register_node(NODE_ID, local_ipv4, local_ipv6, "relay")
dht_manager.log_state()

# ==================== Broadcast Functionality for Peers ====================
def broadcast_peer_to_peers(peer_id, peer_ip):
    """
    For a Relay node: broadcast the newly registered adept to other peers.
    For an Adept node: broadcast the newly registered relay to other peers.
    """
    target_role = "adept" if ROLE.lower() == "relay" else "relay"
    app.logger.info(f"Broadcasting {target_role} {peer_id} to all peers from node {NODE_ID}.")
    peers = query_peers_from_supabase(target_role)
    for peer in peers:
        p_id = peer.get("id")
        if not p_id:
            app.logger.warning("Encountered a peer without an id during broadcast; skipping.")
            continue

        # Avoid sending to self.
        if p_id == NODE_ID:
            app.logger.debug(f"Skipping broadcast to self (node {NODE_ID}).")
            continue

        # Use IPv6 if available; otherwise, fall back to IPv4.
        if ":" in get_preferred_ip():
            p_ip = peer.get("ipv6") if peer.get("ipv6") else peer.get("ipv4")
        else:
            p_ip = peer.get("ipv4")

        app.logger.debug(f"Preparing to broadcast to peer {p_id} at {p_ip}.")
        url = f"http://{format_ip_for_url(p_ip)}:{PORT}/registerPeer"
        # Updated payload: include both ipv4 and ipv6 addresses.
        public_ipv4, public_ipv6 = get_public_ips()
        payload = {
            "id": p_id,
            "role": target_role.capitalize(),
            "ipv4": public_ipv4,
            "ipv6": public_ipv6
        }
        headers = {"X-RelayBroadcast": "true"}
        app.logger.debug(f"Broadcast URL: {url} | Payload: {payload}")

        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=5)
            if resp.status_code in (200, 201):
                app.logger.info(f"Successfully broadcasted {target_role} {p_id} to peer {p_id} at {p_ip}")
            else:
                app.logger.error(f"Failed broadcasting {target_role} {p_id} to peer {p_id} at {p_ip}: {resp.status_code} - {resp.text}")
        except requests.exceptions.ConnectionError as ce:
            app.logger.warning(f"Connection refused when broadcasting {target_role} {p_id} to peer {p_id} at {p_ip}. Details: {ce}")
        except Exception as e:
            app.logger.exception(f"Exception broadcasting {target_role} {p_id} to peer {p_id} at {p_ip}")

# ==================== Shard Manager (for local sharding if needed) ====================
def shard_file(file_obj, chunk_size=64*1024):
    """
    Splits the uploaded file into shards.
    Returns a list of tuples: (shard_id, BytesIO object)
    """
    try:
        content = file_obj.read()
        shards = []
        base_filename = os.path.splitext(secure_filename(file_obj.filename))[0]
        for i in range(0, len(content), chunk_size):
            chunk = content[i:i+chunk_size]
            shard_id = f"{base_filename}_shard_{i//chunk_size}"
            shards.append((shard_id, BytesIO(chunk)))
        app.logger.debug(f"File sharded into {len(shards)} shards.")
        return shards
    except Exception as e:
        app.logger.exception("Error while sharding file:")
        raise

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
    global adept_shard_count
    app.logger.info("Received /store request.")
    if "file" not in request.files:
        app.logger.error("No file part in the request.")
        return "No file part", 400
    file = request.files["file"]
    if file.filename == "":
        app.logger.error("No selected file.")
        return "No selected file", 400
    filename = secure_filename(file.filename)
    app.logger.debug(f"Received file: {filename}")

    is_forwarded = request.headers.get("X-Forwarded", "false").lower() == "true"
    app.logger.debug(f"Is forwarded: {is_forwarded}")

    # --- For forwarded shards (received by Adept nodes) ---
    if is_forwarded:
        if ROLE.lower() != "adept":
            app.logger.error("Relay node received forwarded shard; rejecting.")
            return "Relay nodes do not store forwarded shards", 403
        destination = os.path.join(STORAGE_DIR, filename)
        try:
            file.save(destination)
            app.logger.info(f"Stored forwarded shard locally at: {destination}")
            adept_shard_count += 1
            update_shard_count_in_supabase()
            return "Forwarded shard stored successfully", 200
        except Exception as e:
            app.logger.exception("Error storing forwarded shard:")
            return "Error storing forwarded shard", 500

    # --- Original upload handling ---
    if ROLE.lower() == "adept":
        try:
            shards = shard_file(file)
            relay_endpoint = os.environ.get("RELAY_ENDPOINT", "http://localhost:8080")
            for shard_id, shard_stream in shards:
                files = {"file": (f"{filename}_{shard_id}", shard_stream, "application/octet-stream")}
                headers = {"X-Forwarded": "true", "X-Owner": NODE_ID}
                app.logger.debug(f"Forwarding shard {shard_id} to relay endpoint {relay_endpoint}/store with headers: {headers}")
                try:
                    r = requests.post(f"{relay_endpoint}/store", files=files, headers=headers, timeout=5)
                    if r.status_code != 200:
                        app.logger.error(f"Error forwarding shard {shard_id}: {r.status_code} - {r.text}")
                except Exception as e:
                    app.logger.exception(f"Exception forwarding shard {shard_id}: {e}")
            return "File sharded and forwarded to Relay", 200
        except Exception as e:
            app.logger.exception("Exception during file sharding and forwarding:")
            return "Error processing file", 500

    elif ROLE.lower() == "relay":
        owner_uuid = request.headers.get("X-Owner", "unknown")
        try:
            content = file.read()
            files = {"file": (filename, BytesIO(content), file.content_type)}
            target_uuid = dht_manager.find_available_peer_node()
            if not target_uuid:
                app.logger.error("No available adept node found in DHT")
                return "No available adept node", 500

            peer_info = dht_manager.node_map.get(target_uuid)
            if not peer_info:
                app.logger.error(f"No IP found for adept node {target_uuid} in DHT")
                return "No adept IP found", 500

            # Use IPv6 if available; otherwise, fall back to IPv4.
            if ":" in get_preferred_ip():
                target_ip = peer_info.get("ipv6") if peer_info.get("ipv6") else peer_info.get("ipv4")
            else:
                target_ip = peer_info.get("ipv4")
            target_adept_endpoint = f"http://{format_ip_for_url(target_ip)}:{PORT}"
            app.logger.debug(f"Forwarding file from Relay to Adept at endpoint: {target_adept_endpoint}/store")
            try:
                r = requests.post(f"{target_adept_endpoint}/store", files=files, headers={"X-Forwarded": "true"}, timeout=5)
                if r.status_code == 200:
                    dht_manager.register_shard(filename, owner_uuid, target_uuid)
                    return "File forwarded to Adept", 200
                else:
                    app.logger.error(f"Error forwarding file to Adept: {r.status_code} - {r.text}")
                    return f"Error: {r.text}", 500
            except Exception as e:
                app.logger.exception("Exception during file forwarding from Relay:")
                return "Exception during file forwarding", 500
        except Exception as e:
            app.logger.exception("Exception processing /store request in Relay:")
            return "Error processing file", 500
    else:
        app.logger.error("Unknown node role encountered in /store endpoint.")
        return "Unknown role", 403

@app.route("/download", methods=["GET"])
def download():
    filename = request.args.get("file")
    if not filename:
        app.logger.error("File parameter missing in download request.")
        return "File parameter missing", 400
    filepath = os.path.join(STORAGE_DIR, filename)
    if not os.path.exists(filepath):
        app.logger.error(f"File not found: {filepath}")
        return "File not found", 404
    try:
        app.logger.info(f"Serving file: {filepath}")
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        app.logger.exception("Error serving file:")
        return "Error serving file", 500

# ------------------ DHT Registration Endpoints ------------------
@app.route("/registerPeer", methods=["POST"])
def register_peer():
    """
    Endpoint for external nodes to register themselves in the DHT.
    Expects a JSON payload with at least an 'id' field and optionally 'role', 'ipv4', and 'ipv6' fields.
    Only peers of the opposite type are added.
    """
    data = request.get_json()
    if not data or "id" not in data:
        app.logger.error("Missing 'id' in /registerPeer payload.")
        return jsonify({"error": "Missing 'id' in payload"}), 400
    node_id = data["id"]
    role_from_payload = data.get("role", "").lower()
    ip_address = normalize_ip(data.get("ipv4", request.remote_addr))
    ipv6_address = normalize_ip(data.get("ipv6", ""))
    app.logger.debug(f"/registerPeer received payload: {data} (normalized ipv4: {ip_address}, ipv6: {ipv6_address}, remote_addr: {request.remote_addr})")

    if ROLE.lower() == "relay" and role_from_payload == "adept":
        dht_manager.register_node(node_id, ip_address, ipv6_address, role_from_payload)
        app.logger.info(f"Registered adept peer {node_id} with IPs {{'ipv4': {ip_address}, 'ipv6': {ipv6_address}}} in DHT.")
    elif ROLE.lower() == "adept" and role_from_payload == "relay":
        dht_manager.register_node(node_id, ip_address, ipv6_address, role_from_payload)
        app.logger.info(f"Registered relay peer {node_id} with IPs {{'ipv4': {ip_address}, 'ipv6': {ipv6_address}}} in DHT.")
    else:
        app.logger.info(f"Node {node_id} with role {role_from_payload} not added to our DHT (our role: {ROLE}).")
    
    # Broadcast registration if not already a broadcast.
    if ROLE.lower() == "relay" and role_from_payload == "adept" and not request.headers.get("X-RelayBroadcast"):
        app.logger.debug(f"Initiating broadcast of adept peer {node_id} from relay node.")
        broadcast_peer_to_peers(node_id, ip_address)
    elif ROLE.lower() == "adept" and role_from_payload == "relay" and not request.headers.get("X-RelayBroadcast"):
        app.logger.debug(f"Initiating broadcast of relay peer {node_id} from adept node.")
        broadcast_peer_to_peers(node_id, ip_address)
    
    return jsonify({"status": "success", "message": f"Peer {node_id} registered."}), 200

@app.route("/updateIp", methods=["POST"])
def update_ip():
    """
    Endpoint for external nodes to update their IP in the DHT.
    Expects a JSON payload with an 'id' field.
    Only processes updates for peers of the opposite type.
    """
    data = request.get_json()
    if not data or "id" not in data:
        app.logger.error("Missing 'id' in /updateIp payload.")
        return jsonify({"error": "Missing 'id' in payload"}), 400
    node_id = data["id"]
    ip_address = normalize_ip(data.get("ipv4", request.remote_addr))
    ipv6_address = normalize_ip(data.get("ipv6", ""))
    app.logger.debug(f"/updateIp received for node {node_id} with normalized ipv4: {ip_address}, ipv6: {ipv6_address}")
    if node_id in dht_manager.peer_nodes:
        role = "adept" if ROLE.lower() == "relay" else "relay"
        dht_manager.register_node(node_id, ip_address, ipv6_address, role)
        app.logger.info(f"Updated IP for peer {node_id} to {{'ipv4': {ip_address}, 'ipv6': {ipv6_address}}} in DHT.")
    else:
        app.logger.info(f"Update ignored for node {node_id} (not registered as peer).")
    return jsonify({"status": "success", "message": f"IP updated for node {node_id}."}), 200

# ==================== DHT Info Endpoint ====================
@app.route("/dht", methods=["GET"])
def dht():
    app.logger.debug("DHT information requested.")
    return jsonify({
        "node_map": dht_manager.node_map,
        "shard_map": dht_manager.shard_map,
        "peer_nodes": dht_manager.peer_nodes,
        "current_peer_index": dht_manager.current_peer_index
    })

@app.route("/getShards", methods=["GET"])
def get_shards():
    """
    Endpoint to retrieve all shard information for a given owner.
    Expects a query parameter 'owner' with the owner's UUID.
    """
    owner_uuid = request.args.get("owner")
    if not owner_uuid:
        app.logger.error("Missing 'owner' query parameter in /getShards.")
        return jsonify({"error": "Missing 'owner' query parameter"}), 400
    owner_shards = {shard: info for shard, info in dht_manager.shard_map.items() if info.get("owner") == owner_uuid}
    app.logger.debug(f"Returning shards for owner {owner_uuid}: {owner_shards}")
    return jsonify(owner_shards), 200

# ==================== Heartbeat Functionality ====================
SUPABASE_HEARTBEAT_URL = SUPABASE_URL
headers = {
    "apikey": SUPABASE_API_KEY,
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

def send_heartbeat():
    heartbeat_data = {
        "id": NODE_ID,
        "active": True,
        "last_seen": [datetime.utcnow().isoformat() + "Z"]
    }
    try:
        app.logger.debug(f"Sending heartbeat: {heartbeat_data}")
        response = requests.patch(
            f"{SUPABASE_HEARTBEAT_URL}?id=eq.{NODE_ID}",
            headers=headers,
            json=heartbeat_data,
            timeout=5
        )
        if response.status_code in (200, 201):
            app.logger.debug("Heartbeat sent successfully.")
        else:
            app.logger.error(f"Heartbeat update failed: {response.status_code} - {response.text}")
    except Exception as e:
        app.logger.exception("Exception sending heartbeat:")

def heartbeat_loop(interval=60):
    while True:
        send_heartbeat()
        time.sleep(interval)

heartbeat_thread = threading.Thread(target=heartbeat_loop, args=(60,), daemon=True)
heartbeat_thread.start()

#-----------------DHT UPDAE EVERY 15 MINUTES-----------------------
def periodic_peer_registration(interval=900):
    """
    Periodically query Supabase for new nodes and register this node with their DHTs.
    This function runs an infinite loop that calls register_with_peers() every 'interval' seconds.
    """
    while True:
        app.logger.info("Periodic peer registration: Scanning for new nodes...")
        try:
            register_with_peers()
        except Exception as e:
            app.logger.exception("Error during periodic peer registration:")
        app.logger.info("Periodic peer registration: Waiting for next scan...")
        time.sleep(interval)

# Start the periodic peer registration in a daemon thread
peer_reg_thread = threading.Thread(target=periodic_peer_registration, args=(900,), daemon=True)
peer_reg_thread.start()

if __name__ == "__main__":
    app.logger.info(f"Starting {ROLE} node with ID: {NODE_ID} on port {PORT}")
    # Bind to all interfaces (IPv4 and IPv6)
    app.run(host="::", port=PORT, debug=True)
