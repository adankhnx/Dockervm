import os
import platform
import subprocess
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
import ipaddress  # <-- for NAT checks if needed
import socket

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
# Use our app logger (you can use app.logger or a separate logger)
app_logger = logging.getLogger("myapp")

# ----------------------- Configuration & Node Identification -----------------------
PORT = int(os.environ.get("PORT", 8080))
STORAGE_DIR = os.environ.get("STORAGE_DIR", "./storage")

SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://your-project.supabase.co/rest/v1/users")
SUPABASE_API_KEY = os.environ.get("SUPABASE_API_KEY", "your_supabase_api_key")
NODE_NICKNAME = os.environ.get("NODE_NICKNAME", "FlaskNode")
ROLE = os.environ.get("ROLE", "")  # We'll auto-detect if empty

if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR)
    app_logger.debug(f"Created storage directory: {STORAGE_DIR}")
else:
    app_logger.debug(f"Using existing storage directory: {STORAGE_DIR}")

NODE_ID_FILE = "node_id.txt"
if os.path.exists(NODE_ID_FILE):
    with open(NODE_ID_FILE, "r") as f:
        NODE_ID = f.read().strip()
    app_logger.debug(f"Loaded existing Node ID: {NODE_ID}")
else:
    NODE_ID = str(uuid.uuid4())
    with open(NODE_ID_FILE, "w") as f:
        f.write(NODE_ID)
    app_logger.debug(f"Generated new Node ID: {NODE_ID}")

# Global variable for Adept's shard count.
adept_shard_count = 0

# Global job queue for Relay nodes.
job_queue = []
job_queue_lock = threading.Lock()

def safe_append_job(job):
    with job_queue_lock:
        job_queue.append(job)

def safe_get_jobs_for_target(target_id):
    with job_queue_lock:
        return [job for job in job_queue if job["targetNodeId"] == target_id]

# ----------------------- Helper Functions for IPs -----------------------
def format_ip_for_url(ip):
    """Wrap IPv6 addresses in square brackets for URL usage."""
    if ip and ":" in ip:
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

def ip_external_reach(ip, port=8080, timeout=5):
    """
    Uses a TCP connection attempt to check if the given IP address is reachable on the specified port.
    
    Args:
        ip (str): The target IP address.
        port (int): The port number to test.
        timeout (int): Timeout in seconds for the connection attempt.
    
    Returns:
        bool: True if a TCP connection is established, otherwise False.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            return True
    except (socket.timeout, socket.error) as e:
        return False

def discover_external_ip_info(port=8080):
    """
    Discovers external IPv4 and IPv6 addresses using external services,
    normalizes them, and checks reachability.

    Returns a dictionary:
      {
         "ipv4": <IPv4 address or "Unknown">,
         "ipv6": <IPv6 address or "">,
         "incoming": <True if at least one is reachable, else False>
      }
    """
    ipv4, ipv6 = None, None

    try:
        response_ipv4 = requests.get("https://api.ipify.org", timeout=2)
        if response_ipv4.status_code == 200:
            ipv4 = normalize_ip(response_ipv4.text.strip())
            app_logger.debug(f"Discovered external IPv4: {ipv4}")
        else:
            app_logger.error(f"IPv4 service returned status {response_ipv4.status_code}")
    except Exception as e:
        app_logger.exception("Error fetching public IPv4 address:")

    try:
        response_ipv6 = requests.get("https://api6.ipify.org", timeout=2)
        if response_ipv6.status_code == 200:
            ipv6 = normalize_ip(response_ipv6.text.strip())
            app_logger.debug(f"Discovered external IPv6: {ipv6}")
        else:
            app_logger.error(f"IPv6 service returned status {response_ipv6.status_code}")
    except Exception as e:
        app_logger.exception("Error fetching public IPv6 address:")
        ipv6 = None

    incoming = False
    if ipv4 and ipv4 != "Unknown":
        ipv4_reachable = ip_external_reach(ipv4, port)
        app_logger.debug(f"IPv4 reachable: {ipv4_reachable}")
        if ipv4_reachable:
            incoming = True
    if ipv6:
        ipv6_reachable = ip_external_reach(ipv6, port)
        app_logger.debug(f"IPv6 reachable: {ipv6_reachable}")
        if ipv6_reachable:
            incoming = True

    return {
        "ipv4": ipv4 if ipv4 else "Unknown",
        "ipv6": ipv6 if ipv6 else "",
        "incoming": incoming
    }

# ----------------------- Initialize External IP Variables -----------------------
ip_info = discover_external_ip_info(port=PORT)
public_ipv4 = ip_info["ipv4"]
public_ipv6 = ip_info["ipv6"]
incoming = ip_info["incoming"]
app_logger.debug(f"Own IP discovery: Public IPv4: {public_ipv4}, Public IPv6: {public_ipv6}, Incoming: {incoming}")

# ----------------------- IP Address & Role Determination (Local) -----------------------
def get_ipv4_addresses():
    ipv4_list = []
    for iface in netifaces.interfaces():
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            for addr in addrs[netifaces.AF_INET]:
                ip = addr.get('addr')
                if ip and ip != "127.0.0.1":
                    ipv4_list.append(normalize_ip(ip))
    app_logger.debug(f"Local IPv4 addresses: {ipv4_list}")
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
    app_logger.debug(f"Local IPv6 addresses: {ipv6_list}")
    return ipv6_list

def get_public_ipv4():
    try:
        response = requests.get("https://api.ipify.org", timeout=2)
        if response.status_code == 200:
            public_ip = normalize_ip(response.text.strip())
            app_logger.debug(f"Public IPv4 address obtained: {public_ip}")
            return public_ip
    except Exception as e:
        app_logger.exception("Error fetching public IPv4 address:")
    return None

def get_public_ipv6():
    try:
        response = requests.get("https://api64.ipify.org", timeout=2)
        if response.status_code == 200:
            public_ip = response.text.strip()
            if ":" in public_ip:
                public_ip = normalize_ip(public_ip)
                app_logger.debug(f"Public IPv6 address obtained: {public_ip}")
                return public_ip
    except Exception as e:
        app_logger.exception("Error fetching public IPv6 address:")
    return None

def get_public_ips():
    ipv4 = get_public_ipv4()
    if not ipv4:
        ipv4s = get_ipv4_addresses()
        ipv4 = ipv4s[0] if ipv4s else "Unknown"
    ipv6 = get_public_ipv6()
    if not ipv6:
        ipv6s = get_ipv6_addresses()
        ipv6 = ipv6s[0] if ipv6s else ""
    app_logger.debug(f"Public IPs determined as: IPv4={ipv4}, IPv6={ipv6}")
    return ipv4, ipv6

def get_preferred_ip():
    ipv4, ipv6 = get_public_ips()
    if ipv6:
        app_logger.debug(f"Preferred IP (IPv6): {ipv6}")
        return ipv6
    app_logger.debug(f"Preferred IP (IPv4): {ipv4}")
    return ipv4

def determine_role():
    ipv6s = get_ipv6_addresses()
    if ipv6s:
        app_logger.info("Determined node role as Relay based on available IPv6 addresses.")
        return "Relay"
    app_logger.info("Determined node role as Adept (no non-loopback IPv6 addresses found).")
    return "Adept"

if not ROLE:
    ROLE = determine_role()
app_logger.debug(f"Determined node role: {ROLE}")

# ----------------------- Shard Count / Supabase Registration -----------------------
def update_shard_count_in_supabase():
    data = {"shard_count": adept_shard_count}
    headers = {
        "apikey": SUPABASE_API_KEY,
        "Content-Type": "application/json",
        "Prefer": "return=representation"
    }
    patch_url = SUPABASE_URL + f"?id=eq.{NODE_ID}"
    try:
        app_logger.debug(f"Updating shard count in Supabase with data: {data}")
        r = requests.patch(patch_url, headers=headers, json=data, timeout=5)
        if r.status_code in (200, 201):
            app_logger.debug(f"Shard count updated in Supabase: {adept_shard_count}")
        else:
            app_logger.error(f"Failed to update shard count in Supabase: {r.status_code} - {r.text}")
    except Exception as e:
        app_logger.exception("Exception updating shard count in Supabase:")

def register_node_in_supabase():
    app_logger.info(">> Starting Supabase registration")
    app_logger.info(f"SUPABASE_URL: {SUPABASE_URL}, SUPABASE_API_KEY: {SUPABASE_API_KEY}")
    ip_info = discover_external_ip_info(port=PORT)
    public_ipv4 = ip_info["ipv4"]
    public_ipv6 = ip_info["ipv6"]
    incoming = ip_info["incoming"]
    app_logger.info(f"Discovered public IPv4: {public_ipv4}, public IPv6: {public_ipv6}, incoming: {incoming}")
    data = {
        "id": NODE_ID,
        "nickname": NODE_NICKNAME,
        "role": "Relay" if os.environ.get("ROLE", "").lower() == "relay" else "Adept",
        "ipv4": public_ipv4,
        "ipv6": public_ipv6,
        "incoming": incoming,
        "locked_parameter": "InitialConfig",
        "active": True,
        "shard_count": adept_shard_count
    }
    app_logger.info(f"Registering node in Supabase with data: {data}")
    headers = {
        "apikey": SUPABASE_API_KEY,
        "Content-Type": "application/json",
        "Prefer": "return=representation,resolution=merge-duplicates"
    }
    try:
        r = requests.post(SUPABASE_URL, headers=headers, json=data, timeout=5)
        app_logger.debug(f"Supabase POST status: {r.status_code}")
        if r.status_code in (200, 201):
            app_logger.info(f"Node registered successfully in Supabase. Response: {r.json()}")
        elif r.status_code == 409:
            app_logger.info("Node already exists; attempting to update dynamic fields.")
            patch_headers = {
                "apikey": SUPABASE_API_KEY,
                "Content-Type": "application/json",
                "Prefer": "return=representation"
            }
            patch_url = SUPABASE_URL + f"?id=eq.{NODE_ID}"
            patch_data = {
                "ipv4": public_ipv4,
                "ipv6": public_ipv6,
                "incoming": incoming,
                "active": True,
                "shard_count": adept_shard_count
            }
            r_patch = requests.patch(patch_url, headers=patch_headers, json=patch_data, timeout=5)
            app_logger.debug(f"Supabase PATCH status: {r_patch.status_code}")
            if r_patch.status_code in (200, 201):
                app_logger.info(f"Node updated successfully in Supabase. Response: {r_patch.json()}")
            else:
                app_logger.error(f"Failed to update node in Supabase: {r_patch.text}")
        else:
            app_logger.error(f"Failed to register node in Supabase: {r.text}")
    except Exception as e:
        app_logger.exception("Exception during Supabase registration:")

# ----------------------- Query Peers and Register with Them -----------------------
def query_peers_from_supabase(peer_role):
    try:
        headers = {"apikey": SUPABASE_API_KEY}
        url = SUPABASE_URL + f"?role=eq.{peer_role.capitalize()}"
        app_logger.debug(f"Querying Supabase for peers with role {peer_role.capitalize()} using URL: {url}")
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code == 200:
            peers = response.json()
            app_logger.debug(f"Queried {peer_role} nodes from Supabase: {peers}")
            return peers
        else:
            app_logger.error(f"Failed to query {peer_role} nodes: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        app_logger.exception(f"Exception querying {peer_role} nodes from Supabase:")
        return []

registered_peers = []

def register_with_peers():
    global registered_peers
    target_role = "adept" if ROLE.lower() == "relay" else "relay"
    app_logger.info(f"Attempting to register with {target_role} nodes.")
    peers = query_peers_from_supabase(target_role)
    for peer in peers:
        p_id = peer.get("id")
        if not p_id:
            app_logger.warning("Peer without an id found; skipping.")
            continue
        if p_id == NODE_ID:
            app_logger.debug(f"Skipping self-registration for node {p_id}")
            continue
        if ":" in get_preferred_ip():
            peer_ip = peer.get("ipv6") if peer.get("ipv6") else peer.get("ipv4")
        else:
            peer_ip = peer.get("ipv4")
        if peer_ip and p_id:
            try:
                url = f"http://{format_ip_for_url(peer_ip)}:{PORT}/registerPeer"
                ip_info = discover_external_ip_info(port=PORT)
                public_ipv4 = ip_info["ipv4"]
                public_ipv6 = ip_info["ipv6"]
                payload = {
                    "id": NODE_ID,
                    "role": ROLE.capitalize(),
                    "ipv4": public_ipv4,
                    "ipv6": public_ipv6
                }
                app_logger.debug(f"Sending registration to {url} with payload: {payload}")
                resp = requests.post(url, json=payload, timeout=20)
                if resp.status_code in (200, 201):
                    registered_peers.append({"id": p_id, "ip": peer_ip})
                    app_logger.info(f"Registered with {target_role} node {p_id} at {peer_ip}")
                else:
                    app_logger.error(f"Failed to register with {target_role} node {p_id} at {peer_ip}: {resp.status_code} - {resp.text}")
            except Exception as e:
                app_logger.exception(f"Exception registering with {target_role} node {p_id} at {peer_ip}")
        else:
            app_logger.error(f"Missing IP or ID for peer: {peer}")

if ROLE.lower() in ["adept", "relay"]:
    register_with_peers()

# ----------------------- DHT Manager -----------------------
class DHTManager:
    def __init__(self):
        self.shard_map = {}
        self.node_map = {}
        self.peer_nodes = []
        self.current_peer_index = 0

    def register_node(self, uuid_val, ipv4, ipv6, role, incoming=False):
        ipv4 = normalize_ip(ipv4)
        ipv6 = normalize_ip(ipv6)
        self.node_map[uuid_val] = {"ipv4": ipv4, "ipv6": ipv6, "incoming": incoming}
        app_logger.debug(f"[DHTManager] Added/Updated node {uuid_val}: {{'ipv4': {ipv4}, 'ipv6': {ipv6}, 'incoming': {incoming}}}")
        if ROLE.lower() == "relay" and role.lower() == "adept":
            if uuid_val not in self.peer_nodes:
                self.peer_nodes.insert(0, uuid_val)
                app_logger.debug(f"[DHTManager] Added adept node {uuid_val} to peer_nodes.")
        elif ROLE.lower() == "adept" and role.lower() == "relay":
            if uuid_val not in self.peer_nodes:
                self.peer_nodes.insert(0, uuid_val)
                app_logger.debug(f"[DHTManager] Added relay node {uuid_val} to peer_nodes.")
        else:
            app_logger.debug(f"[DHTManager] Node {uuid_val} with role {role} not added to peer_nodes (our role: {ROLE}).")

    def register_shard(self, shard_id, owner_uuid, peer_node_uuid):
        if shard_id in self.shard_map:
            entry = self.shard_map[shard_id]
            if peer_node_uuid not in entry["distributed_to"]:
                entry["distributed_to"].append(peer_node_uuid)
        else:
            self.shard_map[shard_id] = {"owner": owner_uuid, "distributed_to": [peer_node_uuid]}
        app_logger.debug(f"[DHTManager] Registered shard {shard_id}: {self.shard_map[shard_id]}")

    def get_shard_location(self, shard_id):
        node_info = self.shard_map.get(shard_id)
        app_logger.debug(f"[DHTManager] Shard {shard_id} info: {node_info}")
        return node_info

    def get_all_shards(self):
        app_logger.debug(f"[DHTManager] Current shard map: {self.shard_map}")
        return self.shard_map.copy()

    def find_available_peer_node_excluding(self, exclude_id):
        if not self.peer_nodes:
            app_logger.warning("[DHTManager] No peer nodes available!")
            return None
        available_nodes = [node for node in self.peer_nodes if node != exclude_id]
        if not available_nodes:
            app_logger.warning("[DHTManager] No available peer nodes after excluding the owner.")
            return None
        node_uuid = available_nodes[self.current_peer_index % len(available_nodes)]
        self.current_peer_index = (self.current_peer_index + 1) % len(available_nodes)
        app_logger.debug(f"[DHTManager] Selected peer node (excluding {exclude_id}): {node_uuid}")
        return node_uuid

    def find_available_peer_node(self):
        if not self.peer_nodes:
            app_logger.warning("[DHTManager] No peer nodes available!")
            return None
        node_uuid = self.peer_nodes[self.current_peer_index]
        app_logger.debug(f"[DHTManager] Selected peer node: {node_uuid} (index: {self.current_peer_index})")
        self.current_peer_index = (self.current_peer_index + 1) % len(self.peer_nodes)
        return node_uuid

    def log_state(self):
        app_logger.debug("=== DHT STATE ===")
        app_logger.debug(f"Node Map: {self.node_map}")
        app_logger.debug(f"Shard Map: {self.shard_map}")
        app_logger.debug(f"Peer Nodes: {self.peer_nodes}")
        app_logger.debug(f"Current Peer Index: {self.current_peer_index}")
        app_logger.debug("=================")

dht_manager = DHTManager()

@app.route("/registerPeer", methods=["POST"])
def register_peer():
    data = request.get_json()
    if not data or "id" not in data:
        app_logger.error("Missing 'id' in /registerPeer payload.")
        return jsonify({"error": "Missing 'id' in payload"}), 400
    node_id = data["id"]
    role_from_payload = data.get("role", "").lower()
    ip_address = normalize_ip(data.get("ipv4", request.remote_addr))
    ipv6_address = normalize_ip(data.get("ipv6", ""))
    incoming_status = ip_external_reach(ip_address)  
    app_logger.debug(f"/registerPeer received payload: {data} (normalized ipv4: {ip_address}, ipv6: {ipv6_address}, incoming: {incoming_status})")

    if ROLE.lower() == "relay" and role_from_payload == "adept":
        dht_manager.register_node(node_id, ip_address, ipv6_address, role_from_payload, incoming_status)
        app_logger.info(f"Registered adept peer {node_id} with IPs {{'ipv4': {ip_address}, 'ipv6': {ipv6_address}, 'incoming': {incoming_status}}} in DHT.")
    elif ROLE.lower() == "adept" and role_from_payload == "relay":
        dht_manager.register_node(node_id, ip_address, ipv6_address, role_from_payload, incoming_status)
        app_logger.info(f"Registered relay peer {node_id} with IPs {{'ipv4': {ip_address}, 'ipv6': {ipv6_address}, 'incoming': {incoming_status}}} in DHT.")
    else:
        app_logger.info(f"Node {node_id} with role {role_from_payload} not added to our DHT (our role: {ROLE}).")
    
    if ROLE.lower() == "relay" and role_from_payload == "adept" and not request.headers.get("X-RelayBroadcast"):
        app_logger.debug(f"Initiating broadcast of adept peer {node_id} from relay node.")
        broadcast_peer_to_peers(node_id, ip_address)
    elif ROLE.lower() == "adept" and role_from_payload == "relay" and not request.headers.get("X-RelayBroadcast"):
        app_logger.debug(f"Initiating broadcast of relay peer {node_id} from adept node.")
        broadcast_peer_to_peers(node_id, ip_address)
    
    return jsonify({"status": "success", "message": f"Peer {node_id} registered."}), 200

@app.route("/pendingJobs", methods=["GET"], endpoint="pending_jobs_v2")
def pending_jobs():
    target_id = request.args.get("targetId")
    if not target_id:
        app_logger.error("Missing 'targetId' query parameter in /pendingJobs.")
        return jsonify({"error": "Missing 'targetId' query parameter"}), 400
    if ROLE.lower() != "relay":
        return jsonify({"error": "Not a relay node"}), 403
    jobs_for_target = safe_get_jobs_for_target(target_id)
    return jsonify({"jobs": jobs_for_target}), 200

# ----------------------- Broadcast Functionality for Peers -----------------------
def broadcast_peer_to_peers(peer_id, peer_ip):
    target_role = "adept" if ROLE.lower() == "relay" else "relay"
    app_logger.info(f"Broadcasting {target_role} {peer_id} to all peers from node {NODE_ID}.")
    peers = query_peers_from_supabase(target_role)
    for peer in peers:
        p_id = peer.get("id")
        if not p_id:
            app_logger.warning("Encountered a peer without an id during broadcast; skipping.")
            continue
        if p_id == NODE_ID:
            app_logger.debug(f"Skipping broadcast to self (node {NODE_ID}).")
            continue
        if ":" in get_preferred_ip():
            p_ip = peer.get("ipv6") if peer.get("ipv6") else peer.get("ipv4")
        else:
            p_ip = peer.get("ipv4")
        app_logger.debug(f"Preparing to broadcast to peer {p_id} at {p_ip}.")
        url = f"http://{format_ip_for_url(p_ip)}:{PORT}/registerPeer"
        ip_info = discover_external_ip_info(port=PORT)
        public_ipv4 = ip_info["ipv4"]
        public_ipv6 = ip_info["ipv6"]
        payload = {
            "id": NODE_ID,
            "role": ROLE.capitalize(),
            "ipv4": public_ipv4,
            "ipv6": public_ipv6
        }
        app_logger.debug(f"Broadcast URL: {url} | Payload: {payload}")
        try:
            resp = requests.post(url, json=payload, timeout=20)
            if resp.status_code in (200, 201):
                app_logger.info(f"Successfully broadcasted {target_role} {p_id} to peer {p_id} at {p_ip}")
            else:
                app_logger.error(f"Failed broadcasting {target_role} {p_id} to peer {p_id} at {p_ip}: {resp.status_code} - {resp.text}")
        except requests.exceptions.ConnectionError as ce:
            app_logger.warning(f"Connection refused when broadcasting {target_role} {p_id} to peer {p_id} at {p_ip}. Details: {ce}")
        except Exception as e:
            app_logger.exception(f"Exception broadcasting {target_role} {p_id} to peer {p_id} at {p_ip}")

# ----------------------- Shard Manager (for local sharding if needed) -----------------------
def shard_file(file_obj, chunk_size=64*1024):
    try:
        content = file_obj.read()
        shards = []
        base_filename = os.path.splitext(secure_filename(file_obj.filename))[0]
        for i in range(0, len(content), chunk_size):
            chunk = content[i:i+chunk_size]
            shard_id = f"{base_filename}_shard_{i//chunk_size}"
            shards.append((shard_id, BytesIO(chunk)))
        app_logger.debug(f"File sharded into {len(shards)} shards.")
        return shards
    except Exception as e:
        app_logger.exception("Error while sharding file:")
        raise

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
    app_logger.info("Received /store request.")
    if "file" not in request.files:
        app_logger.error("No file part in the request.")
        return "No file part", 400
    file = request.files["file"]
    if file.filename == "":
        app_logger.error("No selected file.")
        return "No selected file", 400
    filename = secure_filename(file.filename)
    app_logger.debug(f"Received file: {filename}")

    # Check for our custom header "X-OriginalUploader"
    is_forwarded = request.headers.get("X-OriginalUploader", "false").lower() == "true"
    app_logger.debug(f"Is forwarded (X-OriginalUploader): {is_forwarded}")

    # ------------------ Forwarded File Handling ------------------
    if is_forwarded:
        if ROLE.lower() != "adept":
            app_logger.error("Relay node received forwarded shard; rejecting.")
            return "Relay nodes do not store forwarded shards", 403
        # Save the forwarded shard in the replicated_shards folder.
        replicated_dir = os.path.join(STORAGE_DIR, "replicated_shards")
        if not os.path.exists(replicated_dir):
            os.makedirs(replicated_dir)
        destination = os.path.join(replicated_dir, filename)
        try:
            file.save(destination)
            app_logger.info(f"Stored forwarded shard locally at: {destination}")
            adept_shard_count += 1
            update_shard_count_in_supabase()
            # For forwarded uploads, we simply return a success response.
            return jsonify({"message": "Forwarded shard stored successfully"}), 200
        except Exception as e:
            app_logger.exception("Error storing forwarded shard:")
            return "Error storing forwarded shard", 500

    # ------------------ Original Upload Handling ------------------
    # For an original upload, if the node is Adept, we shard the file and forward each shard to Relay.
    if ROLE.lower() == "adept":
        try:
            shards = shard_file(file)
            relay_endpoint = os.environ.get("RELAY_ENDPOINT", "http://localhost:8080")
            mapping = {}  # To collect shard -> redundant adept UUID pairs.
            for shard_id, shard_stream in shards:
                files = {"file": (f"{filename}_{shard_id}", shard_stream, "application/octet-stream")}
                # Mark this upload as original by setting X-OriginalUploader to false.
                headers = {"X-OriginalUploader": "false", "X-Owner": NODE_ID}
                app_logger.debug(f"Forwarding shard {shard_id} to relay endpoint {relay_endpoint}/store with headers: {headers}")
                try:
                    r = requests.post(f"{relay_endpoint}/store", files=files, headers=headers, timeout=20)
                    if r.status_code == 200:
                        resp_json = r.json()  # Expecting {"shard": <shard>, "redundant_adept": <UUID>}
                        mapping[resp_json.get("shard", f"{filename}_{shard_id}")] = resp_json.get("redundant_adept")
                    else:
                        app_logger.error(f"Error forwarding shard {shard_id}: {r.status_code} - {r.text}")
                except Exception as e:
                    app_logger.exception(f"Exception forwarding shard {shard_id}: {e}")
            return jsonify(mapping), 200
        except Exception as e:
            app_logger.exception("Exception during file sharding and forwarding:")
            return "Error processing file", 500

    # For Relay node handling of original uploads.
    elif ROLE.lower() == "relay":
        owner_uuid = request.headers.get("X-Owner", "unknown")
        try:
            content = file.read()
            files = {"file": (filename, BytesIO(content), file.content_type)}
            target_uuid = dht_manager.find_available_peer_node_excluding(owner_uuid)
            if not target_uuid:
                app_logger.error("No available adept node found in DHT (after excluding the owner).")
                return "No available adept node", 500

            peer_info = dht_manager.node_map.get(target_uuid)
            if not peer_info:
                app_logger.error(f"No IP found for adept node {target_uuid} in DHT")
                return "No adept IP found", 500

            if not peer_info.get("incoming", True):
                job = {"shardId": filename, "targetNodeId": target_uuid, "shardFileUrl": f"http://{request.host}/storage/{filename}"}
                safe_append_job(job)
                app_logger.debug(f"Queued job for target {target_uuid} because it is behind NAT: {job}")
                return "Job queued for node behind NAT", 200
            
            if ":" in get_preferred_ip():
                target_ip = peer_info.get("ipv6") if peer_info.get("ipv6") else peer_info.get("ipv4")
            else:
                target_ip = peer_info.get("ipv4")
            target_adept_endpoint = f"http://{format_ip_for_url(target_ip)}:{PORT}"
            app_logger.debug(f"Forwarding file from Relay to Adept at endpoint: {target_adept_endpoint}/store")
            try:
                # IMPORTANT: Set header "X-OriginalUploader" to "true" so the receiving Adept does not re-shard.
                r = requests.post(f"{target_adept_endpoint}/store", files=files, headers={"X-OriginalUploader": "true"}, timeout=20)
                if r.status_code == 200:
                    dht_manager.register_shard(filename, owner_uuid, target_uuid)
                    # Return a JSON object with the shard name and the redundant adept's UUID.
                    return jsonify({"shard": filename, "redundant_adept": target_uuid}), 200
                else:
                    app_logger.error(f"Error forwarding file to Adept: {r.status_code} - {r.text}")
                    return f"Error: {r.text}", 500
            except Exception as e:
                app_logger.exception("Exception during file forwarding from Relay:")
                return "Exception during file forwarding", 500
        except Exception as e:
            app_logger.exception("Exception processing /store request in Relay:")
            return "Error processing file", 500
    else:
        app_logger.error("Unknown node role encountered in /store endpoint.")
        return "Unknown role", 403

@app.route("/download", methods=["GET"])
def download():
    filename = request.args.get("file")
    if not filename:
        app_logger.error("File parameter missing in download request.")
        return "File parameter missing", 400
    filepath = os.path.join(STORAGE_DIR, filename)
    if not os.path.exists(filepath):
        app_logger.error(f"File not found: {filepath}")
        return "File not found", 404
    try:
        app_logger.info(f"Serving file: {filepath}")
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        app_logger.exception("Error serving file:")
        return "Error serving file", 500

# ----------------------- Heartbeat Functionality -----------------------
SUPABASE_HEARTBEAT_URL = SUPABASE_URL
heartbeat_headers = {
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
        app_logger.debug(f"Sending heartbeat: {heartbeat_data}")
        response = requests.patch(
            f"{SUPABASE_HEARTBEAT_URL}?id=eq.{NODE_ID}",
            headers=heartbeat_headers,
            json=heartbeat_data,
            timeout=5
        )
        if response.status_code in (200, 201):
            app_logger.debug("Heartbeat sent successfully.")
        else:
            app_logger.error(f"Heartbeat update failed: {response.status_code} - {response.text}")
    except Exception as e:
        app_logger.exception("Exception sending heartbeat:")

def heartbeat_loop(interval=60):
    while True:
        send_heartbeat()
        time.sleep(interval)

heartbeat_thread = threading.Thread(target=heartbeat_loop, args=(60,), daemon=True)
heartbeat_thread.start()

def periodic_peer_registration(interval=900):
    while True:
        app_logger.info("Periodic peer registration: Scanning for new nodes...")
        try:
            register_with_peers()
        except Exception as e:
            app_logger.exception("Error during periodic peer registration:")
        app_logger.info("Periodic peer registration: Waiting for next scan...")
        time.sleep(interval)

peer_reg_thread = threading.Thread(target=periodic_peer_registration, args=(900,), daemon=True)
peer_reg_thread.start()

# ----------------------- Adept Node: Polling for Shard Jobs -----------------------
def download_and_store_shard(shard_id, shard_file_url):
    try:
        r = requests.get(shard_file_url, timeout=20)
        if r.status_code == 200:
            destination = os.path.join(STORAGE_DIR, shard_id)
            with open(destination, "wb") as f:
                f.write(r.content)
            app_logger.info(f"Downloaded and stored shard {shard_id} at {destination}")
            global adept_shard_count
            adept_shard_count += 1
            update_shard_count_in_supabase()
        else:
            app_logger.error(f"Failed to download shard {shard_id}: {r.status_code} {r.text}")
    except Exception as e:
        app_logger.exception(f"Exception downloading shard {shard_id}:")

def poll_for_shard_jobs():
    while True:
        if ROLE.lower() == "adept":
            relay_endpoint = os.environ.get("RELAY_ENDPOINT", "http://localhost:8080")
            poll_url = f"{relay_endpoint}/pendingJobs?targetId={NODE_ID}"
            try:
                r = requests.get(poll_url, timeout=15)
                if r.status_code == 200:
                    jobs = r.json().get("jobs", [])
                    app_logger.debug(f"Polled {len(jobs)} shard jobs for node {NODE_ID}")
                    for job in jobs:
                        shard_id = job.get("shardId")
                        shard_file_url = job.get("shardFileUrl")
                        if shard_id and shard_file_url:
                            download_and_store_shard(shard_id, shard_file_url)
                else:
                    app_logger.error(f"Failed to poll shard jobs: {r.status_code} {r.text}")
            except Exception as e:
                app_logger.exception("Exception polling for shard jobs:")
        time.sleep(900)

if ROLE.lower() == "adept":
    shard_poll_thread = threading.Thread(target=poll_for_shard_jobs, daemon=True)
    shard_poll_thread.start()

# ----------------------- Broadcast Functionality for Peers (Duplicate block intentionally kept) -----------------------
@app.route("/dht", methods=["GET"])
def dht():
    app_logger.debug("DHT information requested.")
    return jsonify({
        "node_map": dht_manager.node_map,
        "shard_map": dht_manager.shard_map,
        "peer_nodes": dht_manager.peer_nodes,
        "current_peer_index": dht_manager.current_peer_index
    })

@app.route("/getShards", methods=["GET"])
def get_shards():
    owner_uuid = request.args.get("owner")
    if not owner_uuid:
        app_logger.error("Missing 'owner' query parameter in /getShards.")
        return jsonify({"error": "Missing 'owner' query parameter"}), 400
    owner_shards = {shard: info for shard, info in dht_manager.shard_map.items() if info.get("owner") == owner_uuid}
    app_logger.debug(f"Returning shards for owner {owner_uuid}: {owner_shards}")
    return jsonify(owner_shards), 200

# ----------------------- Main -----------------------
if __name__ == "__main__":
    # Prevent duplicate registration in debug mode.
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        register_node_in_supabase()
    app_logger.info(f"Starting {ROLE} node with ID: {NODE_ID} on port {PORT}")
    app.run(host="::", port=PORT, debug=True)
