from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import json
import os
import random
import uuid
from datetime import datetime

try:
    from backend.predict import predict_threat
except ImportError:
    from .predict import predict_threat

app = FastAPI()

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve static files on /static and root file path via route
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
app.mount("/static", StaticFiles(directory=frontend_dir, html=True), name="static")

@app.get("/")
def root():
    from fastapi.responses import FileResponse
    index_file = os.path.join(frontend_dir, "index.html")
    if not os.path.exists(index_file):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"detail": "Index file not found"})
    return FileResponse(index_file)

@app.head("/")
def root_head():
    from fastapi.responses import Response
    index_file = os.path.join(frontend_dir, "index.html")
    if not os.path.exists(index_file):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"detail": "Index file not found"})
    return Response(status_code=200, headers={"content-type": "text/html; charset=utf-8"})

@app.get("/static/index.html")
def static_index():
    from fastapi.responses import FileResponse
    index_file = os.path.join(frontend_dir, "index.html")
    if not os.path.exists(index_file):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"detail": "Index file not found"})
    return FileResponse(index_file)

base_storage_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'storage'))
THREATS_FILE = os.path.join(base_storage_dir, 'threats.json')
GROUPS_FILE = os.path.join(base_storage_dir, 'groups.json')
USERS_FILE = os.path.join(base_storage_dir, 'users.json')
FIREWALL_FILE = os.path.join(base_storage_dir, 'firewall_updates.json')

# Ensure files exist
if not os.path.exists(THREATS_FILE):
    with open(THREATS_FILE, 'w') as f:
        json.dump([], f)

if not os.path.exists(GROUPS_FILE):
    with open(GROUPS_FILE, 'w') as f:
        json.dump({}, f)

if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, 'w') as f:
        json.dump({}, f)

if not os.path.exists(FIREWALL_FILE):
    with open(FIREWALL_FILE, 'w') as f:
        json.dump([], f)

def load_threats():
    with open(THREATS_FILE, 'r') as f:
        return json.load(f)

def save_threats(threats):
    with open(THREATS_FILE, 'w') as f:
        json.dump(threats, f, indent=4)

def load_groups():
    with open(GROUPS_FILE, 'r') as f:
        return json.load(f)

def save_groups(groups):
    with open(GROUPS_FILE, 'w') as f:
        json.dump(groups, f, indent=4)

def load_users():
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def get_node_id_from_request(node_id: str = Header(None, alias="node-id")):
    """Simple node_id extraction from header"""
    if not node_id:
        raise HTTPException(status_code=401, detail="Missing node_id")
    return node_id

@app.post("/register")
def register(data: dict):
    """
    Register a new node
    
    Body:
        organization: str (e.g., "CyberCorp")
        node_type: str (e.g., "SOC", "ENDPOINT")
        node_name: str (e.g., "SOC-1")
        password: str
    
    node_id will be: organization-node_name (e.g., "CyberCorp-SOC-1")
    """
    organization = data.get("organization", "").strip()
    node_type = data.get("node_type", "").strip()
    node_name = data.get("node_name", "").strip()
    password = data.get("password", "").strip()
    
    # Validation
    if not organization or not node_type or not node_name or not password:
        raise HTTPException(status_code=400, detail="Missing required fields")
    
    # Generate node_id
    node_id = f"{organization}-{node_name}"
    
    # Load users and check if node_id already exists
    users = load_users()
    if node_id in users:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Save user with plain text password (demo mode)
    users[node_id] = {
        "organization": organization,
        "node_type": node_type,
        "node_name": node_name,
        "password": password
    }
    save_users(users)
    
    return {"message": "Registration successful", "node_id": node_id}

@app.post("/login")
def login(data: dict):
    """
    Login with node_id or (organization + node_name) and password
    
    Body options:
        node_id: str (e.g., "CyberCorp-SOC-1")
        OR organization: str, node_name: str
        password: str
    """
    node_id = data.get("node_id", "").strip()
    organization = data.get("organization", "").strip()
    node_name = data.get("node_name", "").strip()
    password = data.get("password", "").strip()

    if not node_id and organization and node_name:
        node_id = f"{organization}-{node_name}"

    if not node_id or not password:
        raise HTTPException(status_code=400, detail="Missing required fields")

    users = load_users()
    if node_id not in users:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Check password (plain text for demo)
    if users[node_id]["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Return success with node_id (no JWT token needed)
    return {"message": "Login successful", "node_id": node_id, "token": "dummy"}

def load_firewall():
    with open(FIREWALL_FILE, 'r') as f:
        return json.load(f)

def save_firewall(updates):
    with open(FIREWALL_FILE, 'w') as f:
        json.dump(updates, f, indent=4)

# Automated response: block high-severity IPs
def auto_block_ip(threat, node_id):
    high_severity_attacks = ['smurf', 'neptune', 'teardrop', 'pod', 'land', 'back', 'ipsweep', 'portsweep', 'nmap', 'satan']
    if threat.get("attack_type", "").lower() in high_severity_attacks:
        firewall = load_firewall()
        block_entry = {
            "ip": threat["src_ip"],
            "reason": f"High-severity attack: {threat.get('attack_type', 'Unknown')}",
            "timestamp": datetime.now().isoformat(),
            "node_id": node_id
        }
        firewall.append(block_entry)
        save_firewall(firewall)
        print(f"Blocked IP {threat['src_ip']} due to {threat.get('attack_type', 'Unknown')} attack")

# Auto-share threat to group
def auto_share_threat(threat, node_id):
    groups = load_groups()
    for group_name, group_data in groups.items():
        if node_id in group_data["members"]:
            ioc = {
                "ip": threat["src_ip"],
                "threat_type": threat.get("attack_type", "Unknown"),
                "severity": "High" if threat["prediction"] == "Attack" else "Low",
                "timestamp": datetime.now().isoformat(),
                "source_org": node_id.split('-')[0]
            }
            group_data["shared_threats"].append(ioc)
            save_groups(groups)
            break

# Generate fake traffic
def generate_traffic():
    protocols = ['tcp', 'udp', 'icmp']
    services = ['http', 'ftp', 'smtp', 'ssh', 'dns', 'other']
    flags = ['SF', 'S0', 'REJ', 'RSTO', 'SH', 'RSTR', 'S1', 'S2', 'S3', 'OTH']
    return {
        "src_ip": f"192.168.0.{random.randint(1,255)}",
        "dst_ip": f"10.0.0.{random.randint(1,255)}",
        "protocol": random.choice(protocols),
        "packet_size": random.randint(100,1500),
        "duration": random.randint(0,1000),
        "protocol_type": random.choice(protocols),
        "service": random.choice(services),
        "flag": random.choice(flags),
        "src_bytes": random.randint(0,10000),
        "dst_bytes": random.randint(0,10000),
        "land": random.randint(0,1),
        "wrong_fragment": random.randint(0,1),
        "urgent": random.randint(0,1),
        "hot": random.randint(0,10),
        "num_failed_logins": random.randint(0,5),
        "logged_in": random.randint(0,1),
        "num_compromised": random.randint(0,5),
        "root_shell": random.randint(0,1),
        "su_attempted": random.randint(0,1),
        "num_root": random.randint(0,5),
        "num_file_creations": random.randint(0,5),
        "num_shells": random.randint(0,1),
        "num_access_files": random.randint(0,5),
        "num_outbound_cmds": random.randint(0,1),
        "is_host_login": random.randint(0,1),
        "is_guest_login": random.randint(0,1),
        "count": random.randint(0,100),
        "srv_count": random.randint(0,100),
        "serror_rate": random.uniform(0,1),
        "srv_serror_rate": random.uniform(0,1),
        "rerror_rate": random.uniform(0,1),
        "srv_rerror_rate": random.uniform(0,1),
        "same_srv_rate": random.uniform(0,1),
        "diff_srv_rate": random.uniform(0,1),
        "srv_diff_host_rate": random.uniform(0,1),
        "dst_host_count": random.randint(0,100),
        "dst_host_srv_count": random.randint(0,100),
        "dst_host_same_srv_rate": random.uniform(0,1),
        "dst_host_diff_srv_rate": random.uniform(0,1),
        "dst_host_same_src_port_rate": random.uniform(0,1),
        "dst_host_srv_diff_host_rate": random.uniform(0,1),
        "dst_host_serror_rate": random.uniform(0,1),
        "dst_host_srv_serror_rate": random.uniform(0,1),
        "dst_host_rerror_rate": random.uniform(0,1),
        "dst_host_srv_rerror_rate": random.uniform(0,1)
    }

@app.get("/generate_traffic")
def endpoint_generate_traffic():
    return generate_traffic()


@app.post("/detect")
def detect_threat(data: dict, node_id: str = Header(None, alias="node-id")):
    # Add generated features if not provided
    if 'duration' not in data:
        data.update(generate_traffic())
    prediction = predict_threat(data)
    if prediction["prediction"] == "Attack":
        threats = load_threats()
        threat_id = str(uuid.uuid4())
        threat = {**prediction, "id": threat_id, "node_id": node_id}
        threats.append(threat)
        save_threats(threats)
        # Auto-share to groups
        groups = load_groups()
        for group_name, group_data in groups.items():
            if node_id in group_data["members"]:
                group_data["shared_threats"].append(threat)
                save_groups(groups)
        # Auto-block high-severity
        auto_block_ip(threat, node_id)
    return prediction

@app.get("/threats")
def get_threats(node_id: str = Header(None, alias="node-id")):
    threats = load_threats()
    groups = load_groups()
    shared_threat_ids = set()
    for group_data in groups.values():
        if node_id in group_data["members"]:
            for threat in group_data["shared_threats"]:
                shared_threat_ids.add(threat["id"])
    user_threats = [t for t in threats if t["node_id"] == node_id or t["id"] in shared_threat_ids]
    return user_threats

@app.post("/create-group")
def create_group(data: dict, node_id: str = Header(None, alias="node-id")):
    group_name = data.get("group_name").strip()
    groups = load_groups()
    if group_name in groups:
        raise HTTPException(status_code=400, detail="Group already exists")
    groups[group_name] = {"members": [node_id], "pending_requests": [], "shared_threats": []}
    save_groups(groups)
    return {"message": f"Group {group_name} created"}

@app.post("/request-join")
def request_join(data: dict, node_id: str = Header(None, alias="node-id")):
    group_name = data.get("group_name").strip()
    groups = load_groups()
    if group_name not in groups:
        raise HTTPException(status_code=404, detail="Group not found")
    if node_id in groups[group_name]["members"]:
        raise HTTPException(status_code=400, detail="Already a member")
    if node_id in groups[group_name]["pending_requests"]:
        raise HTTPException(status_code=400, detail="Request already pending")
    groups[group_name]["pending_requests"].append(node_id)
    save_groups(groups)
    return {"message": "Join request sent"}

@app.post("/approve-request")
def approve_request(data: dict, node_id: str = Header(None, alias="node-id")):
    group_name = data.get("group_name").strip()
    target_node = data.get("node_id")
    groups = load_groups()
    if group_name not in groups:
        raise HTTPException(status_code=404, detail="Group not found")
    if node_id not in groups[group_name]["members"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    if target_node not in groups[group_name]["pending_requests"]:
        raise HTTPException(status_code=400, detail="No pending request")
    groups[group_name]["pending_requests"].remove(target_node)
    groups[group_name]["members"].append(target_node)
    save_groups(groups)
    return {"message": f"{target_node} added to {group_name}"}

@app.get("/groups")
def get_groups(node_id: str = Header(None, alias="node-id")):
    all_groups = load_groups()
    return all_groups

@app.get("/shared-threats")
def get_shared_threats(node_id: str = Header(None, alias="node-id")):
    groups = load_groups()
    shared = []
    for group_name, group_data in groups.items():
        if node_id in group_data["members"]:
            for threat in group_data["shared_threats"]:
                # Transform threat data to match frontend expectations
                transformed = {
                    "ip": threat.get("src_ip", "unknown"),
                    "threat_type": threat.get("attack_type", "unknown"),
                    "source_org": threat.get("node_id", "unknown").split("-")[0] if "-" in threat.get("node_id", "") else "unknown",
                    "severity": "High" if threat.get("prediction") == "Attack" else "Low",
                    "id": threat.get("id"),
                    "src_ip": threat.get("src_ip"),
                    "dst_ip": threat.get("dst_ip"),
                    "attack_type": threat.get("attack_type"),
                    "prediction": threat.get("prediction")
                }
                shared.append(transformed)
    return shared

@app.get("/firewall-updates")
def get_firewall_updates(node_id: str = Header(None, alias="node-id")):
    return load_firewall()

@app.get("/users")
def get_users(node_id: str = Header(None, alias="node-id")):
    return load_users()

# Placeholder for MISP integration
def integrate_misp(threat):
    # Placeholder: use PyMISP to send to MISP
    # from pymisp import PyMISP
    # misp = PyMISP(url, key)
    # event = misp.new_event()
    # etc.
    print(f"Placeholder: Sending threat {threat} to MISP")
    pass

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)