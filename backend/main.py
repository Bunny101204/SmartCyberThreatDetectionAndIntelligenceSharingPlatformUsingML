from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import json
import os
import random
import uuid
from datetime import datetime
import bcrypt
import jwt

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

# Serve static files on /static
frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend'))
app.mount("/static", StaticFiles(directory=frontend_dir, html=True), name="frontend")

@app.get("/")
def root():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/static/index.html")

base_storage_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'storage'))
THREATS_FILE = os.path.join(base_storage_dir, 'threats.json')
GROUPS_FILE = os.path.join(base_storage_dir, 'groups.json')
USERS_FILE = os.path.join(base_storage_dir, 'users.json')
FIREWALL_FILE = os.path.join(base_storage_dir, 'firewall_updates.json')

SECRET_KEY = "your-secret-key-here"  # Change for production
security = HTTPBearer()

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

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
        return payload["node_id"]
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/register")
def register(data: dict):
    org = data.get("org")
    node_name = data.get("node_name")
    password = data.get("password")
    if not org or not node_name or not password:
        raise HTTPException(status_code=400, detail="Missing fields")
    users = load_users()
    if org not in users:
        users[org] = {}
    if node_name in users[org]:
        raise HTTPException(status_code=400, detail="User already exists")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[org][node_name] = {"password": hashed}
    save_users(users)
    return {"message": "Registered successfully"}

@app.post("/login")
def login(data: dict):
    org = data.get("org")
    node_name = data.get("node_name")
    password = data.get("password")
    users = load_users()
    if org not in users or node_name not in users[org]:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not bcrypt.checkpw(password.encode(), users[org][node_name]["password"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    node_id = f"{org}:{node_name}"
    token = jwt.encode({"node_id": node_id}, SECRET_KEY, algorithm="HS256")
    return {"token": token, "node_id": node_id}

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
def detect_threat(data: dict, node_id: str = Depends(verify_token)):
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
def get_threats(node_id: str = Depends(verify_token)):
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
def create_group(data: dict, node_id: str = Depends(verify_token)):
    group_name = data.get("group_name")
    org = node_id.split(':')[0]
    full_group_name = f"{org}:{group_name}"
    groups = load_groups()
    if full_group_name in groups:
        raise HTTPException(status_code=400, detail="Group already exists")
    groups[full_group_name] = {"members": [node_id], "pending_requests": [], "shared_threats": []}
    save_groups(groups)
    return {"message": f"Group {group_name} created"}

@app.post("/request-join")
def request_join(data: dict, node_id: str = Depends(verify_token)):
    group_name = data.get("group_name")
    org = node_id.split(':')[0]
    full_group_name = f"{org}:{group_name}"
    groups = load_groups()
    if full_group_name not in groups:
        raise HTTPException(status_code=404, detail="Group not found")
    if node_id in groups[full_group_name]["members"]:
        raise HTTPException(status_code=400, detail="Already a member")
    if node_id in groups[full_group_name]["pending_requests"]:
        raise HTTPException(status_code=400, detail="Request already pending")
    groups[full_group_name]["pending_requests"].append(node_id)
    save_groups(groups)
    return {"message": "Join request sent"}

@app.post("/approve-request")
def approve_request(data: dict, node_id: str = Depends(verify_token)):
    group_name = data.get("group_name")
    target_node = data.get("node_id")
    org = node_id.split(':')[0]
    full_group_name = f"{org}:{group_name}"
    groups = load_groups()
    if full_group_name not in groups:
        raise HTTPException(status_code=404, detail="Group not found")
    if node_id not in groups[full_group_name]["members"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    if target_node not in groups[full_group_name]["pending_requests"]:
        raise HTTPException(status_code=400, detail="No pending request")
    groups[full_group_name]["pending_requests"].remove(target_node)
    groups[full_group_name]["members"].append(target_node)
    save_groups(groups)
    return {"message": f"{target_node} added to {group_name}"}

@app.get("/groups")
def get_groups(node_id: str = Depends(verify_token)):
    org = node_id.split(':')[0]
    all_groups = load_groups()
    return {k: v for k, v in all_groups.items() if k.startswith(f"{org}:")}

@app.get("/shared-threats")
def get_shared_threats(node_id: str = Depends(verify_token)):
    org = node_id.split(':')[0]
    groups = load_groups()
    shared = []
    for group_name, group_data in groups.items():
        if group_name.startswith(f"{org}:") and node_id in group_data["members"]:
            shared.extend(group_data["shared_threats"])
    return shared

@app.get("/firewall-updates")
def get_firewall_updates(node_id: str = Depends(verify_token)):
    return load_firewall()

@app.get("/users")
def get_users():
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