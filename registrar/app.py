from flask import Flask, request, jsonify
import os, yaml
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from gvm.protocols.gmpv208.entities import ScannerType

app = Flask(__name__)

# Ścieżki zgodne z Twoim montowaniem wolumenów w docker-compose
PORT_FILE = "/app/shared_config/ports.txt"
CONFIG_FILE = "/app/shared_config/config.yaml"
AUTHORIZED_KEYS = "/config/.ssh/authorized_keys"

SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"

GVM_HOST = "127.0.0.1"
GVM_PORT = 9390
GVM_USER = os.getenv("GVM_USER")
GVM_PASS = os.getenv("GVM_PASS")

def get_next_port():
    port = 9000
    if os.path.exists(PORT_FILE):
        with open(PORT_FILE, "r") as f:
            port = int(f.read().strip() or 9000)
    new_port = port + 1
    with open(PORT_FILE, "w") as f: f.write(str(new_port))
    return new_port

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        name, pub_key = data.get('name'), data.get('pub_key')
        ip_range = data.get('ip_range', '127.0.0.1/32')

        if not name or not pub_key: return jsonify({"error": "Missing data"}), 400

        port = get_next_port()

        # 1. SSH Key
        os.makedirs(os.path.dirname(AUTHORIZED_KEYS), exist_ok=True)
        with open(AUTHORIZED_KEYS, "a") as f: f.write(f"\n{pub_key.strip()}")

        # 2. GVM: Tworzenie skanera dedykowanego dla tego Sensora
        connection = TLSConnection(hostname=GVM_HOST, port=GVM_PORT)
        with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(GVM_USER, GVM_PASS)
            
            # GVM będzie łączył się z localhost:PORT, co tunel SSH przekieruje do Sensora
            scanner_res = gmp.create_scanner(
                name=f"Scanner_{name}",
                host="127.0.0.1",
                port=port,
                type="OSP"
            )
            scanner_id = scanner_res.get('id')

        # 3. Config update
        config = {}
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f: config = yaml.safe_load(f) or {}

        config[name] = {
            "range": ip_range,
            "active_hosts": [],
            "tunnel_port": port,
            "scanner_id": scanner_id
        }
        with open(CONFIG_FILE, "w") as f: yaml.dump(config, f)

        return jsonify({"status": "success", "port": port, "scanner_id": scanner_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/ingest', methods=['POST'])
def ingest():
    data = request.json
    name, hosts = data.get("sensor"), data.get("hosts", [])
    if not name: return jsonify({"error": "No sensor name"}), 400
    
    with open(CONFIG_FILE, "r") as f: config = yaml.safe_load(f) or {}
    if name in config:
        config[name]["active_hosts"] = hosts
        with open(CONFIG_FILE, "w") as f: yaml.dump(config, f)
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)