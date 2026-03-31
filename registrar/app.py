from flask import Flask, request, jsonify
import os
import yaml
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

app = Flask(__name__)
PORT_FILE = "/app/data/ports.txt"
CONFIG_FILE = "/app/config/config.yaml"

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data['name']
    pub_key = data['pub_key']
    ip_range = data.get('ip_range', '127.0.0.1/32') # Domyślnie jeśli nie podano

    # 1. Przydziel port
    port = 9001
    if os.path.exists(PORT_FILE):
        with open(PORT_FILE, "r") as f: port = int(f.read()) + 1
    with open(PORT_FILE, "w") as f: f.write(str(port))

    # 2. Zapisz klucz dla tunelu SSH
    with open(f"/remote_keys/{name}.pub", "w") as f:
        f.write(pub_key)
    
    # 3. Zaktualizuj config.yaml dla Orchestratora
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f: config = yaml.safe_load(f) or {}
    config[name] = ip_range
    with open(CONFIG_FILE, "w") as f: yaml.dump(config, f)

    # 4. Rejestracja w OpenVAS
    try:
        connection = TLSConnection(hostname="gvmd", port=9390) # Używamy nazwy serwisu z docker-compose
        with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(os.getenv("GVM_USER"), os.getenv("GVM_PASS"))
            # Typ 1 to zazwyczaj skaner OSP (OpenVAS)
            gmp.create_scanner(name=f"Scanner_{name}", host="127.0.0.1", port=port, type=1)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"port": port, "status": "success"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)