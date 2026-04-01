from flask import Flask, request, jsonify
import os, yaml
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
# Dodajemy import typów skanera dla pewności
from gvm.protocols.gmpv208.entities.scanner_types import ScannerType

app = Flask(__name__)
PORT_FILE = "/app/ports.txt"
CONFIG_FILE = "/app/config.yaml"

def get_next_port():
    default_port = 9001
    if not os.path.exists(PORT_FILE):
        return default_port
    try:
        with open(PORT_FILE, "r") as f:
            content = f.read().strip()
            return int(content) + 1 if content else default_port
    except ValueError:
        return default_port

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data['name']
    pub_key = data['pub_key']
    ip_range = data.get('ip_range', '127.0.0.1/32')

    port = get_next_port()

    # 1. Zapisz klucz dla tunelu
    with open("/remote_keys/authorized_keys", "a") as f:
        f.write(f"\n{pub_key}")

    # 2. Zapisz nowy port
    with open(PORT_FILE, "w") as f:
        f.write(str(port))

    # 3. Aktualizuj config.yaml
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f: config = yaml.safe_load(f) or {}
    config[name] = ip_range
    with open(CONFIG_FILE, "w") as f: yaml.dump(config, f)

    # 4. Rejestracja w OpenVAS
    try:
        # Pobieramy host z ENV (openvas-master)
        gvm_host = os.getenv("GVM_HOST", "127.0.0.1")
        connection = TLSConnection(hostname=gvm_host, port=9390)
        
        with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(os.getenv("GVM_USER"), os.getenv("GVM_PASS"))
            
            # POPRAWKA TUTAJ: 
            # Argumenty pozycyjne: name, host, port, type
            # Typ 2 (ScannerType.OSP_SCANNER) jest wymagany dla OSPD-OpenVAS
            gmp.create_scanner(f"Scanner_{name}", "127.0.0.1", port, 2)
            
        return jsonify({"port": port, "status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)