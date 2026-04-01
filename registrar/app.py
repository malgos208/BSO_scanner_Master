from flask import Flask, request, jsonify
import os, yaml
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

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
            if not content: # Jeśli plik jest pusty
                return default_port
            return int(content) + 1
    except ValueError:
        return default_port

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data['name']
    pub_key = data['pub_key']
    ip_range = data.get('ip_range', '127.0.0.1/32')

    # 1. Przydziel port (logika inkrementacji)
    port = port = get_next_port()
    
    with open(PORT_FILE, "w") as f:
        f.write(str(port))

    # 2. DOPISANIE klucza do authorized_keys dla tunnel-server
    # W tunnel-server wolumen montujemy do /config/.ssh, więc tu ścieżka musi pasować
    with open("/remote_keys/authorized_keys", "a") as f:
        f.write(f"\n{pub_key}")
    
    # 3. Aktualizacja config.yaml
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f: config = yaml.safe_load(f) or {}
    config[name] = ip_range
    with open(CONFIG_FILE, "w") as f: yaml.dump(config, f)

    # 4. Rejestracja w OpenVAS (używając nazwy kontenera openvas-master)
    try:
        connection = TLSConnection(hostname=os.getenv("GVM_HOST"), port=9390)
        with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(os.getenv("GVM_USER"), os.getenv("GVM_PASS"))
            # Host 127.0.0.1 bo tunel SSH kończy się wewnątrz openvas-master (network_mode: host w sensorze)
            # lub skaner łączy się przez localhost jeśli tunel jest na maszynie Master.
            gmp.create_scanner(name=f"Scanner_{name}", host="127.0.0.1", port=port, type=1)
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

    return jsonify({"port": port, "status": "success"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)