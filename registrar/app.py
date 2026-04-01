from flask import Flask, request, jsonify
import os, yaml
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

app = Flask(__name__)

# Ścieżki zgodne z Twoim montowaniem wolumenów w docker-compose
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
    except (ValueError, FileNotFoundError):
        return default_port

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        name = data.get('name')
        pub_key = data.get('pub_key')
        ip_range = data.get('ip_range', '127.0.0.1/32')

        if not name or not pub_key:
            return jsonify({"status": "error", "message": "Brak nazwy lub klucza"}), 400

        port = get_next_port()

        # 1. Zapisz klucz dla tunnel-server
        with open("/remote_keys/authorized_keys", "a") as f:
            f.write(f"\n{pub_key}")

        # 2. Zaktualizuj licznik portów
        with open(PORT_FILE, "w") as f:
            f.write(str(port))

        # 3. Zaktualizuj config.yaml
        config = {}
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r") as f:
                config = yaml.safe_load(f) or {}
        config[name] = ip_range
        with open(CONFIG_FILE, "w") as f:
            yaml.dump(config, f)

        # 4. Połączenie z GVM i rejestracja skanera
        # Jeśli używasz network_mode: host, GVM jest na 127.0.0.1
        gvm_host = "127.0.0.1"
        connection = TLSConnection(hostname=gvm_host, port=9390)
        
        with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(os.getenv("GVM_USER"), os.getenv("GVM_PASS"))
            
            # Rejestracja skanera OSP (typ 2)
            gmp.create_scanner(
                name=f"Scanner_{name}",
                host="127.0.0.1",
                port=port,
                type=2,
                credential_id=""
            )
            
        return jsonify({"port": port, "status": "success"})

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # Ważne: Flask musi słuchać na 0.0.0.0 wewnątrz kontenera
    app.run(host='0.0.0.0', port=5000)