from flask import Flask, request, jsonify
import os, yaml
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

app = Flask(__name__)

# Ścieżki zgodne z Twoim montowaniem wolumenów w docker-compose
PORT_FILE = "/app/ports.txt"
CONFIG_FILE = "/app/config.yaml"

GVM_HOST = "127.0.0.1"
GVM_PORT = 9390

SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"  # OpenVAS Default
CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"   # Full and Fast

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
        AUTHORIZED_KEYS = "/config/.ssh/authorized_keys"
        existing_keys = []

        if os.path.exists(AUTHORIZED_KEYS):
            with open(AUTHORIZED_KEYS, "r") as f:
               existing_keys = f.read().splitlines()

        if pub_key.strip() not in existing_keys:
            with open(AUTHORIZED_KEYS, "a") as f:
                f.write(pub_key.strip() + "\n")

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

        # GVM connection
        connection = TLSConnection(hostname=GVM_HOST, port=GVM_PORT)

        with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(
                os.getenv("GVM_USER", "admin"),
                os.getenv("GVM_PASS", "admin123")
            )

            # test connection
            gmp.get_scanners()

        return jsonify({
            "status": "success",
            "port": port,
            "scanner_id": SCANNER_ID
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    # Flask musi słuchać na 0.0.0.0 wewnątrz kontenera
    app.run(host='0.0.0.0', port=5000)