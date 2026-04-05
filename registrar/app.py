from flask import Flask, request, jsonify
import os, yaml
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

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
    """Pobiera następny wolny port i aktualizuje licznik."""
    default_port = 9000
    port = default_port
    
    if os.path.exists(PORT_FILE):
        try:
            with open(PORT_FILE, "r") as f:
                content = f.read().strip()
                if content:
                    port = int(content)
        except ValueError:
            pass
    
    new_port = port + 1
    with open(PORT_FILE, "w") as f:
        f.write(str(new_port))
    return new_port

def load_config():
    """Bezpiecznie ładuje plik YAML."""
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return yaml.safe_load(f) or {}
    return {}

def save_config(config):
    """Zapisuje plik YAML."""
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        name = data.get('name')
        pub_key = data.get('pub_key')
        ip_range = data.get('ip_range', '127.0.0.1/32')

        if not name or not pub_key:
            return jsonify({"status": "error", "message": "Brak nazwy klienta lub klucza publicznego"}), 400

        # 1. Zarządzanie portami i SSH
        port = get_next_port()
        
        if os.path.exists(AUTHORIZED_KEYS):
            with open(AUTHORIZED_KEYS, "r") as f:
                if pub_key.strip() not in f.read():
                    with open(AUTHORIZED_KEYS, "a") as fa:
                        fa.write(f"\n{pub_key.strip()}")
        else:
            os.makedirs(os.path.dirname(AUTHORIZED_KEYS), exist_ok=True)
            with open(AUTHORIZED_KEYS, "w") as f:
                f.write(pub_key.strip())

        # 2. Aktualizacja strukturalnego config.yaml
        config = load_config()
        
        # Jeśli klient już istniał, zachowujemy jego stare hosty, aktualizujemy tylko resztę
        existing_hosts = config.get(name, {}).get('active_hosts', [])
        
        config[name] = {
            "range": ip_range,          # Zakres wpisany "z ręki" przy instalacji
            "active_hosts": existing_hosts, # Tu trafią dane z /ingest
            "tunnel_port": port,
            "created_at": str(os.times()[4]) # Opcjonalnie: timestamp
        }
        
        save_config(config)

        return jsonify({
            "status": "success",
            "port": port,
            "scanner_id": SCANNER_ID
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/ingest', methods=['POST'])
def ingest():
    data = request.json
    sensor_name = data.get("sensor")
    new_hosts = data.get("hosts", [])

    if not sensor_name:
        return jsonify({"status": "error", "message": "Brak nazwy sensora"}), 400

    config = load_config()

    if sensor_name in config:
        # Aktualizujemy tylko listę aktywnych hostów
        config[sensor_name]["active_hosts"] = new_hosts
        save_config(config)
        return jsonify({"status": "ok", "message": f"Zaktualizowano {len(new_hosts)} hostów"})
    else:
        return jsonify({"status": "error", "message": "Sensor nie jest zarejestrowany"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)