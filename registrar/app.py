from flask import Flask, request, jsonify
import os, yaml
import uuid

app = Flask(__name__)

pending_tasks = {} # Kolejka zadań w pamięci (Sensor pyta o swoje ID)

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
        sensor_id = str(uuid.uuid4())[:8]
        customer_name = data.get('name', 'N/A')
        pub_key = data.get('pub_key')
        ip_range = data.get('ip_range', '127.0.0.1/32')

        if not pub_key:
            return jsonify({"status": "error", "message": "Brak klucza publicznego"}), 400

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
                
        config[sensor_id] = {
            "name": customer_name,
            "range": ip_range, # Zakres określony przy umowie z klientwem
            "active_hosts": [], # Tu trafią dane z /ingest
            "tunnel_port": port, # Port, na którym sensor ma postawić tunel
            "updated_at": str(os.times()[4])
        }
        save_config(config)

        return jsonify({
            "status": "registered",
            "port": port,
            "sensor_id": sensor_id
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/check-tasks/<sensor_id>', methods=['GET'])
def check_tasks(sensor_id):
    # Sprawdź czy dla tego ID jest zaplanowane discovery
    should_run = pending_tasks.get(sensor_id, False)
    if should_run:
        pending_tasks[sensor_id] = False # Resetuj flagę
    return jsonify({"run_nmap": should_run})

@app.route('/trigger-discovery/<sensor_id>', methods=['POST'])
def trigger_discovery(sensor_id):
    pending_tasks[sensor_id] = True
    return jsonify({"status": "queued"})

@app.route('/ingest', methods=['POST'])
def ingest():
    data = request.json
    sensor_id = data.get("sensor_id")
    new_hosts = data.get("hosts", [])

    if not sensor_id:
        return jsonify({"status": "error", "message": "Brak ID sensora"}), 400

    config = load_config()

    if sensor_id in config:
        # Aktualizujemy tylko listę aktywnych hostów i datę aktualizacji
        config[sensor_id]["active_hosts"] = new_hosts
        config[sensor_id]["updated_at"] = str(os.times()[4])
        
        save_config(config)
        return jsonify({"status": "ok", "message": f"Zaktualizowano {len(new_hosts)} hostów"})
    else:
        return jsonify({"status": "error", "message": "Sensor nie jest zarejestrowany"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)