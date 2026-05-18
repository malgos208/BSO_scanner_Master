import datetime

from flask import Flask, request, jsonify
import os, yaml
import uuid

app = Flask(__name__)

pending_tasks = {} # Kolejka zadań w pamięci (Sensor pyta o swoje ID)

CONFIG_FILE = "/app/shared_config/config.yaml"
AUTHORIZED_KEYS = "/config/.ssh/authorized_keys"
VALID_TOKENS_FILE = "/app/shared_config/valid_tokens.txt"

@app.before_request
def restrict_access():
    public_endpoints = ['register']
    if request.endpoint in public_endpoints:
        return None
    if request.remote_addr != '127.0.0.1':
        return jsonify({"status": "error", "message": "Odmowa dostępu. Endpoint dostępny tylko przez tunel SSH."}), 403

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

def validate_and_use_token(token):
    """Sprawdza, czy token istnieje i usuwa go (jednorazowy)."""
    if not os.path.exists(VALID_TOKENS_FILE):
        return False
    with open(VALID_TOKENS_FILE, "r") as f:
        tokens = [line.strip() for line in f if line.strip()]
    if token not in tokens:
        return False
    tokens.remove(token)
    with open(VALID_TOKENS_FILE, "w") as f:
        for t in tokens:
            f.write(t + "\n")
    return True

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        token = data.get('token')
        if not token:
            return jsonify({"status": "error", "message": "Brak tokena autoryzacyjnego"}), 401

        if not validate_and_use_token(token):
            return jsonify({"status": "error", "message": "Token nieprawidłowy lub już wykorzystany"}), 403
        
        sensor_id = str(uuid.uuid4())[:8]
        customer_name = data.get('name', 'N/A')
        pub_key = data.get('pub_key')
        ip_range = data.get('ip_range', '127.0.0.1/32')

        if not pub_key:
            return jsonify({"status": "error", "message": "Brak klucza publicznego"}), 400

        # Dodanie klucza do authorized_keys
        if os.path.exists(AUTHORIZED_KEYS):
            with open(AUTHORIZED_KEYS, "r") as f:
                if pub_key.strip() not in f.read():
                    with open(AUTHORIZED_KEYS, "a") as fa:
                        # Ograniczenie klucza tylko do tunelowania portów, bez dostępu do shella
                        ssh_restriction = 'no-pty,no-X11-forwarding,no-agent-forwarding,command="/bin/false" '
                        fa.write(f"\n{ssh_restriction}{pub_key.strip()}")
        else:
            os.makedirs(os.path.dirname(AUTHORIZED_KEYS), exist_ok=True)
            with open(AUTHORIZED_KEYS, "w") as f:
                f.write(pub_key.strip())

        # Aktualizacja config.yaml
        config = load_config()
                
        config[sensor_id] = {
            "name": customer_name,
            "range": ip_range, # Zakres określony przy umowie z klientem
            "active_hosts": [], # Tu trafią dane z /ingest
            "updated_at": str(os.times()[4]),
            "updated_at_iso": datetime.datetime.now().isoformat()
        }
        save_config(config)

        return jsonify({
            "status": "registered",
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
        config[sensor_id]["updated_at_iso"] = datetime.datetime.now().isoformat()
        
        save_config(config)
        return jsonify({"status": "ok", "message": f"Zaktualizowano {len(new_hosts)} hostów"})
    else:
        return jsonify({"status": "error", "message": "Sensor nie jest zarejestrowany"}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)