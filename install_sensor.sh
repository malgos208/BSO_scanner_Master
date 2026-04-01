#!/bin/bash

# Sprawdzenie argumentów
if [ "$#" -ne 3 ]; then
    echo "Użycie: $0 <IP_MASTERA> <NAZWA_KLIENTA> <ZAKRES_IP_DO_SKANOWANIA>"
    echo "Przykład: $0 192.168.1.10 MojaFirma 10.0.0.0/24"
    exit 1
fi

SERVER_IP=$1
CLIENT_NAME=$2
SCAN_RANGE=$3

echo "Przygotowywanie sensora dla: $CLIENT_NAME"

# 1. Generowanie kluczy SSH (jeśli nie istnieją)
mkdir -p ./ssh_keys
if [ ! -f "./ssh_keys/id_ed25519" ]; then
    ssh-keygen -t ed25519 -N "" -f ./ssh_keys/id_ed25519 -q
    echo "✅ Wygenerowano klucze SSH."
fi
PUB_KEY=$(cat ./ssh_keys/id_ed25519.pub)

# 2. Rejestracja w Masterze
echo "📡 Rejestrowanie w systemie Master..."
RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"name\":\"$CLIENT_NAME\", \"pub_key\":\"$PUB_KEY\", \"ip_range\":\"$SCAN_RANGE\"}" \
    "http://$SERVER_IP:5000/register")

# Wyciągnięcie portu z JSONa
PORT=$(echo $RESPONSE | grep -oP '(?<="port":)[0-9]+')

if [ -z "$PORT" ]; then
    echo "❌ Błąd rejestracji! Odpowiedź serwera: $RESPONSE"
    exit 1
fi

echo "✅ Zarejestrowano. Przydzielony port tunelu: $PORT"

# 3. Tworzenie pliku docker-compose.yml dla Sensora
cat <<EOF > docker-compose.yml
version: '3.8'
services:
  redis:
    image: redis:alpine
    container_name: sensor_redis
    restart: always

  tunnel:
    image: alpine/openssh
    container_name: sensor_tunnel
    depends_on:
      - scanner
    volumes:
      - "./ssh_keys:/root/.ssh:ro"
    # Dodajemy -o ConnectTimeout dla stabilności
    command: ssh -o StrictHostKeyChecking=no -o ExitOnForwardFailure=yes -o ConnectTimeout=10 -N -R $PORT:scanner:9391 scanner_user@$SERVER_IP -p 2222 -i /root/.ssh/id_ed25519
    restart: always

  scanner:
    image: greenbone/ospd-openvas:stable
    container_name: sensor_scanner
    privileged: true
    depends_on:
      - redis
    environment:
      - OSPD_OPENVAS_REDIS_URL=redis://redis:6379/0
    command: ["ospd-openvas", "--address", "0.0.0.0", "--port", "9391", "--notls", "--redis-server", "redis://redis:6379/0"]
    restart: always
EOF

# 4. Uruchomienie
docker compose up -d
echo "🚀 Sensor działa w tle."