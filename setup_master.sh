#!/bin/bash
# Tworzenie struktury katalogów
mkdir -p registrar orchestrator mailer shared_config remote_keys orchestrator/reports/outbox orchestrator/reports/backup

touch shared_config/config.yaml
touch shared_config/ports.txt
echo "9000" > shared_config/ports.txt

# Uprawnienia
chmod -R 777 ./orchestrator/reports
chmod 700 remote_keys

# Budowanie i uruchomienie
docker compose up -d --build
echo "Master scanner ready to use"