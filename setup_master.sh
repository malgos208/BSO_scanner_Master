#!/bin/bash
# Tworzenie struktury katalogów
mkdir -p registrar orchestrator mailer shared_config remote_keys orchestrator/reports/outbox orchestrator/reports/backup

# Plik z konfiguracją sensorów
touch shared_config/config.yaml
# Plik z tokenami
touch shared_config/valid_tokens.txt
# chmod 600 shared_config/valid_tokens.txt

# Uprawnienia
chmod -R 777 ./orchestrator/reports
chmod 700 remote_keys

# Budowanie i uruchomienie
docker compose up -d --build
echo "Master scanner ready to use"
echo "Pamiętaj, aby dodać tokeny do pliku shared_config/valid_tokens.txt"