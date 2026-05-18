#!/usr/bin/env python3
import os
import sys
import time
import datetime
import re
import base64
import argparse
import requests
import yaml
from concurrent.futures import ThreadPoolExecutor, as_completed
from lxml import etree
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

# =========================
# CONFIG
# =========================
GVM_HOST = "127.0.0.1"
GVM_PORT = 9390
GVM_USER = os.getenv("GVM_USER")
GVM_PASS = os.getenv("GVM_PASS")

SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"

SCAN_CONFIGS = {
    "full_and_fast":    "daba56c8-73ec-11df-a475-002264764cea",
    "discovery":        "8715c877-47a0-438d-98a3-27c7a6ab2196",
    "base":             "d21f6c81-2b88-4ac1-b7b4-a2a9f2ad4663",
    "host_discovery":   "2d3f051c-55ba-11e3-bf43-406186ea4fc5",
}

PORT_LISTS = {
    "all_tcp":              "33d0cd82-57c6-11e1-8ed1-406186ea4fc5",
    "all_tcp_udp":          "4a4717fe-57d2-11e1-9a26-406186ea4fc5",
    "all_tcp_nmap100udp":   "730ef368-57e2-11e1-a90f-406186ea4fc5",
}

REPORT_FORMAT_PDF = "c402cc3e-b531-11e1-9163-406186ea4fc5"
REPORT_FORMAT_XML = "a994b278-1f62-11e1-96ac-406186ea4fc5"

CONFIG_FILE = "/app/shared_config/config.yaml"
OUTBOX_DIR = "/app/reports/outbox"
BACKUP_DIR = "/app/reports/backup"

DEFAULT_SCAN_CONFIG = SCAN_CONFIGS["full_and_fast"]
DEFAULT_PORT_LIST = PORT_LISTS["all_tcp"]

# =========================
# FUNKCJE POMOCNICZE
# =========================
def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def wait_for_gvm(host, port, max_attempts=12, delay=10):
    log(f"⏳ Oczekiwanie na gotowość GVM {host}:{port}...")
    for attempt in range(1, max_attempts + 1):
        try:
            connection = TLSConnection(hostname=host, port=port, timeout=300)
            with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
                gmp.authenticate(GVM_USER, GVM_PASS)
                log("[  OK  ] GVM osiągalny.")
                return
        except Exception:
            log(f"\tpróba {attempt}/{max_attempts} – GVM jeszcze nie gotowy")
            time.sleep(delay)
    raise RuntimeError(f"[ FAIL ] Nie udało się połączyć z GVM po {max_attempts} próbach")

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return yaml.safe_load(f) or {}
    return {}

def extract_ips(hosts_data):
    if not hosts_data:
        return []
    if isinstance(hosts_data, list):
        clean = []
        for h in hosts_data:
            match = re.search(r"\d+\.\d+\.\d+\.\d+", str(h))
            if match:
                clean.append(match.group(0))
        return clean
    return re.findall(r"\d+\.\d+\.\d+\.\d+", str(hosts_data))

def save_report_to_outbox(customer_name, report_pdf, report_xml, sensor_id=None):
    os.makedirs(OUTBOX_DIR, exist_ok=True)
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    # Prefiks to sensor_id (gdy brak: bezpieczna wersja nazwy klienta)
    file_prefix = sensor_id if sensor_id else customer_name.replace(' ', '_')
    pdf_path = os.path.join(OUTBOX_DIR, f"{file_prefix}_{timestamp}.pdf")
    
    backup_scanner_dir = os.path.join(BACKUP_DIR, file_prefix)
    os.makedirs(backup_scanner_dir, exist_ok=True)
    xml_path = os.path.join(backup_scanner_dir, f"{file_prefix}_{timestamp}.xml")

    if report_pdf is not None:
        try:
            report_node = report_pdf.find(".//report")
            if report_node is not None:
                full_text = etree.tostring(report_node, method='text', encoding='unicode')
                idx = full_text.find("JVBERi0")
                if idx != -1:
                    b64_clean = ''.join(full_text[idx:].split())
                    missing = len(b64_clean) % 4
                    if missing:
                        b64_clean += '=' * (4 - missing)
                    pdf_bytes = base64.b64decode(b64_clean)
                    with open(pdf_path, "wb") as f:
                        f.write(pdf_bytes)
                    log(f"Zapisano PDF: {pdf_path}")
        except Exception as e:
            log(f"[ FAIL ] Nie udało się zapisać PDF: {e}")

    try:
        content_xml = etree.tostring(report_xml, encoding='unicode', pretty_print=True)
        with open(xml_path, "w", encoding="utf-8") as f:
            f.write(content_xml)
        log(f"Zapisano XML: {xml_path}")
    except Exception as e:
        log(f"[ FAIL ] Błąd zapisu XML: {e}")

# =========================
# GŁÓWNA LOGIKA SKANOWANIA
# =========================
def run_customer_scan(customer_name, ips, sensor_id=None, config_id=None, port_list_id=None):
    if config_id is None:
        config_id = DEFAULT_SCAN_CONFIG
    if port_list_id is None:
        port_list_id = DEFAULT_PORT_LIST

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    task_id = None

    try:
        connection = TLSConnection(hostname=GVM_HOST, port=GVM_PORT, timeout=300)
        with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(GVM_USER, GVM_PASS)
            log(f"Inicjowanie skanu dla: {customer_name} na adresach: {ips}")
            
            target = gmp.create_target(
                name=f"Tgt_{customer_name}_{timestamp}",
                hosts=ips,
                port_list_id=port_list_id,
                alive_test="Consider Alive"
            )
            target_id = target.get("id")

            task = gmp.create_task(
                name=f"Task_{customer_name}_{timestamp}",
                config_id=config_id,
                target_id=target_id,
                scanner_id=SCANNER_ID
            )
            task_id = task.get("id")
            gmp.start_task(task_id)
    except Exception as e:
        log(f"[ FAIL ] Błąd podczas inicjowania zadania dla {customer_name}: {e}")
        return

    report_id = None
    while True:
        try:
            connection = TLSConnection(hostname=GVM_HOST, port=GVM_PORT, timeout=300)
            with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
                gmp.authenticate(GVM_USER, GVM_PASS)
                
                t = gmp.get_task(task_id)
                status = t.find(".//status").text
                progress = t.find(".//progress").text if t.find(".//progress") is not None else "?"
                
                if status == "Running":
                    log(f"⏳ [{customer_name}] Status: {status} | {progress}%")
                else:
                    log(f"⏳ [{customer_name}] Status: {status}")

                if status in ["Done", "Stopped", "Error"]:
                    last_report = t.find(".//last_report/report")
                    if last_report is not None:
                        report_id = last_report.get("id")
                    break
            time.sleep(60)
        except Exception as e:
            log(f"[ FAIL ] Problem z połączeniem (monitorowanie {customer_name}): {e}. Próba ponownego połączenia za 30s...")
            time.sleep(30)

    if not report_id:
        log(f"[ FAIL ] Nie znaleziono ID raportu dla {customer_name}. Przerywam.")
        return

    log(f"⏳ Pobieranie raportów dla {customer_name} (ID: {report_id})...")
    report_pdf = None
    report_xml = None
    
    for attempt in range(1, 15):
        try:
            connection = TLSConnection(hostname=GVM_HOST, port=GVM_PORT, timeout=300)
            with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
                gmp.authenticate(GVM_USER, GVM_PASS)
                
                if not report_xml:
                    report_xml = gmp.get_report(report_id=report_id, report_format_id=REPORT_FORMAT_XML)
                
                temp_pdf = gmp.get_report(report_id=report_id, report_format_id=REPORT_FORMAT_PDF, filter_string="levels=hmlog rows=-1")
                report_node = temp_pdf.find(".//report")
                if report_node is not None and "JVBERi0" in etree.tostring(report_node, method='text', encoding='unicode'):
                    report_pdf = temp_pdf
                    log(f"[  OK  ] PDF wygenerowany dla {customer_name}")
                    break
                
                log(f"\t[{customer_name}] PDF jeszcze niegotowy (próba {attempt}/15)...")
                time.sleep(60)
        except Exception as e:
            log(f"[ FAIL ] Błąd podczas pobierania raportu {customer_name}: {e}. Ponawiam...")
            time.sleep(30)

    save_report_to_outbox(customer_name, report_pdf, report_xml, sensor_id=sensor_id)
    log(f"[  OK  ] Proces zakończony dla {customer_name}")

# =========================
# FUNKCJA ODPYTUJĄCA SENSOR O AKTUALNE HOSTY
# =========================
def refresh_hosts_for_sensor(sensor_id):
    config = load_config()
    sensor_data = config.get(sensor_id, {})
    if not sensor_data:
        log(f"[ FAIL ] Sensor {sensor_id} nie istnieje w konfiguracji.")
        return None, []

    customer_name = sensor_data.get("name", sensor_id)
    last_known_update = float(sensor_data.get("updated_at", 0))

    try:
        requests.post(f"http://127.0.0.1:5000/trigger-discovery/{sensor_id}", timeout=5)
        log(f"Wysłano trigger discovery do sensora {sensor_id}")
    except Exception:
        log(f"[ FAIL ] Nie udało się wysłać triggera do API dla {sensor_id}")

    for _ in range(12):
        time.sleep(10)
        current_config = load_config()
        current_sensor = current_config.get(sensor_id, {})
        if float(current_sensor.get("updated_at", 0)) > last_known_update:
            log(f"[  OK  ] Nowe dane od sensora {customer_name} odebrane.")
            active_hosts = current_sensor.get("active_hosts", [])
            ips = extract_ips(active_hosts)
            return customer_name, ips

    log(f"Nie otrzymano nowych danych od sensora {customer_name} – używam ostatnich.")
    active_hosts = sensor_data.get("active_hosts", [])
    ips = extract_ips(active_hosts)
    return customer_name, ips

# =========================
# TRYB AUTOMATYCZNY
# =========================
def process_sensor(sensor_id, data):
    try:
        log(f"Sprawdzanie sensora: {data.get('name', sensor_id)} ({sensor_id})")
        customer_name, ips = refresh_hosts_for_sensor(sensor_id)
        
        if ips:
            run_customer_scan(customer_name, ips, sensor_id=sensor_id)
        else:
            log(f"Brak hostów do skanowania dla {customer_name}.")
    except Exception as e:
        log(f"[ FAIL ] KRYTYCZNY BŁĄD SENSORA {data.get('name', sensor_id)}: {e}")

# =========================
# TRYB MANUALNY (CLI)
# =========================
def manual_scan_from_sensor(sensor_id, scan_type, port_type, customer_name_override=None, trigger_discovery=False):
    if trigger_discovery:
        customer_name, ips = refresh_hosts_for_sensor(sensor_id)
    else:
        config = load_config()
        if sensor_id not in config:
            log(f"[ FAIL ] Sensor {sensor_id} nie istnieje w konfiguracji.")
            sys.exit(1)
        sensor_data = config[sensor_id]
        customer_name = customer_name_override or sensor_data.get("name", sensor_id)
        active_hosts = sensor_data.get("active_hosts", [])
        ips = extract_ips(active_hosts)

    if not ips:
        log(f"[ FAIL ] Brak aktywnych hostów dla sensora {sensor_id}. Uruchom z --trigger-discovery lub najpierw discovery.")
        sys.exit(1)

    config_id = SCAN_CONFIGS[scan_type]
    port_list_id = PORT_LISTS[port_type]

    log(f"Ręczny skan dla sensora {sensor_id} ({customer_name}): {ips}, typ={scan_type}, porty={port_type}")
    run_customer_scan(customer_name, ips, sensor_id=sensor_id, config_id=config_id, port_list_id=port_list_id)

# =========================
# PĘTLA GŁÓWNA DEMONA
# =========================
def run_daemon():
    log("Scanner Daemon start...")
    wait_for_gvm(GVM_HOST, GVM_PORT)

    while True:
        config = load_config()
        if not config:
            log("[ FAIL ] Brak sensorów w config.yaml")
        else:
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {executor.submit(process_sensor, sid, data): sid for sid, data in config.items()}
                for future in as_completed(futures):
                    sid = futures[future]
                    try:
                        future.result()
                    except Exception as e:
                        log(f"[ FAIL ] Nieobsłużony błąd w wątku sensora {sid}: {e}")

        log("Cykl zakończony. Następne sprawdzenie za 24h...")
        time.sleep(86400)

# =========================
# INTERFEJS CLI
# =========================
def main():
    parser = argparse.ArgumentParser(description="BSO Scanner Orchestrator CLI")
    subparsers = parser.add_subparsers(dest="command", help="Dostępne tryby")

    subparsers.add_parser("daemon", help="Uruchom orchestrator w trybie ciągłym")

    scan_parser = subparsers.add_parser("scan", help="Ręczny skan na podstawie sensor_id")
    scan_parser.add_argument("--sensor-id", required=True, help="ID sensora (np. 7cc00183)")
    scan_parser.add_argument("--type", choices=SCAN_CONFIGS.keys(), default="full_and_fast", help="Typ skanu")
    scan_parser.add_argument("--ports", choices=PORT_LISTS.keys(), default="all_tcp", help="Lista portów")
    scan_parser.add_argument("--name", default=None, help="Nazwa klienta (opcjonalna, domyślnie z konfiguracji)")
    scan_parser.add_argument("--trigger-discovery", action="store_true",help="Przed skanem wyślij trigger discovery i czekaj na świeże dane")

    args = parser.parse_args()

    if args.command == "scan":
        manual_scan_from_sensor(
            sensor_id=args.sensor_id,
            scan_type=args.type,
            port_type=args.ports,
            customer_name_override=args.name,
            trigger_discovery=args.trigger_discovery
        )
    elif args.command == "daemon" or args.command is None:
        run_daemon()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()