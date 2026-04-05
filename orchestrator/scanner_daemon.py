import os
import time, datetime
import re
import base64
import yaml
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

#SCANNER_ID = "6acd0832-df90-11e4-b9d5-28d24461215b"
SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"
FULL_AND_FAST_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
DISCOVERY_CONFIG_ID = "8715c877-47a0-438d-98a3-27c7a6ab2196"
TCP_PORT_LIST_ID = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5" #All IANA assigned TCP
TCP_UDP_PORT_LIST_ID = "4a4717fe-57d2-11e1-9a26-406186ea4fc5" #All IANA assigned TCP and UDP
ALL_PORT_LIST_ID = "730ef368-57e2-11e1-a90f-406186ea4fc5" #All TCP and Nmap top 100 UDP

REPORT_FORMAT_PDF = "c402cc3e-b531-11e1-9163-406186ea4fc5"
REPORT_FORMAT_XML = "a994b278-1f62-11e1-96ac-406186ea4fc5"

CONFIG_PATH = "/app/shared_config/config.yaml"
OUTBOX_DIR = "/app/reports/outbox"


def save_report_to_outbox(customer_name, report_pdf, report_xml):
    os.makedirs(OUTBOX_DIR, exist_ok=True)

    timestamp = time.strftime("%Y%m%d-%H%M%S")

    pdf_path = os.path.join(OUTBOX_DIR, f"{customer_name}_{timestamp}.pdf")
    xml_path = os.path.join(OUTBOX_DIR, f"{customer_name}_{timestamp}.xml")

    # =========================
    # PDF PROCESSING
    # =========================
    try:
        pdf_node = report_pdf.find(".//report")

        if pdf_node is None or not pdf_node.text:
            print("❌ Brak zawartości PDF w raporcie")
        else:
            content_pdf = pdf_node.text.strip()

            try:
                pdf_bytes = base64.b64decode(content_pdf)

                with open(pdf_path, "wb") as f:
                    f.write(pdf_bytes)

                print(f"📄 Saved PDF: {pdf_path}")
                pdf_ok = True

            except Exception as e:
                print(f"❌ Nie udało się zapisać PDF: {e}")

    except Exception as e:
        print(f"❌ PDF processing error: {e}")

    # =========================
    # XML PROCESSING
    # =========================
    try:
        content_xml = etree.tostring(
            report_xml,
            encoding='unicode',
            pretty_print=True
        )

        try:
            with open(xml_path, "w", encoding="utf-8") as f:
                f.write(content_xml)

            print(f"📄 Saved XML: {xml_path}")
            xml_ok = True

        except Exception as e:
            print(f"❌ Failed to save XML: {e}")

    except Exception as e:
        print(f"❌ XML processing error: {e}")


def extract_ips(hosts_data):
    """
    Wyciąga adresy IP z listy lub stringa.
    """
    if not hosts_data:
        return []
    
    # Jeśli dostaliśmy listę (np. z config[sensor]['active_hosts'])
    if isinstance(hosts_data, list):
        clean_ips = []
        for h in hosts_data:
            match = re.search(r"\d+\.\d+\.\d+\.\d+", str(h))
            if match:
                clean_ips.append(match.group(0))
        return clean_ips

    # Jeśli dostaliśmy stringa (fallback)
    return re.findall(r"\d+\.\d+\.\d+\.\d+", str(hosts_data))

def run_customer_scan(gmp, customer_name, ips):
    # Używamy poprawionego datetime.now()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    try:
        print(f"🚀 Inicjowanie skanu dla: {customer_name} na adresach: {ips}")

        # 1. CREATE TARGET
        target = gmp.create_target(
            name=f"Tgt_{customer_name}_{timestamp}",
            hosts=ips,
            port_list_id=TCP_PORT_LIST_ID,
            alive_test="Consider Alive"
        )
        target_id = target.get("id")

        # 2. CREATE TASK
        task = gmp.create_task(
            name=f"Task_{customer_name}_{timestamp}",
            config_id=FULL_AND_FAST_CONFIG_ID,
            target_id=target_id,
            scanner_id=SCANNER_ID
        )
        task_id = task.get("id")

        # 3. START & WAIT
        gmp.start_task(task_id)
        
        while True:
            t = gmp.get_task(task_id)
            status = t.find("task/status").text
            print(f"⏳ [{customer_name}] Status: {status}")
            if status in ["Done", "Stopped", "Error"]:
                break
            time.sleep(60)

        # 4. FETCH & SAVE (PDF + XML)
        report_id = gmp.get_task(task_id).find("task/last_report/report").get("id")
        
        report_pdf = gmp.get_report(report_id=report_id, report_format_id=REPORT_FORMAT_PDF,
                                    ignore_pagination=True, filter_string="levels=hmlog rows=-1")
        
        report_xml = gmp.get_report(report_id=report_id, report_format_id=REPORT_FORMAT_XML,
                                    filter_string="levels=hmlog rows=-1")

        save_report_to_outbox(customer_name, report_pdf, report_xml)
        print(f"✅ Skan zakończony, raporty zapisane dla {customer_name}")

    except Exception as e:
        print(f"💥 Błąd podczas skanowania {customer_name}: {e}")

# =========================
# DAEMON LOOP
# =========================
def run_daemon():
    print("🤖 Scanner Daemon started")

    while True:
        try:
            connection = TLSConnection(hostname=GVM_HOST, port=GVM_PORT)

            with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
                gmp.authenticate(GVM_USER, GVM_PASS)

                if not os.path.exists(CONFIG_PATH):
                    print("⚠️ Brak pliku config.yaml")
                else:
                    with open(CONFIG_PATH, "r") as f:
                        config = yaml.safe_load(f) or {}

                    for customer_name, customer_data in config.items():
                        active_hosts = customer_data.get("active_hosts", [])
                        
                        # Walidacja adresów IP
                        ips = extract_ips(active_hosts)

                        if not ips:
                            print(f"Brak aktywnych hostów dla {customer_name}. Czekam na dane z Sensora.")
                            continue

                        run_customer_scan(gmp, customer_name, ips)

        except Exception as e:
            print(f"Błąd pętli głównej: {e}")

        print("Pętla zakończona. Następne sprawdzenie za 24h...")
        time.sleep(86400)

if __name__ == "__main__":
    run_daemon()


# # orchestrator/scanner_daemon.py (fragment)
# import threading

# def manage_scan(customer_name, targets):
#     # Logika run_customer_scan tutaj...
#     # Po zakończeniu zapisz plik w /app/reports/ready_to_send/
#     pass

# def main_loop():
#     while True:
#         config = load_config() # z shared_config/config.yaml
#         for customer, data in config.items():
#             t = threading.Thread(target=manage_scan, args=(customer, data['hosts']))
#             t.start()
#         time.sleep(86400) # Skan raz na dobę