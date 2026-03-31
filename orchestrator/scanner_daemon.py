import time
import os
import base64
import smtplib
import yaml
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

# --- KONFIGURACJA ---
GVM_HOST = "127.0.0.1"
GVM_PORT = 9390
GVM_USER = os.getenv("GVM_USER", "admin")
GVM_PASS = os.getenv("GVM_PASS", "admin123")

REPORT_FORMAT_PDF = "5057e5f8-66d9-11e1-9e5e-406186ea4fc5"
LAST_SCANS = {}

def get_target_from_config(customer_name):
    try:
        with open("config.yaml", "r") as f:
            config = yaml.safe_load(f)
            return config.get(customer_name)
    except Exception as e:
        print(f"❌ Błąd odczytu config.yaml: {e}")
        return None

def send_email_with_report(customer_name, file_path):
    print(f"📧 Wysyłanie raportu dla {customer_name}...")
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = f"🔴 Raport Podatności: {customer_name} - {datetime.now().strftime('%Y-%m-%d')}"

    body = f"Skanowanie dla {customer_name} zakończone.\nRaport w załączniku."
    msg.attach(MIMEText(body, 'plain'))

    with open(file_path, "rb") as attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f"attachment; filename={os.path.basename(file_path)}")
        msg.attach(part)

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        print("✅ E-mail wysłany!")
    except Exception as e:
        print(f"❌ Błąd e-mail: {e}")

def run_customer_scan(gmp, customer_name, target_range):
    # 1. Znajdź skaner
    scanner_id = None
    for s in gmp.get_scanners().findall("scanner"):
        if f"Scanner_{customer_name}" in (s.find("name").text or ""):
            scanner_id = s.get("id")
            break
    
    if not scanner_id:
        return

    print(f"🚀 Uruchamiam skan dla {customer_name} na zasięgu {target_range}")
    target_id = gmp.create_target(name=f"Tgt_{customer_name}", hosts=[target_range])['id']
    task_id = gmp.create_task(name=f"Scan_{customer_name}", 
                              config_id="daba56c8-73ec-11df-a475-002264764cea", 
                              target_id=target_id, 
                              scanner_id=scanner_id)['id']

    gmp.start_task(task_id)
    
    while True:
        status = gmp.get_task(task_id).find("task/status").text
        if status in ("Done", "Stopped", "Error"):
            break
        time.sleep(30)

    report_id = gmp.get_task(task_id).find("task/last_report/report").get("id")
    if report_id:
        response = gmp.get_report(report_id=report_id, report_format_id=REPORT_FORMAT_PDF, ignore_pagination=True)
        content = response.find("report").text
        file_name = f"/app/reports/Raport_{customer_name}.pdf"
        with open(file_name, "wb") as f:
            f.write(base64.b64decode(content))
        send_email_with_report(customer_name, file_name)

def run_daemon():
    print("🤖 Demon uruchomiony...")
    while True:
        try:
            connection = TLSConnection(hostname=GVM_HOST, port=GVM_PORT)
            with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
                gmp.authenticate(GVM_USER, GVM_PASS)
                
                for s in gmp.get_scanners().findall("scanner"):
                    s_name = s.find("name").text
                    s_id = s.get("id")

                    if s_name.startswith("Scanner_"):
                        client_name = s_name.replace("Scanner_", "")
                        last_time = LAST_SCANS.get(s_id)
                        
                        if last_time is None or datetime.now() - last_time > timedelta(hours=24):
                            target_range = get_target_from_config(client_name)
                            if target_range:
                                run_customer_scan(gmp, client_name, target_range)
                                LAST_SCANS[s_id] = datetime.now()
        except Exception as e:
            print(f"⚠️ Czekam na GVM... ({e})")
        
        time.sleep(300)

if __name__ == "__main__":
    run_daemon()