import time
import os
import base64
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform

# --- KONFIGURACJA GVM ---
GVM_HOST = "127.0.0.1"
GVM_PORT = 9390
GVM_USER = "admin"
GVM_PASS = "admin123"

# --- KONFIGURACJA E-MAIL ---
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "mainpublictenders@gmail.com"
SMTP_PASS = "xbzm urdr xswq priy" # W Gmailu użyj "Hasła aplikacji"
EMAIL_RECEIVER = "Diabolina208@wp.pl"

# UUID dla formatu PDF
REPORT_FORMAT_PDF = "5057e5f8-66d9-11e1-9e5e-406186ea4fc5"

def send_email_with_report(customer_name, file_path):
    print(f"📧 Wysyłanie e-maila z raportem dla {customer_name}...")
    
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = f"🔴 Raport Podatności: {customer_name} - {time.strftime('%Y-%m-%d')}"

    body = f"Witaj,\n\nSkanowanie dla klienta {customer_name} zostało zakończone pomyślnie.\nW załączniku znajduje się pełny raport w formacie PDF.\n\nPozdrawiamy,\nSystem OpenVAS Orchestrator"
    msg.attach(MIMEText(body, 'plain'))

    # Załącznik PDF
    with open(file_path, "rb") as attachment:
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(attachment.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f"attachment; filename= {os.path.basename(file_path)}")
        msg.attach(part)

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        print("✅ E-mail wysłany pomyślnie!")
    except Exception as e:
        print(f"❌ Błąd wysyłki e-mail: {e}")

def run_customer_scan(customer_name, target_range):
    connection = TLSConnection(hostname=GVM_HOST, port=GVM_PORT)
    with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
        gmp.authenticate(GVM_USER, GVM_PASS)

        # 1. Znajdź skaner
        scanner_id = None
        for s in gmp.get_scanners().findall("scanner"):
            if f"Scanner_{customer_name}" in (s.find("name").text or ""):
                scanner_id = s.get("id")
                break
        
        if not scanner_id:
            print(f"❌ Nie znaleziono skanera dla {customer_name}")
            return

        # 2. Target i Task
        target_id = gmp.create_target(name=f"Tgt_{customer_name}", hosts=[target_range])['id']
        task_id = gmp.create_task(name=f"Scan_{customer_name}", config_id="daba56c8-73ec-11df-a475-002264764cea", 
                                  target_id=target_id, scanner_id=scanner_id)['id']

        # 3. Start i Czekanie
        gmp.start_task(task_id)
        print(f"🚀 Skan {customer_name} w toku...")

        report_id = None
        while True:
            status = gmp.get_task(task_id).find("task/status").text
            if status in ("Done", "Stopped", "Error"):
                report_id = gmp.get_task(task_id).find("task/last_report/report").get("id")
                break
            time.sleep(30)

        # 4. Pobieranie PDF i wysyłka
        if report_id:
            response = gmp.get_report(report_id=report_id, report_format_id=REPORT_FORMAT_PDF, ignore_pagination=True)
            content = response.find("report").text
            file_name = f"Raport_{customer_name}.pdf"
            
            with open(file_name, "wb") as f:
                f.write(base64.b64decode(content))
            
            # --- WYSYŁKA ---
            send_email_with_report(customer_name, file_name)
            # ----------------

if __name__ == "__main__":
    run_customer_scan("Kowalski", "10.0.2.7/24")
