import datetime
import os
import time
import shutil
import smtplib
import yaml
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

OUTBOX_DIR = "/app/reports/outbox"
BACKUP_DIR = "/app/reports/backup"
CONFIG_FILE = "/app/shared_config/config.yaml"

SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")

def log(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return yaml.safe_load(f) or {}
    return {}

def get_customer_name(sensor_id):
    """Zwraca nazwę klienta dla danego sensor_id na podstawie config.yaml."""
    config = load_config()
    sensor = config.get(sensor_id, {})
    return sensor.get('name', sensor_id)

def send_and_archive():
    files = [f for f in os.listdir(OUTBOX_DIR) if f.endswith('.pdf')]
    for file_name in files:
        file_path = os.path.join(OUTBOX_DIR, file_name)
        
        # sensor_id z nazwy pliku (wszystko przed pierwszym '_')
        sensor_id = file_name.split('_')[0] if '_' in file_name else file_name
        customer_name = get_customer_name(sensor_id)
        
        log(f"Przetwarzanie: {file_name} (sensor: {sensor_id}, klient: {customer_name})")
        
        success = send_email(file_path, sensor_id, customer_name)
        
        if success:
            # Folder backup według sensor_id
            backup_dir = os.path.join(BACKUP_DIR, sensor_id)
            os.makedirs(backup_dir, exist_ok=True)
            dest = os.path.join(backup_dir, file_name)
            shutil.move(file_path, dest)
            log(f"Zarchiwizowano: {dest}")
        else:
            log(f"[ FAIL ] Błąd wysyłania {file_name} – spróbuję w następnej iteracji")

def send_email(file_path, sensor_id, customer_name):
    file_name = os.path.basename(file_path)
    subject = f"Raport podatności – sensor {sensor_id} ({customer_name}): {file_name}"
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = subject

    body = f"W załączniku raport dla klienta: {customer_name} (sensor: {sensor_id}).\n\nPozdrawiamy,\nZespół BSO"
    msg.attach(MIMEText(body, 'plain'))

    try:
        with open(file_path, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f"attachment; filename= {file_name}")
            msg.attach(part)

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        log(f"[ FAIL ] Błąd wysyłania: {e}")
        return False

if __name__ == "__main__":
    log("Mailer Daemon start...")
    while True:
        os.makedirs(OUTBOX_DIR, exist_ok=True)
        os.makedirs(BACKUP_DIR, exist_ok=True)
        send_and_archive()
        time.sleep(60)