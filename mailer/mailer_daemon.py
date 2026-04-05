import os
import time
import shutil
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Ścieżki wewnątrz kontenera
OUTBOX_DIR = "/app/reports/outbox"
BACKUP_DIR = "/app/reports/backup"

# Konfiguracja
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
EMAIL_RECEIVER = os.getenv("EMAIL_RECEIVER")

def send_and_archive():
    # Lista plików PDF w outbox
    files = [f for f in os.listdir(OUTBOX_DIR) if f.endswith('.pdf')]

    for file_name in files:
        file_path = os.path.join(OUTBOX_DIR, file_name)
        
        # 1. Wyciągnięcie nazwy klienta z nazwy pliku (wszystko przed pierwszym '_')
        try:
            customer_name = file_name.split('_')[0]
        except Exception:
            customer_name = "Nieznany"

        print(f"📬 Processing: {file_name} for customer: {customer_name}")

        # 2. Wysyłka E-mail
        success = send_email(file_path, customer_name)

        if success:
            # 3. Tworzenie dedykowanego folderu backupu dla klienta
            customer_backup_dir = os.path.join(BACKUP_DIR, customer_name)
            os.makedirs(customer_backup_dir, exist_ok=True)

            # 4. Przeniesienie pliku (Backup)
            dest_path = os.path.join(customer_backup_dir, file_name)
            shutil.move(file_path, dest_path)
            print(f"📁 Archived: {dest_path}")
        else:
            print(f"⚠️ Error sending {file_name} - will try again in the next loop.")

def send_email(file_path, customer_name):
    file_name = os.path.basename(file_path)
    print(f"📧 Processing report: {file_name}")
    
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER
    msg['To'] = EMAIL_RECEIVER
    msg['Subject'] = f"🔴 Raport Podatności dla klienta {customer_name}: {file_name}"

    body = f"W załączniku znajduje się raport dla klienta: {customer_name}.\n\nPozdrawiamy,\nZespół BSO"
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
        print(f"❌ Error sending {file_name}: {e}")
        return False

if __name__ == "__main__":
    print("Mailer Daemon started...")

    while True:
        os.makedirs(OUTBOX_DIR, exist_ok=True)
        os.makedirs(BACKUP_DIR, exist_ok=True)

        send_and_archive()
        time.sleep(60)