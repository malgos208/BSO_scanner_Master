import time
import os
import base64
import smtplib
import yaml
import re
from lxml import etree
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform


# =========================
# CONFIG
# =========================
GVM_HOST = "127.0.0.1"
GVM_PORT = 9390
GVM_USER = os.getenv("GVM_USER", "admin")
GVM_PASS = os.getenv("GVM_PASS", "admin123")

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "mainpublictenders@gmail.com"
SMTP_PASS = "xbzm urdr xswq priy"
EMAIL_RECEIVER = "Diabolina208@wp.pl"

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

# =========================
# EMAIL
# =========================
def send_email(customer_name, file_path):
    print(f"📧 Sending email for {customer_name}")

    msg = MIMEMultipart()
    msg["From"] = SMTP_USER
    msg["To"] = EMAIL_RECEIVER
    msg["Subject"] = f"🔴 Vulnerability Report: {customer_name} ({datetime.now().date()})"

    msg.attach(MIMEText("Scan completed. Report attached.", "plain"))

    with open(file_path, "rb") as f:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename={os.path.basename(file_path)}"
        )
        msg.attach(part)

    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.send_message(msg)

    print("✅ Email sent")


# =========================
# SCAN PIPELINE
# =========================
def run_customer_scan(gmp, customer_name, hosts):

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    print(f"🚀 Scan: {customer_name} -> {hosts}")

    # CREATE TARGET
    target = gmp.create_target(
        name=f"Target_{customer_name}_{timestamp}",
        hosts=hosts,
        port_list_id=TCP_PORT_LIST_ID,
        alive_test="Consider Alive"
    )

    target_id = target.get("id")
    print(f"✅ Target created: {target_id}")

    # CREATE TASK
    task = gmp.create_task(
        name=f"Task_{customer_name}_{timestamp}",
        config_id=FULL_AND_FAST_CONFIG_ID,
        target_id=target_id,
        scanner_id=SCANNER_ID
    )

    task_id = task.get("id")
    print(f"✅ Task created: {task_id}")

    # START TASK
    gmp.start_task(task_id)
    print("▶️ Scan started")

    # WAIT
    while True:
        t = gmp.get_task(task_id)
        status = t.find("task/status").text

        print(f"⏳ Status: {status}")

        if status in ["Done", "Stopped", "Error"]:
            break

        time.sleep(10)

    # REPORT
    task = gmp.get_task(task_id)
    report_node = task.find("task/last_report/report")

    if report_node is None:
        print("❌ No report found")
        return

    report_id = report_node.get("id")
    print(f"📄 Report ID: {report_id}")

    reportPDF = gmp.get_report(
        report_id=report_id,
        report_format_id=REPORT_FORMAT_PDF,
        ignore_pagination=True,
        filter_string="levels=hmlog rows=-1 min_qod=0"
    )

    reportXML = gmp.get_report(
        report_id=report_id,
        report_format_id=REPORT_FORMAT_XML,
        filter_string="levels=hmlog rows=-1 min_qod=0"
    )

    content_PDF = reportPDF.find(".//report").text
    content_XML = etree.tostring(reportXML, encoding='unicode', pretty_print=True)

    os.makedirs("/app/reports", exist_ok=True)

    PDF_path = f"/app/reports/{customer_name}_{timestamp}.pdf"
    XML_path = f"/app/reports/{customer_name}_{timestamp}.xml"

    with open(PDF_path, "wb") as f:
        f.write(base64.b64decode(content_PDF))
    print(f"📄 Saved: {PDF_path}")


    with open(XML_path, "w", encoding="utf-8") as f:
        f.write(content_XML)
    print(f"📄 Saved: {XML_path}")

    send_email(customer_name, PDF_path)

# =========================
# EXTRACT IPS
# =========================
def extract_ips(hosts):
    """
    Returns ALL valid IPs found in hosts list.
    """

    if not hosts:
        return []

    if isinstance(hosts, str):
        hosts = [hosts]

    ips = []

    for h in hosts:
        if not h:
            continue

        match = re.search(r"\d+\.\d+\.\d+\.\d+", str(h))
        if match:
            ips.append(match.group(0))

    return ips

# =========================
# DAEMON
# =========================
def run_daemon():

    print("🤖 Master scan daemon started")

    while True:
        try:
            connection = TLSConnection(hostname=GVM_HOST, port=GVM_PORT)

            with Gmp(connection, transform=EtreeCheckCommandTransform()) as gmp:
                gmp.authenticate(GVM_USER, GVM_PASS)

                with open(CONFIG_PATH, "r") as f:
                    config = yaml.safe_load(f) or {}

                for sensor_name, hosts in config.items():

                    ips = extract_ips(hosts)

                    if not ips:
                        print(f"⚠️ No valid IPs for {sensor_name}")
                        continue

                    print(f"🚀 Scanning {sensor_name}: {ips}")

                    run_customer_scan(
                        gmp,
                        sensor_name,
                        ips
                    )

        except Exception as e:
            print(f"⚠️ Error: {e}")

        time.sleep(86400) #co 24h


if __name__ == "__main__":
    run_daemon()