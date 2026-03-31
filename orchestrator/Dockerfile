FROM python:3.9-slim

# Instalacja zależności systemowych (np. dla bibliotek sieciowych)
RUN apt-get update && apt-get install -y \
    gcc \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Kopiujemy listę bibliotek
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Kopiujemy skrypt demona
COPY scanner_daemon.py .
# Kopiujemy plik konfiguracyjny (można też podmontować jako wolumen)
COPY config.yaml .

# Folder na raporty przed wysyłką
RUN mkdir /app/reports

CMD ["python", "scanner_daemon.py"]
