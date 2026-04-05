FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    gcc \
    libxml2-dev \
    libxslt-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner_daemon.py .

RUN mkdir /app/reports

CMD ["python", "-u", "scanner_daemon.py"]