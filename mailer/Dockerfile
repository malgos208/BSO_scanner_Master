FROM python:3.11-slim

# Ustawienie zmiennych środowiskowych, aby Python nie tworzył plików .pyc i logował na bieżąco
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY mailer_daemon.py .

# Uruchomienie skryptu
CMD ["python", "-u", "mailer_daemon.py"]