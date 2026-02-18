FROM python:3.12-slim

#Empêche Python de créer des .pyc et force l'affichage des logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

#Copier le projet dans /app
WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

#Copie tout le repo (donc /app/app/app.py existe)
COPY . .

#Se placer dans le dossier contenant app.py + instance/
WORKDIR /app/app

#S'assurer que le dossier existe
RUN mkdir -p instance

RUN useradd -m -u 10001 non-root \
  && chown -R non-root:non-root /app

USER non-root

ENV PYTHONPATH=/app

EXPOSE 8080
CMD ["gunicorn", "-b", "0.0.0.0:8080", "--workers", "2", "wsgi:app"]

