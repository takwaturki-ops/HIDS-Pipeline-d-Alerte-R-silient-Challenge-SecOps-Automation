FROM python:3.12-slim

LABEL maintainer="secops-challenge"
LABEL description="Agent HIDS leger - surveillance temps reel + API + planification"

WORKDIR /app

# Dépendances système minimales (inotify fonctionne en user-space standard,
# aucun privilège root étendu n'est nécessaire)
RUN apt-get update \
    && apt-get install -y --no-install-recommends coreutils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY hids_agent.py .

# Le fichier surveillé et l'état persistant vivent dans /data (volume nommé)
RUN mkdir -p /data/state

EXPOSE 8000

CMD ["python", "-u", "hids_agent.py"]

