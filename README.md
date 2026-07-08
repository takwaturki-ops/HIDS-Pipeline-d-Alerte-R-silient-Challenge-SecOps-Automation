# HIDS Pipeline d’Alerte – SecOps Automation

Ce projet déploie une stack locale de détection/automatisation avec **Docker Compose** :

- **n8n** : orchestration des workflows d’alerte
- **secops_agent** : agent de surveillance (Flask + scheduler)
- **Mailpit** : boîte mail de test locale (SMTP + UI web)

---

## 📦 Architecture

- `n8n_automation` (port `5678`)  
  Reçoit les alertes via webhook et déclenche les automatisations.

- `secops_agent` (port `8000`)  
  Surveille un fichier sensible, garde un état local, et envoie des alertes à n8n.

- `mailpit` (ports `8025` et `1025`)  
  Permet de tester l’envoi/réception d’emails sans utiliser un SMTP externe.

Tous les services communiquent via le réseau Docker `hids_net`.

---

## ✅ Prérequis

- Docker
- Docker Compose (plugin `docker compose`)
- Git

Vérification rapide :

```bash
docker --version
docker compose version
git --version
```

---

## 🚀 Lancement rapide

Depuis la racine du projet (où se trouve `docker-compose.yml`) :

```bash
docker compose up -d
```

Vérifier l’état :

```bash
docker compose ps
```

---

## 🌐 Accès aux services

- n8n : http://localhost:5678
 https://wooing-twisted-singing.ngrok-free.dev/workflow/nJi08eQX7BIM2pBs
- secops_agent : http://localhost:8000
- Mailpit UI : http://localhost:8025
- Mailpit SMTP : `localhost:1025`

---

## 🧩 Variables importantes

### n8n
- `N8N_HOST=localhost`
- `N8N_PORT=5678`
- `N8N_PROTOCOL=http`
- `WEBHOOK_URL=http://localhost:5678/`
- `GENERIC_TIMEZONE=Europe/Paris`
- `N8N_BASIC_AUTH_ACTIVE=true`
- `N8N_BASIC_AUTH_USER=admin`
- `N8N_BASIC_AUTH_PASSWORD=...` ⚠️ à changer

### secops_agent
- `WATCHED_FILE=/data/sensitive_config.txt`
- `STATE_DIR=/data/state`
- `N8N_ALERT_WEBHOOK=http://n8n_automation:5678/webhook/hids-alert`
- `CRON_HOUR=2`
- `CRON_MINUTE=0`
- `FLASK_PORT=8000`
- `TZ=Europe/Paris`

---

## 💾 Persistance des données

Volumes Docker utilisés :

- `n8n_data` → données n8n
- `agent_data` → état/fichiers de l’agent

Lister les volumes :

```bash
docker volume ls
```

---

## 🛠️ Commandes utiles

### Voir les logs
```bash
docker compose logs -f
```

### Logs d’un service précis
```bash
docker compose logs -f n8n_automation
docker compose logs -f secops_agent
docker compose logs -f mailpit
```

### Arrêter la stack
```bash
docker compose down
```

### Arrêter + supprimer volumes (⚠️ perte de données locales)
```bash
docker compose down -v
```

---

## 🔐 Sécurité (recommandé)

Ne laissez pas les secrets en dur dans `docker-compose.yml`.

### Option recommandée : fichier `.env`

Exemple `.env` :

```env
N8N_BASIC_AUTH_USER=admin
N8N_BASIC_AUTH_PASSWORD=change_me_now
GENERIC_TIMEZONE=Europe/Paris
TZ=Europe/Paris
```

Puis dans `docker-compose.yml`, utilisez `${VARIABLE}`.

Ajoutez aussi `.env` dans `.gitignore` si nécessaire.

---

## 🧪 Test fonctionnel rapide

1. Démarrer la stack : `docker compose up -d`
2. Ouvrir n8n : http://localhost:5678
3. Ouvrir Mailpit : http://localhost:8025
4. Vérifier que `secops_agent` répond sur le port 8000
5. Déclencher un événement dans l’agent et confirmer la réception webhook côté n8n

---

## 🧯 Dépannage

### Port déjà utilisé
Erreur type “port is already allocated” :
- changer le port host dans `docker-compose.yml`
- ou arrêter le process qui utilise le port

### Un service redémarre en boucle
```bash
docker compose logs -f <service_name>
```
Vérifier variables d’environnement, dépendances, et fichiers montés.

### n8n inaccessible
- vérifier `docker compose ps`
- vérifier logs n8n
- tester `http://localhost:5678`

---

## 📁 Structure minimale attendue

```text
.
├── docker-compose.yml
├── README.md
└── agent/
    ├── Dockerfile
    └── ... (code de l’agent)
```

---

## 👤 Auteur

Projet maintenu par `takwaturki-ops`.
