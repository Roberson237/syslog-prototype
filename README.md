# Collecteur Syslog avec Analyse IA

Un système de collecte de syslog moderne qui utilise l’intelligence artificielle pour analyser et interpréter les messages de logs réseau en temps réel. Cette application recueille des messages syslog via UDP, les traite avec la plateforme GROQ, les stocke dans MongoDB, et fournit une interface web pour afficher et rechercher les logs.

## Fonctionnalités

- **Collecte Syslog** : Écoute le port UDP standard 514 pour les messages syslog
- **Analyse IA** : Utilise le modèle Mistral via GROQ pour analyser et interpréter les messages de logs
- **Traitement par lots** : Analyse les logs par lots toutes les 5 minutes pour améliorer l’efficacité
- **Stockage persistant** : Enregistre tous les logs et leurs analyses dans MongoDB
- **Mises à jour en temps réel** : Utilise WebSockets pour envoyer des mises à jour aux clients connectés
- **Interface Web** : Fournit une interface utilisateur claire et simple pour visualiser les logs
- **API REST** : Offre des endpoints pour accéder aux logs de manière programmée
- **Filtres** : Permet de filtrer les logs par source, contenu et période

## Prérequis

- Node.js 14.x ou supérieur
- MongoDB 4.x ou supérieur
- Serveur GROQ accessible localement ou sur un hôte réseau

## Installation

1. Clonez le dépôt :
   ```bash
   git clone https://github.com/yourusername/syslog-scollector.git
   cd syslog-collector
   ```

2. Installez les dépendances :
   ```bash
   npm install
   ```

3. Créez un fichier `.env` avec votre configuration (optionnel) :
   ```bash
   MONGODB_URI=mongodb://localhost:27017/syslog
   GROQ_API_URL=http://localhost:11434
   STARTUP_DELAY=5
   GROQ_API_KEY=your_groq_api_key_here
   ```

4. Vérifiez que le dossier `public` contient bien vos fichiers frontend (HTML, CSS, JS).

## Utilisation

### Démarrage du serveur

```bash
# Démarrer avec la configuration par défaut
npm start

# Ou avec des variables d’environnement personnalisées
MONGODB_URI=mongodb://localhost:27017/syslog GROQ_API_URL=http://localhost:11434 GROQ_API_KEY=your_groq_api_key_here npm start
```

Le serveur va :
- Commencer à écouter les messages syslog sur le port UDP 514
- Se connecter à MongoDB avec une logique de reconnexion automatique
- Commencer à traiter et analyser les logs
- Servir l’interface web sur le port 3000

### Exécution avec Docker

```bash
docker build -t syslog-collector .
docker run -p 3000:3000 -p 514:514/udp --env MONGODB_URI=mongodb://mongo:27017/syslog --env 
```

### Envoi de logs de test

Vous pouvez envoyer des logs de test via l’API :

```bash
curl -X POST http://localhost:3000/api/test-log
```

Ou envoyer des messages syslog standard sur le port UDP 514 :

```bash
logger -n localhost -P 514 "Test syslog message from logger utility"
```

## Configuration

L’application peut être configurée via des variables d’environnement :

| Variable | Description | Valeur par défaut |
|----------|-------------|-------------------|
| `MONGODB_URI` | Chaîne de connexion MongoDB | `mongodb://localhost:27017/syslog` |
| `GROQ_API_URL` | URL du serveur GROQ | `http://localhost:11434` |
| `STARTUP_DELAY` | Délai en secondes avant la connexion à MongoDB | `0` |
| `GROQ_API_KEY` | Clé API GROQ | Aucun |

## Endpoints API

- `GET /api/logs?limit=100` : Récupère les logs les plus récents (optionnellement limité)
- `GET /api/analysis?hours=24&source=&analysis=` : Récupère l’analyse filtrée des logs
- `POST /api/test-log` : Génère une entrée de log de test

## Interface Web

L’interface web est accessible à http://localhost:3000 et offre :

- Affichage des logs en temps réel avec mises à jour automatiques
- Vue détaillée des analyses de logs
- Options de filtrage par source et contenu
- Filtrage par période

## Architecture

L’application se compose de plusieurs éléments clés :

1. **Serveur UDP** : Reçoit les messages syslog sur le port 514
2. **Intégration MongoDB** : Stocke les logs et les analyses de manière persistante
3. **Client API GROQ** : Envoie les logs au modèle IA pour analyse
4. **Serveur WebSocket** : Fournit les mises à jour en temps réel aux clients connectés
5. **Serveur Express** : Sert l’interface web et les endpoints API
6. **Traitement par lots** : Analyse les logs par lots toutes les 5 minutes

## Analyse des logs

Les logs sont analysés par lots toutes les 5 minutes avec le modèle Mistral via GROQ. Cette méthode :
- Réduit la charge sur l’API par rapport à une analyse individuelle par message
- Améliore l’efficacité en cas de grand volume de logs
- Garantit que tous les logs sont analysés même en cas de pic de trafic

## Contribution

Les contributions sont les bienvenues ! N’hésitez pas à soumettre une Pull Request.

## Licence

Ce projet est sous licence MIT - voir le fichier LICENSE pour les détails.
