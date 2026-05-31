# 📊 Syslog Collector with AI Analysis

Un système de collecte de syslog moderne qui utilise l'intelligence artificielle pour analyser et interpréter les messages de logs réseau en temps réel. Cette application recueille des messages syslog via UDP, les analyse avec LiteLLM (supportant plusieurs modèles comme Llama3, Phi3, Gemma, etc.), les stocke dans MongoDB, et fournit une interface web complète avec visualisation des analyses et synthèse vocale.

## ✨ Fonctionnalités

### Collecte et Traitement
- **📡 Collecte Syslog** : Écoute le port UDP standard 514 pour les messages syslog
- **🔄 Dédoublonnage intelligent** : Évite la duplication des logs identiques (même source + message normalisé) pendant 24h avec normalisation avancée (remplacement IPs, IDs, nombres)
- **⚡ Traitement par lots** : Analyse les logs par lots de 20 toutes les 5 minutes pour améliorer l'efficacité
- **🎯 Analyse manuelle** : Possibilité d'analyser un log individuellement via l'interface avec modèle adapté à la sévérité
- **🗑️ Rotation automatique des logs** : Politique de rétention configurable (7j non analysés, 30j info, 90j warning, 365j critical)

### Analyse IA Multi-modèles
Différents modèles selon la sévérité du log :

| Sévérité | Modèle | Usage |
|----------|--------|-------|
| ℹ️ Info | `llama3:8b` | Analyse rapide pour événements normaux |
| ⚠️ Warning | `llama3:70b` | Analyse standard pour anomalies |
| 🔴 Critical | `gemma` | Analyse approfondie pour incidents critiques |

### Stockage
- **💾 MongoDB** : Stockage persistant avec indexation optimisée
- **🔑 Index unique** : Hash SHA256 (source + message normalisé) pour dédoublonnage
- **📊 Index performants** : timestamp, analyzed, source, classification

### Interface Web - Logs Bruts (`/`)
- **📋 Vue temps réel** : Affichage des logs bruts avec WebSocket
- **🔍 Filtres avancés** : Période, sévérité, source, recherche texte
- **📊 Graphiques** : Camembert de distribution, histogramme de volume
- **🎯 Analyse manuelle** : Bouton "Analyse" par log avec feedback visuel
- **📤 Export CSV** : Export des logs au format CSV
- **🌓 Mode clair/sombre** : Thème persistant
- **🔄 Onglets** : Live Stream / Historical

### Interface Web - Analyse (`/analysis`)
- **📈 Vue analyse** : Logs analysés avec métadonnées IA
- **🎤 Synthèse vocale** : Lecture audio des descriptions et résolutions (Web Speech API)
- **📱 Modal de détails** : Affichage complet des analyses avec description et résolution
- **🏷️ Badges** : Sévérité, profondeur d'analyse, modèle utilisé, catégorie
- **🔍 Filtres temps réel** : Période, sévérité, recherche texte
- **📊 Graphiques** : Distribution des sévérités, barres de profondeur d'analyse

### API REST
- **🔍 Logs** : `GET /api/logs`, `GET /api/logs/sources`, `GET /api/logs/export`
- **📊 Analyses** : `GET /api/analysis`, `POST /api/analyse-log`
- **📈 Statistiques** : `GET /api/stats`, `GET /api/stats/volume`
- **🤖 Modèles** : `GET /api/models` (liste des modèles disponibles)
- **🎯 Batch** : `POST /api/run-analysis` (déclenchement manuel)

### Temps Réel
- **🔌 WebSockets** : Mises à jour instantanées (`log_message`, `log_updated`)
- **📡 UDP Server** : Réception syslog en continu avec dédoublonnage

## 📋 Prérequis

- Node.js 18.x ou supérieur
- MongoDB 4.x ou supérieur
- Serveur LiteLLM accessible (supportant l'API OpenAI)

## 🚀 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/yourusername/syslog-collector.git
cd syslog-collector
