# 📊 Syslog Collector with AI Analysis

Un système de collecte de syslog moderne qui utilise l'intelligence artificielle pour analyser et interpréter les messages de logs réseau en temps réel. Cette application recueille des messages syslog via UDP, les analyse avec LiteLLM (supportant plusieurs modèles comme Llama3, Phi3, Gemma, etc.), les stocke dans MongoDB, et fournit une interface web complète avec visualisation des analyses et synthèse vocale.

## ✨ Fonctionnalités

### Collecte et Traitement
- **📡 Collecte Syslog** : Écoute le port UDP standard 514 pour les messages syslog
- **🔄 Dédoublonnage intelligent** : Évite la duplication des logs identiques (même source + message) pendant 24h
- **⚡ Traitement par lots** : Analyse les logs par lots toutes les 5 minutes pour améliorer l'efficacité
- **🎯 Analyse manuelle** : Possibilité d'analyser un log individuellement via l'interface

### Analyse IA Multi-modèles
Différents modèles selon la sévérité du log :

| Sévérité | Modèle | Usage |
|----------|--------|-------|
| ℹ️ Info | `llama3:8b` | Analyse rapide pour événements normaux |
| ⚠️ Warning | `llama3:70b` | Analyse standard pour anomalies |
| 🔴 Critical | `deepseek` | Analyse approfondie pour incidents critiques |

### Stockage
- **💾 MongoDB** : Stockage persistant avec indexation optimisée
- **🔑 Index unique** : Hash SHA256 (source + message) pour dédoublonnage
- **📊 Index performants** : timestamp, analyzed, source, classification

### Interface Web
- **📋 Vue des logs bruts** : Affichage temps réel avec filtres avancés
- **📈 Vue d'analyse** : Graphiques interactifs (camembert, barres d'analyse)
- **🎤 Synthèse vocale** : Lecture audio des descriptions et résolutions
- **📱 Modal de détails** : Affichage complet des analyses
- **🌓 Mode clair/sombre** : Thème persistant
- **📤 Export CSV** : Export des logs au format CSV

### API REST
- **🔍 Logs** : Récupération, filtrage, export
- **📊 Analyses** : Logs analysés avec filtres multiples
- **📈 Statistiques** : Volumétrie, distribution, sources
- **🤖 Modèles** : Liste des modèles disponibles
- **🎯 Analyse manuelle** : Endpoint dédié

### Temps Réel
- **🔌 WebSockets** : Mises à jour instantanées (`log_message`, `log_updated`)
- **📡 UDP Server** : Réception syslog en continu

## 📋 Prérequis

- Node.js 18.x ou supérieur
- MongoDB 4.x ou supérieur
- Serveur LiteLLM accessible (supportant l'API OpenAI)

## 🚀 Installation

### 1. Cloner le dépôt

```bash
git clone https://github.com/yourusername/syslog-collector.git
cd syslog-collector