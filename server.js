import 'dotenv/config';
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import dgram from 'dgram';
import path from 'path';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';
import crypto from 'crypto';
import { setTimeout } from 'timers/promises';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ─── Schéma MongoDB ────────────────────────────────────────────────────────────
const logSchema = new mongoose.Schema({
    timestamp:      { type: Date, default: Date.now },
    source:         String,
    message:        String,
    facility:       { type: Number, default: 0 },
    severity:       { type: Number, default: 6 },
    rawMessage:     String,
    analyzed:       { type: Boolean, default: false },
    classification: { type: String, enum: ['info', 'warning', 'critical'], default: null },
    description:    { type: String, default: null },
    resolution:     { type: String, default: null },
    uniqueHash:     { type: String, unique: true, sparse: true }
}, { timestamps: true });

// Index pour les performances
logSchema.index({ timestamp: -1 });
logSchema.index({ analyzed: 1 });
logSchema.index({ source: 1 });
logSchema.index({ classification: 1 });

const Log = mongoose.model('Log', logSchema);

// ─── Configuration ─────────────────────────────────────────────────────────────
const MONGODB_URI     = process.env.MONGODB_URI     || 'mongodb://localhost:27017/syslog';
const LITELLM_URL     = process.env.LITELLM_URL     || '';
const LITELLM_API_KEY = process.env.LITELLM_API_KEY || '';
const LITELLM_MODEL   = process.env.LITELLM_MODEL   || 'llama3:8b';
const SYSLOG_PORT     = parseInt(process.env.SYSLOG_PORT || '514');
const MAX_RETRIES     = 5;
const RETRY_INTERVAL  = 5000;
const STARTUP_DELAY   = parseInt(process.env.STARTUP_DELAY || '0', 10) * 1000;
const BATCH_LIMIT     = 20;

// Configuration de la rotation des logs (en jours)
const LOG_RETENTION = {
    unanalyzed: 7,
    info: 30,
    warning: 90,
    critical: 365
};

// ─── MODÈLES CONFIGURABLES VIA .env ────────────────────────────────────────────
const MODEL_INFO     = process.env.INFO_MODEL     || 'llama3:8b';
const MODEL_WARNING  = process.env.WARNING_MODEL  || 'phi3:mini';
const MODEL_CRITICAL = process.env.CRITICAL_MODEL || 'gemma4:26b';

const MODEL_BY_SEV = {
    info: MODEL_INFO,
    warning: MODEL_WARNING,
    critical: MODEL_CRITICAL
};

console.log(`📡 LiteLLM URL   : ${LITELLM_URL}`);
console.log(`🤖 Modèle par défaut : ${LITELLM_MODEL}`);
console.log(`📋 Modèle INFO    : ${MODEL_INFO}`);
console.log(`⚠️ Modèle WARNING : ${MODEL_WARNING}`);
console.log(`🔴 Modèle CRITICAL: ${MODEL_CRITICAL}`);
console.log(`🗄️ MongoDB URI   : ${MONGODB_URI}`);

// ─── Fonction pour générer un hash unique ──────────────────────────────────────
function generateUniqueHash(source, message) {
    let normalizedMessage = message.trim().toLowerCase()
        .replace(/\s+/g, ' ')
        .replace(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, 'IP_ADDR')
        .replace(/[0-9a-f]{8,}/g, 'HEX_ID')
        .replace(/\d+/g, 'NUM');
    
    const normalizedSource = source.trim().toLowerCase();
    const content = `${normalizedSource}|${normalizedMessage}`;
    return crypto.createHash('sha256').update(content).digest('hex');
}

// ─── Rotation automatique des logs ────────────────────────────────────────────
async function rotateLogs() {
    try {
        const now = new Date();
        let deletedCount = 0;
        
        const unanalyzedCutoff = new Date(now - LOG_RETENTION.unanalyzed * 24 * 3600000);
        const result1 = await Log.deleteMany({ analyzed: false, timestamp: { $lt: unanalyzedCutoff } });
        deletedCount += result1.deletedCount;
        
        const infoCutoff = new Date(now - LOG_RETENTION.info * 24 * 3600000);
        const result2 = await Log.deleteMany({ classification: 'info', timestamp: { $lt: infoCutoff } });
        deletedCount += result2.deletedCount;
        
        const warningCutoff = new Date(now - LOG_RETENTION.warning * 24 * 3600000);
        const result3 = await Log.deleteMany({ classification: 'warning', timestamp: { $lt: warningCutoff } });
        deletedCount += result3.deletedCount;
        
        const criticalCutoff = new Date(now - LOG_RETENTION.critical * 24 * 3600000);
        const result4 = await Log.deleteMany({ classification: 'critical', timestamp: { $lt: criticalCutoff } });
        deletedCount += result4.deletedCount;
        
        if (deletedCount > 0) {
            console.log(`🔄 Rotation des logs : ${deletedCount} logs supprimés`);
        }
    } catch (err) {
        console.error('❌ Erreur rotation logs:', err.message);
    }
}

// ─── Connexion MongoDB ─────────────────────────────────────────────────────────
async function connectWithRetry(retries = MAX_RETRIES) {
    try {
        console.log('🔌 Connexion à MongoDB...');
        await mongoose.connect(MONGODB_URI);
        console.log('✅ MongoDB connecté');
        
        try {
            await Log.collection.createIndex({ uniqueHash: 1 }, { unique: true, sparse: true });
            console.log('✅ Index unique sur uniqueHash créé');
        } catch (indexErr) {
            if (indexErr.code === 11000) {
                console.log('⚠️ Des doublons existent, nettoyage recommandé');
            } else {
                console.log('ℹ️ Index uniqueHash existe déjà');
            }
        }
        
        const count = await Log.countDocuments();
        console.log(`📊 Logs en base : ${count}`);
    } catch (err) {
        console.error('❌ Erreur MongoDB :', err.message);
        if (retries > 0) {
            console.log(`🔄 Nouvelle tentative dans ${RETRY_INTERVAL / 1000}s...`);
            await setTimeout(RETRY_INTERVAL);
            await connectWithRetry(retries - 1);
        } else {
            console.error('💀 Impossible de se connecter à MongoDB. Arrêt.');
            process.exit(1);
        }
    }
}

// ─── Appel LiteLLM ─────────────────────────────────────────────────────────────
async function callLiteLLM(prompt, model = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (LITELLM_API_KEY) headers['Authorization'] = `Bearer ${LITELLM_API_KEY}`;

    const response = await fetch(`${LITELLM_URL}/chat/completions`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
            model: model || LITELLM_MODEL,
            messages: [{ role: 'user', content: prompt }],
            max_tokens: 3000,
            temperature: 0.1
        })
    });

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`LiteLLM HTTP ${response.status}: ${errorText}`);
    }

    const data = await response.json();
    return data.choices[0].message.content;
}

// ─── Prompts IA avec fallback pour les résolutions ─────────────────────────────
function buildBatchPrompt(logs) {
    const lines = logs.map((l, i) => `${i + 1}. [${l.source}] ${l.message}`).join('\n');
    return `You are a cybersecurity expert. Analyze each syslog message.

IMPORTANT: For "warning" and "critical" messages, you MUST provide a specific, actionable resolution.
"info" messages should have null for both description and resolution.

Return ONLY valid JSON array. Example:
[
  {"index":1,"classification":"critical","description":"SSH brute force attack detected","resolution":"Block IP 185.220.101.45 using: sudo iptables -A INPUT -s 185.220.101.45 -j DROP"},
  {"index":2,"classification":"warning","description":"High CPU usage","resolution":"Check processes with 'top' and restart service if needed"},
  {"index":3,"classification":"info","description":null,"resolution":null}
]

Logs to analyze:
${lines}

Return ONLY the JSON array, no other text.`;

}

function buildManualPrompt(log, sev) {
    const base = `[${log.source}] ${log.message}`;
    
    if (sev === 'info') {
        return `Analyze this INFO syslog entry. Reply ONLY with JSON: {"classification":"info","description":"summary","resolution":null}\n\nLog: ${base}`;
    }
    if (sev === 'warning') {
        return `Analyze this WARNING syslog entry. You MUST provide an actionable resolution. Reply ONLY with JSON: {"classification":"warning","description":"what is the issue","resolution":"specific command or action to fix"}\n\nLog: ${base}`;
    }
    if (sev === 'critical') {
        return `Analyze this CRITICAL syslog entry deeply. You MUST provide step-by-step remediation. Reply ONLY with JSON: {"classification":"critical","description":"root cause","resolution":"step-by-step remediation actions"}\n\nLog: ${base}`;
    }
    return `Analyze this syslog entry. Reply ONLY with JSON: {"classification":"info|warning|critical","description":"...","resolution":"..."}\n\nLog: ${base}`;
}

// ─── Génération de résolution par défaut (fallback) ───────────────────────────
function generateDefaultResolution(message, classification) {
    const msg = message.toLowerCase();
    
    const resolutions = {
        'ssh': "Bloquer l'IP source: sudo iptables -A INPUT -s IP -j DROP && sudo fail2ban-client status sshd",
        'brute': "Bloquer l'IP source et activer fail2ban: sudo fail2ban-client set sshd banip IP",
        'port scan': "Configurer fail2ban ou un IDS: sudo apt install fail2ban && sudo systemctl enable fail2ban",
        'cpu': "Identifier le processus: top -b -n 1 | head -20 && killall -9 PROCESSUS ou redémarrer le service",
        'disk': "Nettoyer l'espace: sudo du -sh /* | sort -h && sudo journalctl --vacuum-size=500M",
        'memory': "Vérifier la mémoire: free -h && sudo systemctl restart service_consommant",
        'vpn': "Vérifier les logs VPN: tail -f /var/log/openvpn.log et vérifier les certificats",
        'sql': "Mettre à jour l'application avec des requêtes paramétrées (PDO/prepared statements)",
        'injection': "Audit de sécurité immédiat et activation d'un WAF: sudo apt install modsecurity",
        'ddos': "Activer rate limiting: iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute -j ACCEPT",
        'interface down': "Remonter l'interface: sudo ip link set eth0 up && sudo systemctl restart networking",
        'slow query': "Optimiser la base: EXPLAIN ANALYZE SELECT...; CREATE INDEX idx_nom ON table(colonnes)",
        'acl denied': "Vérifier les règles ACL: iptables -L -n -v | grep DROP && ajuster les règles",
        'failed login': "Vérifier /var/log/auth.log et ajouter une règle fail2ban pour root",
        'default': classification === 'critical' 
            ? "Investigation immédiate requise. Vérifier les logs système dans /var/log/ et analyser les processus actifs."
            : "Surveiller la situation. Analyser les tendances sur 1 heure et documenter l'incident."
    };
    
    for (const [key, resolution] of Object.entries(resolutions)) {
        if (msg.includes(key)) {
            return resolution;
        }
    }
    return resolutions.default;
}

// ─── Parsers avec fallback ─────────────────────────────────────────────────────
function parseBatchResponse(raw, originalLogs) {
    let cleaned = raw.replace(/```json|```/g, '').trim();
    const start = cleaned.indexOf('[');
    const end = cleaned.lastIndexOf(']');
    if (start !== -1 && end !== -1) cleaned = cleaned.slice(start, end + 1);
    cleaned = cleaned.replace(/,\s*}/g, '}').replace(/,\s*\]/g, ']');
    
    let parsed;
    try {
        parsed = JSON.parse(cleaned);
    } catch (e) {
        console.error('❌ JSON parsing error, using fallback');
        // Fallback : créer des analyses par défaut
        return originalLogs.map((log, idx) => ({
            index: idx + 1,
            classification: log.message.toLowerCase().includes('brute') || log.message.toLowerCase().includes('critical') ? 'critical' : 'info',
            description: `Log: ${log.message.substring(0, 100)}`,
            resolution: log.message.toLowerCase().includes('brute') || log.message.toLowerCase().includes('critical') 
                ? generateDefaultResolution(log.message, 'critical') 
                : null
        }));
    }
    
    return parsed.map(item => {
        const log = originalLogs[item.index - 1];
        const classification = item.classification;
        let resolution = item.resolution;
        let description = item.description;
        
        // Si classification est warning/critical et resolution est null/absent, générer une résolution par défaut
        if (classification && classification !== 'info' && (!resolution || resolution === 'null' || resolution === null)) {
            resolution = generateDefaultResolution(log?.message || '', classification);
            console.log(`🔧 Fallback: Résolution générée pour ${classification} - ${log?.message?.substring(0, 50)}`);
        }
        
        // Si description est null pour warning/critical, ajouter une description par défaut
        if (classification && classification !== 'info' && (!description || description === 'null')) {
            description = `Anomalie détectée: ${log?.message?.substring(0, 100)}`;
        }
        
        return {
            index: item.index,
            classification: ['info', 'warning', 'critical'].includes(classification) ? classification : 'info',
            description: description || null,
            resolution: resolution || null
        };
    });
}

function parseManualResponse(raw, originalLog) {
    let cleaned = raw.replace(/```json|```/g, '').trim();
    const start = cleaned.indexOf('{');
    const end = cleaned.lastIndexOf('}');
    if (start !== -1 && end !== -1) cleaned = cleaned.slice(start, end + 1);
    
    let parsed;
    try {
        parsed = JSON.parse(cleaned);
    } catch (e) {
        console.error('❌ Manual parsing error, using fallback');
        const classification = originalLog.message.toLowerCase().includes('brute') ? 'critical' : 'info';
        return {
            classification: classification,
            description: `Log: ${originalLog.message.substring(0, 100)}`,
            resolution: classification !== 'info' ? generateDefaultResolution(originalLog.message, classification) : null
        };
    }
    
    const classification = parsed.classification;
    let resolution = parsed.resolution;
    let description = parsed.description;
    
    // Fallback pour résolution manquante
    if (classification && classification !== 'info' && (!resolution || resolution === 'null' || resolution === null)) {
        resolution = generateDefaultResolution(originalLog.message, classification);
        console.log(`🔧 Fallback manuel: Résolution générée pour ${classification}`);
    }
    
    return {
        classification: ['info', 'warning', 'critical'].includes(classification) ? classification : 'info',
        description: description || null,
        resolution: resolution || null
    };
}

// ─── Batch Processor ───────────────────────────────────────────────────────────
let isAnalysisRunning = false;

async function processBatchAnalysis() {
    if (isAnalysisRunning) {
        console.log('⏳ Batch déjà en cours...');
        return;
    }
    isAnalysisRunning = true;
    
    try {
        const logs = await Log.find({ analyzed: false }).sort({ timestamp: 1 }).limit(BATCH_LIMIT);
        if (logs.length === 0) {
            console.log('📭 Batch : aucun log en attente.');
            return;
        }

        console.log(`🔍 Batch : analyse de ${logs.length} logs avec ${LITELLM_MODEL}...`);
        const prompt = buildBatchPrompt(logs);
        const rawResponse = await callLiteLLM(prompt);

        let results;
        try {
            results = parseBatchResponse(rawResponse, logs);
        } catch (parseErr) {
            console.error('❌ Réponse IA non parseable, utilisation du fallback');
            // Fallback complet
            results = logs.map((log, idx) => ({
                index: idx + 1,
                classification: log.message.toLowerCase().includes('brute') || log.message.toLowerCase().includes('critical') ? 'critical' : 
                               (log.message.toLowerCase().includes('warning') ? 'warning' : 'info'),
                description: `Analyse automatique: ${log.message.substring(0, 150)}`,
                resolution: generateDefaultResolution(log.message, 'warning')
            }));
        }

        let updatedCount = 0;
        for (const result of results) {
            const log = logs[result.index - 1];
            if (!log) continue;
            
            await Log.findByIdAndUpdate(log._id, {
                $set: {
                    analyzed: true,
                    classification: result.classification,
                    description: result.description,
                    resolution: result.resolution
                }
            });
            updatedCount++;
        }
        
        console.log(`✅ Batch terminé : ${updatedCount}/${logs.length} logs analysés.`);
        
        const updatedLogs = await Log.find({ _id: { $in: logs.slice(0, updatedCount).map(l => l._id) } }).lean();
        updatedLogs.forEach(log => io.emit('log_updated', log));
        
    } catch (err) {
        console.error('❌ Erreur batch :', err.message);
    } finally {
        isAnalysisRunning = false;
    }
}

// ─── Parser Syslog UDP ─────────────────────────────────────────────────────────
function parseSyslog(msg, remoteAddress) {
    const raw = msg.toString();
    const match = raw.match(/^<(\d+)>(.*)/);
    if (match) {
        const priority = parseInt(match[1]);
        return {
            source: remoteAddress,
            facility: Math.floor(priority / 8),
            severity: priority % 8,
            message: match[2].trim(),
            rawMessage: raw
        };
    }
    return {
        source: remoteAddress,
        facility: 0,
        severity: 6,
        message: raw.trim(),
        rawMessage: raw
    };
}

function severityLabel(n) {
    const labels = ['emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'];
    return labels[n] || 'unknown';
}

// ─── Express + Socket.IO ───────────────────────────────────────────────────────
const app = express();
const http = createServer(app);
const io = new Server(http, {
    cors: { origin: '*', methods: ['GET', 'POST'], credentials: true },
    transports: ['websocket', 'polling']
});

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});
app.use(express.json());

const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));
app.use('/socket.io', express.static(path.join(__dirname, 'node_modules/socket.io/client-dist')));

// ─── Routes API ────────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
app.get('/analysis', (req, res) => res.sendFile(path.join(publicPath, 'analysis.html')));

// Analyse manuelle
app.post('/api/analyse-log', async (req, res) => {
    try {
        const { logId } = req.body;
        if (!logId) return res.status(400).json({ error: 'logId requis' });
        
        const log = await Log.findById(logId);
        if (!log) return res.status(404).json({ error: 'Log introuvable' });
        
        const sev = log.classification || '';
        const model = MODEL_BY_SEV[sev] || LITELLM_MODEL;
        
        console.log(`🔍 Analyse manuelle log ${logId} — sévérité: ${sev || 'inconnue'} — modèle: ${model}`);
        
        const prompt = buildManualPrompt(log, sev);
        let rawResponse;
        try {
            rawResponse = await callLiteLLM(prompt, model);
        } catch (err) {
            console.error('❌ Erreur appel IA, utilisation fallback:', err.message);
            const fallbackResult = {
                classification: log.message.toLowerCase().includes('brute') ? 'critical' : 'info',
                description: `Analyse automatique: ${log.message.substring(0, 150)}`,
                resolution: generateDefaultResolution(log.message, 'warning')
            };
            const updated = await Log.findByIdAndUpdate(logId, {
                $set: {
                    analyzed: true,
                    classification: fallbackResult.classification,
                    description: fallbackResult.description,
                    resolution: fallbackResult.resolution
                }
            }, { new: true });
            if (updated) io.emit('log_updated', updated.toObject());
            return res.json({
                _id: updated._id,
                classification: fallbackResult.classification,
                description: fallbackResult.description,
                resolution: fallbackResult.resolution,
                model: 'fallback'
            });
        }
        
        let result;
        try {
            result = parseManualResponse(rawResponse, log);
        } catch (parseErr) {
            console.error('❌ Réponse IA non parseable, utilisation fallback:', rawResponse);
            result = {
                classification: log.message.toLowerCase().includes('brute') ? 'critical' : 'info',
                description: `Analyse automatique: ${log.message.substring(0, 150)}`,
                resolution: generateDefaultResolution(log.message, 'warning')
            };
        }
        
        const updated = await Log.findByIdAndUpdate(logId, {
            $set: {
                analyzed: true,
                classification: result.classification,
                description: result.description,
                resolution: result.resolution
            }
        }, { new: true });
        
        if (updated) io.emit('log_updated', updated.toObject());
        
        res.json({
            _id: updated._id,
            classification: result.classification,
            description: result.description,
            resolution: result.resolution,
            model: model
        });
    } catch (err) {
        console.error('❌ Erreur analyse manuelle:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// Modèles disponibles
app.get('/api/models', async (req, res) => {
    res.json({ 
        models: [MODEL_INFO, MODEL_WARNING, MODEL_CRITICAL, LITELLM_MODEL],
        default: LITELLM_MODEL,
        by_severity: {
            info: MODEL_INFO,
            warning: MODEL_WARNING,
            critical: MODEL_CRITICAL
        }
    });
});

// Logs avec filtres
app.get('/api/logs', async (req, res) => {
    try {
        const limit = parseInt(req.query.limit) || 200;
        const hours = parseInt(req.query.hours) || 24;
        const severity = req.query.severity || '';
        const source = req.query.source || '';
        const search = req.query.search || '';
        const threshold = new Date(Date.now() - hours * 3600000);

        const query = { timestamp: { $gte: threshold } };
        if (source) query.source = { $regex: source, $options: 'i' };
        if (search) query.message = { $regex: search, $options: 'i' };
        if (severity && severity !== 'All' && ['info', 'warning', 'critical'].includes(severity.toLowerCase())) {
            query.classification = severity.toLowerCase();
        }

        const logs = await Log.find(query).sort({ timestamp: -1 }).limit(limit).lean();
        res.json(logs);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Sources uniques
app.get('/api/logs/sources', async (req, res) => {
    try {
        const sources = await Log.distinct('source');
        res.json(sources);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Export CSV
app.get('/api/logs/export', async (req, res) => {
    try {
        const hours = parseInt(req.query.hours) || 24;
        const threshold = new Date(Date.now() - hours * 3600000);
        const logs = await Log.find({ timestamp: { $gte: threshold } }).sort({ timestamp: -1 }).lean();

        const header = 'Time,Source,Severity,Classification,Message,Description,Resolution\n';
        const rows = logs.map(l => [
            new Date(l.timestamp).toISOString(),
            `"${l.source || ''}"`,
            severityLabel(l.severity),
            l.classification || 'pending',
            `"${(l.message || '').replace(/"/g, '""')}"`,
            `"${(l.description || '').replace(/"/g, '""')}"`,
            `"${(l.resolution || '').replace(/"/g, '""')}"`
        ].join(',')).join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="syslog-export.csv"');
        res.send(header + rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Logs analysés
app.get('/api/analysis', async (req, res) => {
    try {
        const hours = parseInt(req.query.hours) || 24;
        const source = req.query.source || '';
        const classif = req.query.classification || '';
        const search = req.query.search || '';
        const limit = parseInt(req.query.limit) || 500;
        const threshold = new Date(Date.now() - hours * 3600000);

        const query = { timestamp: { $gte: threshold }, analyzed: true };
        if (source) query.source = { $regex: source, $options: 'i' };
        if (classif) query.classification = classif;
        if (search) {
            query.$or = [
                { message: { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } },
                { resolution: { $regex: search, $options: 'i' } }
            ];
        }

        const logs = await Log.find(query).sort({ timestamp: -1 }).limit(limit).lean();
        res.json(logs);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Log de test
app.post('/api/test-log', async (req, res) => {
    try {
        const messages = [
            'SSH brute force attempt from 185.220.101.45',
            'Interface GigabitEthernet0/1 went down',
            'User admin logged in successfully',
            'CPU utilization 95% for 5 minutes',
            'ACL denied tcp 192.168.1.100 -> 10.0.0.1 port 22',
            'Disk space warning /dev/sda1 85% full',
            'firewall01: BLOCKED port scan from 203.45.67.89',
            'db01: Slow query detected 8500ms on table users',
            'webserver01: SQL injection attempt detected',
            'router01: CRITICAL CPU overload 98 percent'
        ];
        const msg = messages[Math.floor(Math.random() * messages.length)];
        const source = '127.0.0.1';
        const uniqueHash = generateUniqueHash(source, msg);
        
        const existing = await Log.findOne({ uniqueHash });
        if (existing) {
            return res.json({ status: 'ignored', message: 'Log déjà existant' });
        }
        
        const log = await Log.create({
            source,
            message: msg,
            analyzed: false,
            severity: Math.floor(Math.random() * 7),
            uniqueHash
        });
        io.emit('log_message', log.toObject());
        res.json(log);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Déclencher l'analyse batch
app.post('/api/run-analysis', async (req, res) => {
    try {
        processBatchAnalysis();
        res.json({ status: 'batch_lancé' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Statistiques
app.get('/api/stats', async (req, res) => {
    try {
        const total = await Log.countDocuments();
        const analyzed = await Log.countDocuments({ analyzed: true });
        const critical = await Log.countDocuments({ classification: 'critical' });
        const warning = await Log.countDocuments({ classification: 'warning' });
        const info = await Log.countDocuments({ classification: 'info' });
        const sources = await Log.distinct('source');
        const pending = await Log.countDocuments({ analyzed: false });
        
        res.json({ total, analyzed, pending, critical, warning, info, sources: sources.length });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Volume horaire
app.get('/api/stats/volume', async (req, res) => {
    try {
        const since = new Date(Date.now() - 24 * 3600000);
        const logs = await Log.find({ timestamp: { $gte: since } }, { timestamp: 1 }).lean();
        const buckets = {};
        logs.forEach(l => {
            const h = new Date(l.timestamp);
            h.setMinutes(0, 0, 0);
            const key = h.toISOString();
            buckets[key] = (buckets[key] || 0) + 1;
        });
        const result = Object.entries(buckets)
            .map(([time, count]) => ({ time, count }))
            .sort((a, b) => a.time.localeCompare(b.time));
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ─── WebSocket ─────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
    console.log('🟢 Client connecté :', socket.id);
    socket.on('disconnect', () => console.log('🔴 Client déconnecté :', socket.id));
});

// ─── UDP Syslog AVEC DÉDOUBLONNAGE ─────────────────────────────────────────────
const syslogServer = dgram.createSocket('udp4');

syslogServer.on('message', async (msg, rinfo) => {
    try {
        const parsed = parseSyslog(msg, `${rinfo.address}:${rinfo.port}`);
        const source = parsed.source;
        const message = parsed.message;
        
        const uniqueHash = generateUniqueHash(source, message);
        const existing = await Log.findOne({ uniqueHash: uniqueHash });
        
        if (existing) {
            console.log(`🔄 [DEDUP] Log ignoré (existe déjà en base) : ${message.substring(0, 60)}...`);
            return;
        }
        
        const log = await Log.create({
            ...parsed,
            analyzed: false,
            uniqueHash: uniqueHash
        });
        
        io.emit('log_message', log.toObject());
        console.log(`✅ [NEW] Log de ${rinfo.address} : ${message.substring(0, 80)}`);
        
    } catch (err) {
        if (err.code === 11000) {
            console.log(`🔄 [CONFLIT] Doublon ignoré (index unique MongoDB)`);
        } else {
            console.error('❌ Erreur UDP :', err.message);
        }
    }
});

syslogServer.on('error', (err) => console.error('❌ Erreur UDP server :', err.message));
syslogServer.bind(SYSLOG_PORT, '0.0.0.0', () => {
    console.log(`📡 UDP syslog écoute sur le port ${SYSLOG_PORT}`);
});

// ─── Script de nettoyage des doublons existants ───────────────────────────────
async function cleanExistingDuplicates() {
    try {
        console.log('🧹 Nettoyage des doublons existants...');
        
        const logsWithoutHash = await Log.find({ uniqueHash: { $exists: false } });
        for (const log of logsWithoutHash) {
            const hash = generateUniqueHash(log.source, log.message);
            await Log.updateOne({ _id: log._id }, { $set: { uniqueHash: hash } });
        }
        console.log(`✅ ${logsWithoutHash.length} logs sans hash mis à jour`);
        
        const duplicates = await Log.aggregate([
            { $group: { _id: "$uniqueHash", ids: { $push: "$_id" }, count: { $sum: 1 } } },
            { $match: { count: { $gt: 1 } } }
        ]);
        
        let deletedCount = 0;
        for (const dup of duplicates) {
            const logs = await Log.find({ _id: { $in: dup.ids } }).sort({ timestamp: -1 });
            const keepId = logs[0]._id;
            const deleteIds = dup.ids.filter(id => id.toString() !== keepId.toString());
            
            if (deleteIds.length) {
                await Log.deleteMany({ _id: { $in: deleteIds } });
                deletedCount += deleteIds.length;
                console.log(`🗑️ Supprimé ${deleteIds.length} doublons pour hash ${dup._id}`);
            }
        }
        
        console.log(`✅ Nettoyage terminé : ${deletedCount} doublons supprimés`);
    } catch (err) {
        console.error('❌ Erreur nettoyage:', err.message);
    }
}

// ─── Arrêt propre ──────────────────────────────────────────────────────────────
let analysisInterval = null;
let rotationInterval = null;

function shutdown() {
    console.log('🛑 Arrêt en cours...');
    if (analysisInterval) clearInterval(analysisInterval);
    if (rotationInterval) clearInterval(rotationInterval);
    http.close();
    syslogServer.close();
    mongoose.connection.close().then(() => {
        console.log('✅ Arrêt complet');
        process.exit(0);
    }).catch(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000);
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// ─── Démarrage ─────────────────────────────────────────────────────────────────
async function startServer() {
    if (STARTUP_DELAY > 0) {
        console.log(`⏳ Attente de ${STARTUP_DELAY / 1000}s avant démarrage...`);
        await setTimeout(STARTUP_DELAY);
    }
    
    await connectWithRetry();
    await cleanExistingDuplicates();
    
    analysisInterval = setInterval(processBatchAnalysis, 5 * 60 * 1000);
    console.log('🚀 Lancement du batch initial...');
    processBatchAnalysis();
    
    rotationInterval = setInterval(rotateLogs, 24 * 3600000);
    console.log('🔄 Rotation des logs programmée toutes les 24h');
    
    http.listen(3000, '0.0.0.0', () => {
        console.log('🌐 Interface web sur http://localhost:3000');
        console.log('📊 Page analyse sur http://localhost:3000/analysis');
    });
}

startServer();