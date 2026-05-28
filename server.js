import 'dotenv/config';
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import dgram from 'dgram';
import path from 'path';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';
import mongoose from 'mongoose';
import { setTimeout } from 'timers/promises';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

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
    resolution:     { type: String, default: null }
}, { timestamps: true });

logSchema.index({ timestamp: -1 });
logSchema.index({ analyzed: 1 });
logSchema.index({ source: 1 });
logSchema.index({ classification: 1 });

const Log = mongoose.model('Log', logSchema);

// ─── Configuration ─────────────────────────────────────────────────────────────
const MONGODB_URI     = process.env.MONGODB_URI     || 'mongodb://localhost:27017/syslog';
const LITELLM_URL     = process.env.LITELLM_URL     || '';
const LITELLM_API_KEY = process.env.LITELLM_API_KEY || '';
const LITELLM_MODEL   = process.env.LITELLM_MODEL   || '';
const SYSLOG_PORT     = parseInt(process.env.SYSLOG_PORT || '514');
const MAX_RETRIES     = 5;
const RETRY_INTERVAL  = 5000;
const STARTUP_DELAY   = parseInt(process.env.STARTUP_DELAY || '0', 10) * 1000;
const BATCH_LIMIT     = 20;

// Modèles par sévérité pour l'analyse manuelle
const MODEL_BY_SEV = {
    info:     'llama3:8b',
    warning:  'phi3:mini',
    critical: 'gemma4:26b',
};

console.log(`LiteLLM URL   : ${LITELLM_URL}`);
console.log(`LiteLLM Model : ${LITELLM_MODEL}`);

// ─── Connexion MongoDB ─────────────────────────────────────────────────────────
async function connectWithRetry(retries = MAX_RETRIES) {
    try {
        console.log('Connexion à MongoDB :', MONGODB_URI);
        await mongoose.connect(MONGODB_URI);
        console.log('✅ MongoDB connecté');
        const count = await Log.countDocuments();
        console.log(`Logs en base : ${count}`);
    } catch (err) {
        console.error('Erreur MongoDB :', err.message);
        if (retries > 0) {
            console.log(`Nouvelle tentative dans ${RETRY_INTERVAL / 1000}s... (${retries} restantes)`);
            await setTimeout(RETRY_INTERVAL);
            await connectWithRetry(retries - 1);
        } else {
            console.error('Impossible de se connecter à MongoDB. Arrêt.');
            process.exit(1);
        }
    }
}

// ─── Appel LiteLLM générique ───────────────────────────────────────────────────
async function callLiteLLM(prompt, model) {
    const headers = { 'Content-Type': 'application/json' };
    if (LITELLM_API_KEY) headers['Authorization'] = `Bearer ${LITELLM_API_KEY}`;

    const response = await fetch(`${LITELLM_URL}/chat/completions`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
            model:       model || LITELLM_MODEL,
            messages:    [{ role: 'user', content: prompt }],
            max_tokens:  3000,
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

// ─── Prompt batch (plusieurs logs, modèle unique) ──────────────────────────────
function buildBatchPrompt(logs) {
    const lines = logs.map((l, i) => `${i + 1}. [${l.source}] ${l.message}`).join('\n');
    return `You are a network security and system administration expert.
Analyze each syslog message below and return ONLY a valid JSON array.

Strict rules:
- "classification": exactly one of: "info", "warning", "critical"
  * info     = normal event, no action needed
  * warning  = anomaly to monitor, action recommended
  * critical = serious problem, immediate action required
- "description": short sentence explaining the problem (null if info)
- "resolution": short sentence on what to do to fix it (null if info). ALWAYS provide resolution for warning and critical.
- Reply ONLY with the JSON array, no text before or after, no markdown.

Logs to analyze:
${lines}

Expected format:
[
  {"index":1,"classification":"critical","description":"SSH brute force attack detected from external IP","resolution":"Block IP 185.220.101.45 in firewall immediately and check /var/log/auth.log"},
  {"index":2,"classification":"info","description":null,"resolution":null}
]`;
}

// ─── Prompt analyse manuelle (log unique, prompt adapté à la sévérité) ─────────
function buildManualPrompt(log, sev) {
    const base = `[${log.source}] ${log.message}`;

    if (sev === 'info') {
        return `You are a syslog analysis assistant.
Analyze this INFO syslog entry and provide a concise quick summary (2-3 sentences max).
Reply ONLY with valid JSON, no markdown:
{"classification":"info","description":"short summary of what this log means","resolution":null}

Log: ${base}`;
    }

    if (sev === 'warning') {
        return `You are a network security analyst.
Analyze this WARNING syslog entry: identify the issue and provide a recommended action.
Reply ONLY with valid JSON, no markdown:
{"classification":"warning","description":"what is the anomaly or issue","resolution":"what action to take"}

Log: ${base}`;
    }

    if (sev === 'critical') {
        return `You are a senior cybersecurity incident responder.
Perform a deep analysis of this CRITICAL syslog entry.
Identify the root cause, assess the impact, and provide step-by-step remediation.
Reply ONLY with valid JSON, no markdown:
{"classification":"critical","description":"root cause and impact summary","resolution":"step-by-step remediation actions"}

Log: ${base}`;
    }

    // Sévérité inconnue : analyse générique
    return `You are a syslog analysis assistant.
Analyze this syslog entry and determine its severity.
Reply ONLY with valid JSON, no markdown:
{"classification":"info|warning|critical","description":"explanation or null","resolution":"action or null"}

Log: ${base}`;
}

// ─── Parser réponse IA (batch) ─────────────────────────────────────────────────
function parseBatchResponse(raw) {
    let cleaned = raw.replace(/```json|```/g, '').trim();
    const start = cleaned.indexOf('[');
    const end   = cleaned.lastIndexOf(']');
    if (start !== -1 && end !== -1) cleaned = cleaned.slice(start, end + 1);

    const parsed = JSON.parse(cleaned);
    return parsed.map(item => ({
        index:          item.index,
        classification: ['info', 'warning', 'critical'].includes(item.classification)
            ? item.classification : 'info',
        description: item.description || null,
        resolution:  item.resolution  || null
    }));
}

// ─── Parser réponse IA (manuelle, JSON objet) ──────────────────────────────────
function parseManualResponse(raw) {
    let cleaned = raw.replace(/```json|```/g, '').trim();
    // Extraire le premier objet JSON
    const start = cleaned.indexOf('{');
    const end   = cleaned.lastIndexOf('}');
    if (start !== -1 && end !== -1) cleaned = cleaned.slice(start, end + 1);
    const parsed = JSON.parse(cleaned);
    return {
        classification: ['info', 'warning', 'critical'].includes(parsed.classification)
            ? parsed.classification : 'info',
        description: parsed.description || null,
        resolution:  parsed.resolution  || null
    };
}

// ─── Batch Processor (automatique toutes les 5 min) ───────────────────────────
let isAnalysisRunning = false;

async function processBatchAnalysis() {
    if (isAnalysisRunning) {
        console.log('Batch déjà en cours, on attend le prochain cycle.');
        return;
    }
    isAnalysisRunning = true;
    try {
        const logs = await Log.find({ analyzed: false }).sort({ timestamp: 1 }).limit(BATCH_LIMIT);
        if (logs.length === 0) { console.log('Batch : aucun log en attente.'); return; }

        console.log(`Batch : analyse de ${logs.length} logs via LiteLLM [${LITELLM_MODEL}]...`);
        const prompt      = buildBatchPrompt(logs);
        const rawResponse = await callLiteLLM(prompt, LITELLM_MODEL);

        let results;
        try { results = parseBatchResponse(rawResponse); }
        catch (parseErr) { console.error('Réponse IA non parseable :', rawResponse); return; }

        let updatedCount = 0;
        for (const result of results) {
            const log = logs[result.index - 1];
            if (!log) continue;
            const updated = await Log.findByIdAndUpdate(
                log._id,
                { $set: { analyzed: true, classification: result.classification, description: result.description, resolution: result.resolution } },
                { new: true }
            );
            if (updated) { io.emit('log_updated', updated.toObject()); updatedCount++; }
        }
        console.log(`✅ Batch terminé : ${updatedCount}/${logs.length} logs analysés.`);
    } catch (err) {
        console.error('❌ Erreur batch :', err.message);
    } finally {
        isAnalysisRunning = false;
    }
}

// ─── Parser Syslog UDP ─────────────────────────────────────────────────────────
function parseSyslog(msg, remoteAddress) {
    const raw   = msg.toString();
    const match = raw.match(/^<(\d+)>(.*)/);
    if (match) {
        const priority = parseInt(match[1]);
        return { source: remoteAddress, facility: Math.floor(priority / 8), severity: priority % 8, message: match[2].trim(), rawMessage: raw };
    }
    return { source: remoteAddress, facility: 0, severity: 6, message: raw.trim(), rawMessage: raw };
}

function severityLabel(n) {
    const labels = ['emergency','alert','critical','error','warning','notice','info','debug'];
    return labels[n] || 'unknown';
}

// ─── Express + Socket.IO ───────────────────────────────────────────────────────
const app  = express();
const http = createServer(app);
const io   = new Server(http, {
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

// ─── Routes ────────────────────────────────────────────────────────────────────
app.get('/',         (req, res) => res.sendFile(path.join(publicPath, 'index.html')));
app.get('/analysis', (req, res) => res.sendFile(path.join(publicPath, 'analysis.html')));

// Logs avec filtres
app.get('/api/logs', async (req, res) => {
    try {
        const limit    = parseInt(req.query.limit)  || 200;
        const hours    = parseInt(req.query.hours)  || 24;
        const severity = req.query.severity         || '';
        const source   = req.query.source           || '';
        const search   = req.query.search           || '';
        const threshold = new Date(Date.now() - hours * 3600000);

        const query = { timestamp: { $gte: threshold } };
        if (source) query.source  = { $regex: source, $options: 'i' };
        if (search) query.message = { $regex: search, $options: 'i' };
        if (severity && severity !== 'All') {
            if (['info','warning','critical'].includes(severity.toLowerCase())) {
                query.classification = severity.toLowerCase();
            }
        }

        const logs = await Log.find(query).sort({ timestamp: -1 }).limit(limit).lean();
        res.json(logs);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Sources uniques
app.get('/api/logs/sources', async (req, res) => {
    try {
        const sources = await Log.distinct('source');
        res.json(sources);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Export CSV
app.get('/api/logs/export', async (req, res) => {
    try {
        const hours     = parseInt(req.query.hours) || 24;
        const threshold = new Date(Date.now() - hours * 3600000);
        const logs      = await Log.find({ timestamp: { $gte: threshold } }).sort({ timestamp: -1 }).lean();

        const header = 'Time,Source,Severity,Classification,Message,Description,Resolution\n';
        const rows   = logs.map(l => [
            new Date(l.timestamp).toISOString(),
            `"${l.source || ''}"`,
            severityLabel(l.severity),
            l.classification || 'pending',
            `"${(l.message     || '').replace(/"/g, '""')}"`,
            `"${(l.description || '').replace(/"/g, '""')}"`,
            `"${(l.resolution  || '').replace(/"/g, '""')}"`
        ].join(',')).join('\n');

        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', 'attachment; filename="syslog-export.csv"');
        res.send(header + rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Logs analysés (page analysis.html)
app.get('/api/analysis', async (req, res) => {
    try {
        const hours     = parseInt(req.query.hours) || 24;
        const source    = req.query.source          || '';
        const classif   = req.query.classification  || '';
        const search    = req.query.search          || '';
        const limit     = parseInt(req.query.limit) || 500;
        const threshold = new Date(Date.now() - hours * 3600000);

        const query = { timestamp: { $gte: threshold }, analyzed: true };
        if (source)  query.source         = { $regex: source, $options: 'i' };
        if (classif) query.classification = classif;
        if (search) {
            query.$or = [
                { message:     { $regex: search, $options: 'i' } },
                { description: { $regex: search, $options: 'i' } },
                { resolution:  { $regex: search, $options: 'i' } }
            ];
        }

        const logs = await Log.find(query).sort({ timestamp: -1 }).limit(limit).lean();
        res.json(logs);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ANALYSE MANUELLE (bouton dans index.html) ─────────────────────────────────
// POST /api/analyse-log { logId }
// Sélectionne automatiquement le modèle selon la classification existante du log.
// Si le log n'est pas encore classifié, utilise le modèle par défaut.
// Met à jour la base et émet log_updated.
app.post('/api/analyse-log', async (req, res) => {
    try {
        const { logId } = req.body;
        if (!logId) return res.status(400).json({ error: 'logId requis' });

        const log = await Log.findById(logId);
        if (!log) return res.status(404).json({ error: 'Log introuvable' });

        // Déterminer la sévérité pour choisir le modèle
        // On utilise la classification existante si dispo, sinon on fait un pré-classement rapide
        const sev   = log.classification || '';
        const model = MODEL_BY_SEV[sev]  || LITELLM_MODEL;

        console.log(`Analyse manuelle log ${logId} — sévérité: ${sev} — modèle: ${model}`);

        const prompt      = buildManualPrompt(log, sev);
        const rawResponse = await callLiteLLM(prompt, model);

        let result;
        try { result = parseManualResponse(rawResponse); }
        catch (parseErr) {
            console.error('Réponse IA non parseable :', rawResponse);
            return res.status(502).json({ error: 'Réponse IA invalide', raw: rawResponse });
        }

        // Sauvegarder en base
        const updated = await Log.findByIdAndUpdate(
            logId,
            { $set: { analyzed: true, classification: result.classification, description: result.description, resolution: result.resolution } },
            { new: true }
        );

        // Notifier tous les clients connectés
        if (updated) io.emit('log_updated', updated.toObject());

        res.json({
            _id:            updated._id,
            classification: result.classification,
            description:    result.description,
            resolution:     result.resolution,
            model:          model,
            sev:            sev
        });
    } catch (err) {
        console.error('❌ Erreur analyse manuelle :', err.message);
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
        const log = await Log.create({ source: '127.0.0.1', message: msg, analyzed: false, severity: Math.floor(Math.random() * 7) });
        io.emit('log_message', log.toObject());
        res.json(log);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Batch manuel (déclenchement depuis l'UI si besoin)
app.post('/api/run-analysis', async (req, res) => {
    try { processBatchAnalysis(); res.json({ status: 'batch_lancé' }); }
    catch (err) { res.status(500).json({ error: err.message }); }
});

// Stats globales
app.get('/api/stats', async (req, res) => {
    try {
        const total    = await Log.countDocuments();
        const analyzed = await Log.countDocuments({ analyzed: true });
        const critical = await Log.countDocuments({ classification: 'critical' });
        const warning  = await Log.countDocuments({ classification: 'warning' });
        const info     = await Log.countDocuments({ classification: 'info' });
        const sources  = await Log.distinct('source');
        const pending  = await Log.countDocuments({ analyzed: false });
        const deep     = critical; // Critical = analyse deep (deepseek)
        res.json({ total, analyzed, pending, critical, warning, info, sources: sources.length, deep });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// Volume over time (dernières 24h, par heure)
app.get('/api/stats/volume', async (req, res) => {
    try {
        const since = new Date(Date.now() - 24 * 3600000);
        const logs  = await Log.find({ timestamp: { $gte: since } }, { timestamp: 1 }).lean();
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
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── WebSocket ─────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
    console.log('Client connecté :', socket.id);
    socket.on('disconnect', () => console.log('Client déconnecté :', socket.id));
});

// ─── UDP Syslog ────────────────────────────────────────────────────────────────
const syslogServer = dgram.createSocket('udp4');
syslogServer.on('message', async (msg, rinfo) => {
    try {
        const parsed = parseSyslog(msg, `${rinfo.address}:${rinfo.port}`);
        const log    = await Log.create({ ...parsed, analyzed: false });
        io.emit('log_message', log.toObject());
        console.log(`Log reçu de ${rinfo.address} : ${parsed.message}`);
    } catch (err) { console.error('Erreur traitement UDP :', err.message); }
});
syslogServer.on('error', (err) => console.error('Erreur UDP :', err.message));
syslogServer.bind(SYSLOG_PORT, '0.0.0.0', () => console.log(`✅ UDP syslog écoute sur le port ${SYSLOG_PORT}`));

// ─── Arrêt propre ──────────────────────────────────────────────────────────────
let analysisInterval = null;
function shutdown() {
    console.log('Arrêt en cours...');
    clearInterval(analysisInterval);
    http.close();
    syslogServer.close();
    mongoose.connection.close().then(() => process.exit(0)).catch(() => process.exit(0));
    setTimeout(() => process.exit(1), 10000);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT',  shutdown);

// ─── Démarrage ─────────────────────────────────────────────────────────────────
async function startServer() {
    if (STARTUP_DELAY > 0) {
        console.log(`Attente de ${STARTUP_DELAY / 1000}s avant démarrage...`);
        await setTimeout(STARTUP_DELAY);
    }
    await connectWithRetry();
    analysisInterval = setInterval(processBatchAnalysis, 5 * 60 * 1000);
    console.log('Lancement du batch initial...');
    processBatchAnalysis();
    http.listen(3000, '0.0.0.0', () => console.log('✅ Interface web sur http://localhost:3000'));
}
startServer();