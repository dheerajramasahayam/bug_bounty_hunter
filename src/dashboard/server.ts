import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { getConfig } from '../config/settings.js';
import { db } from '../core/database.js';
import { logger } from '../core/logger.js';
import { Response } from 'express';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize database
db.initialize();

// --- SSE Setup ---
const clients = new Set<Response>();

const broadcast = (event: string, data: any) => {
    const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    clients.forEach(client => client.write(message));
};

app.get('/api/stream', (req, res) => {
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');

    res.write('event: connected\ndata: "true"\n\n');
    clients.add(res);

    // Send initial state immediately
    const stats = db.getStats();
    res.write(`event: stats\ndata: ${JSON.stringify(stats)}\n\n`);

    req.on('close', () => {
        clients.delete(res);
    });
});

// --- Log Watching ---
const config = getConfig();
const logFile = config.logging.file;
let logSize = 0;

// Ensure log file exists
const logDir = path.dirname(logFile);
if (!fs.existsSync(logDir)) fs.mkdirSync(logDir, { recursive: true });
if (!fs.existsSync(logFile)) fs.writeFileSync(logFile, '');

const checkLogs = () => {
    try {
        const stats = fs.statSync(logFile);
        if (stats.size > logSize) {
            const stream = fs.createReadStream(logFile, {
                start: logSize,
                end: stats.size
            });

            let data = '';
            stream.on('data', chunk => data += chunk);
            stream.on('end', () => {
                if (data.trim()) {
                    const lines = data.split('\n').filter(l => l.trim());
                    if (lines.length > 0) {
                        broadcast('logs', lines);
                    }
                }
                logSize = stats.size;
            });
        } else if (stats.size < logSize) {
            // File rotated
            logSize = 0;
        }
    } catch (e) {
        // Ignore errors (file busy etc)
    }
};

// Log watcher interval (fs.watch is flakey on strict modes sometimes, polling 200ms is safer for logs)
setInterval(checkLogs, 200);
// specific fs.watch might be better but polling 200ms is negligible cost for local file

// --- Stats & Findings Watcher ---
let lastStatsHash = '';
let lastFindingsCount = 0;

const checkDb = () => {
    try {
        const stats = db.getStats();
        const currentHash = JSON.stringify(stats);

        if (currentHash !== lastStatsHash) {
            broadcast('stats', stats);
            lastStatsHash = currentHash;
        }

        if (stats.totalFindings !== lastFindingsCount) {
            // Findings changed, send latest 10
            // We can optimize this by only sending diffs, but for dashboard simpler is fine
            // We'll just trigger a 'findings_update' event and let client fetch?
            // Or send the latest findings directly.

            // Let's send the latest 10 findings always if count changes
            const latestFindings = db.getAllTargets()
                .flatMap(t => db.getFindingsByTarget(t.id))
                .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
                .slice(0, 10);

            broadcast('findings', latestFindings);
            lastFindingsCount = stats.totalFindings;
        }
    } catch (e) {
        console.error('DB Check error:', e);
    }
};

setInterval(checkDb, 2000); // Check DB every 2s

// --- Standard API Routes (Fallback/Initial Load) ---

app.get('/api/stats', (_req, res) => {
    try {
        res.json(db.getStats());
    } catch (e) { res.status(500).json({ error: String(e) }) }
});

app.get('/api/targets', (_req, res) => {
    try {
        res.json(db.getAllTargets());
    } catch (e) { res.status(500).json({ error: String(e) }) }
});

app.get('/api/findings', (req, res) => {
    try {
        const findings = db.getAllTargets().flatMap(t => db.getFindingsByTarget(t.id));
        res.json(findings);
    } catch (e) { res.status(500).json({ error: String(e) }) }
});

// Serve frontend
app.get('*', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start
app.listen(config.dashboard.port, config.dashboard.host, () => {
    logger.success(`Dashboard 2.0 running at http://${config.dashboard.host}:${config.dashboard.port}`);
    // Initialize log size
    try {
        logSize = fs.statSync(logFile).size;
    } catch { }
});
