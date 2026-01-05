import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { getConfig } from '../config/settings.js';
import { db } from '../core/database.js';
import { logger } from '../core/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize database
db.initialize();

// API Routes

// Get all targets
app.get('/api/targets', (_req, res) => {
    try {
        const targets = db.getAllTargets();
        res.json(targets);
    } catch (error) {
        res.status(500).json({ error: String(error) });
    }
});

// Get target by ID
app.get('/api/targets/:id', (req, res) => {
    try {
        const target = db.getTarget(req.params.id);
        if (!target) {
            return res.status(404).json({ error: 'Target not found' });
        }
        return res.json(target);
    } catch (error) {
        return res.status(500).json({ error: String(error) });
    }
});

// Get findings for a target
app.get('/api/targets/:id/findings', (req, res) => {
    try {
        const findings = db.getFindingsByTarget(req.params.id);
        res.json(findings);
    } catch (error) {
        res.status(500).json({ error: String(error) });
    }
});

// Get all findings
app.get('/api/findings', (req, res) => {
    try {
        const { severity, status } = req.query;
        let findings = db.getAllTargets().flatMap(t => db.getFindingsByTarget(t.id));

        if (severity) {
            findings = findings.filter(f => f.severity === severity);
        }
        if (status) {
            findings = findings.filter(f => f.status === status);
        }

        res.json(findings);
    } catch (error) {
        res.status(500).json({ error: String(error) });
    }
});

// Get finding by ID
app.get('/api/findings/:id', (req, res) => {
    try {
        const finding = db.getFinding(req.params.id);
        if (!finding) {
            return res.status(404).json({ error: 'Finding not found' });
        }
        return res.json(finding);
    } catch (error) {
        return res.status(500).json({ error: String(error) });
    }
});

// Update finding status
app.patch('/api/findings/:id/status', (req, res) => {
    try {
        const { status } = req.body;
        if (!['new', 'verified', 'false_positive', 'reported', 'duplicate'].includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }

        db.updateFindingStatus(req.params.id, status);
        return res.json({ success: true });
    } catch (error) {
        return res.status(500).json({ error: String(error) });
    }
});

// Get statistics
app.get('/api/stats', (_req, res) => {
    try {
        const stats = db.getStats();
        res.json(stats);
    } catch (error) {
        res.status(500).json({ error: String(error) });
    }
});

// Get system status
app.get('/api/status', async (_req, res) => {
    try {
        // In a real implementation, we would check PM2 or a status file
        // For now, we'll infer status from recent database activity
        const stats = db.getStats();
        res.json({
            online: true,
            uptime: process.uptime(),
            lastScan: new Date().toISOString(),
            activeTarget: 'Monitoring...', // We'll improve this later
            stats
        });
    } catch (error) {
        res.status(500).json({ error: String(error) });
    }
});

// Serve the dashboard
app.get('*', (_req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
const config = getConfig();
app.listen(config.dashboard.port, config.dashboard.host, () => {
    logger.success(`Dashboard running at http://${config.dashboard.host}:${config.dashboard.port}`);
});
