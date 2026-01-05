import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { getConfig } from '../config/settings.js';
import { logger } from './logger.js';

export interface Target {
    id: string;
    domain: string;
    scope: string[];
    outOfScope: string[];
    platform: string;
    programUrl: string;
    createdAt: string;
    updatedAt: string;
}

export interface Finding {
    id: string;
    targetId: string;
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    url: string;
    parameter?: string;
    payload?: string;
    evidence: string;
    description: string;
    aiAnalysis?: string;
    confidence: number;
    status: 'new' | 'verified' | 'false_positive' | 'reported' | 'duplicate';
    createdAt: string;
    updatedAt: string;
}

export interface ScanSession {
    id: string;
    targetId: string;
    status: 'running' | 'completed' | 'failed' | 'paused';
    startedAt: string;
    completedAt?: string;
    urlsScanned: number;
    findingsCount: number;
    config: string;
}

export interface CrawledUrl {
    id: string;
    targetId: string;
    sessionId: string;
    url: string;
    method: string;
    statusCode: number;
    contentType: string;
    responseSize: number;
    parameters: string;
    crawledAt: string;
}

class DatabaseManager {
    private db: Database.Database | null = null;

    initialize(): void {
        const config = getConfig();
        const dbPath = path.resolve(config.paths.root, config.database.path);
        const dbDir = path.dirname(dbPath);

        // Ensure directory exists
        if (!fs.existsSync(dbDir)) {
            fs.mkdirSync(dbDir, { recursive: true });
        }

        this.db = new Database(dbPath);
        this.db.pragma('journal_mode = WAL');
        this.db.pragma('foreign_keys = ON');

        this.createTables();
        logger.info('Database initialized', { path: dbPath });
    }

    private createTables(): void {
        if (!this.db) throw new Error('Database not initialized');

        // Targets table
        this.db.exec(`
      CREATE TABLE IF NOT EXISTS targets (
        id TEXT PRIMARY KEY,
        domain TEXT NOT NULL UNIQUE,
        scope TEXT NOT NULL DEFAULT '[]',
        out_of_scope TEXT NOT NULL DEFAULT '[]',
        platform TEXT DEFAULT '',
        program_url TEXT DEFAULT '',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);

        // Findings table
        this.db.exec(`
      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        type TEXT NOT NULL,
        severity TEXT NOT NULL,
        url TEXT NOT NULL,
        parameter TEXT,
        payload TEXT,
        evidence TEXT NOT NULL,
        description TEXT NOT NULL,
        ai_analysis TEXT,
        confidence REAL NOT NULL DEFAULT 0.5,
        status TEXT NOT NULL DEFAULT 'new',
        created_at TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
      )
    `);

        // Scan sessions table
        this.db.exec(`
      CREATE TABLE IF NOT EXISTS scan_sessions (
        id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'running',
        started_at TEXT NOT NULL DEFAULT (datetime('now')),
        completed_at TEXT,
        urls_scanned INTEGER NOT NULL DEFAULT 0,
        findings_count INTEGER NOT NULL DEFAULT 0,
        config TEXT NOT NULL DEFAULT '{}',
        FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE
      )
    `);

        // Crawled URLs table
        this.db.exec(`
      CREATE TABLE IF NOT EXISTS crawled_urls (
        id TEXT PRIMARY KEY,
        target_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        url TEXT NOT NULL,
        method TEXT NOT NULL DEFAULT 'GET',
        status_code INTEGER,
        content_type TEXT,
        response_size INTEGER,
        parameters TEXT DEFAULT '[]',
        crawled_at TEXT NOT NULL DEFAULT (datetime('now')),
        FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
        FOREIGN KEY (session_id) REFERENCES scan_sessions(id) ON DELETE CASCADE
      )
    `);

        // Create indexes for performance
        this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target_id);
      CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
      CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
      CREATE INDEX IF NOT EXISTS idx_crawled_urls_target ON crawled_urls(target_id);
      CREATE INDEX IF NOT EXISTS idx_crawled_urls_session ON crawled_urls(session_id);
    `);
    }

    getDb(): Database.Database {
        if (!this.db) {
            this.initialize();
        }
        return this.db!;
    }

    // Target operations
    createTarget(target: Omit<Target, 'createdAt' | 'updatedAt'>): Target {
        const db = this.getDb();
        const stmt = db.prepare(`
      INSERT INTO targets (id, domain, scope, out_of_scope, platform, program_url)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

        stmt.run(
            target.id,
            target.domain,
            JSON.stringify(target.scope),
            JSON.stringify(target.outOfScope),
            target.platform,
            target.programUrl
        );

        return this.getTarget(target.id)!;
    }

    getTarget(id: string): Target | null {
        const db = this.getDb();
        const row = db.prepare('SELECT * FROM targets WHERE id = ?').get(id) as Record<string, unknown> | undefined;
        return row ? this.rowToTarget(row) : null;
    }

    getTargetByDomain(domain: string): Target | null {
        const db = this.getDb();
        const row = db.prepare('SELECT * FROM targets WHERE domain = ?').get(domain) as Record<string, unknown> | undefined;
        return row ? this.rowToTarget(row) : null;
    }

    getAllTargets(): Target[] {
        const db = this.getDb();
        const rows = db.prepare('SELECT * FROM targets ORDER BY created_at DESC').all() as Record<string, unknown>[];
        return rows.map(row => this.rowToTarget(row));
    }

    private rowToTarget(row: Record<string, unknown>): Target {
        return {
            id: row.id as string,
            domain: row.domain as string,
            scope: JSON.parse(row.scope as string || '[]'),
            outOfScope: JSON.parse(row.out_of_scope as string || '[]'),
            platform: row.platform as string,
            programUrl: row.program_url as string,
            createdAt: row.created_at as string,
            updatedAt: row.updated_at as string,
        };
    }

    // Finding operations
    createFinding(finding: Omit<Finding, 'createdAt' | 'updatedAt'>): Finding {
        const db = this.getDb();
        const stmt = db.prepare(`
      INSERT INTO findings (id, target_id, type, severity, url, parameter, payload, evidence, description, ai_analysis, confidence, status)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

        stmt.run(
            finding.id,
            finding.targetId,
            finding.type,
            finding.severity,
            finding.url,
            finding.parameter || null,
            finding.payload || null,
            finding.evidence,
            finding.description,
            finding.aiAnalysis || null,
            finding.confidence,
            finding.status
        );

        return this.getFinding(finding.id)!;
    }

    getFinding(id: string): Finding | null {
        const db = this.getDb();
        const row = db.prepare('SELECT * FROM findings WHERE id = ?').get(id) as Record<string, unknown> | undefined;
        return row ? this.rowToFinding(row) : null;
    }

    getFindingsByTarget(targetId: string): Finding[] {
        const db = this.getDb();
        const rows = db.prepare('SELECT * FROM findings WHERE target_id = ? ORDER BY severity, created_at DESC').all(targetId) as Record<string, unknown>[];
        return rows.map(row => this.rowToFinding(row));
    }

    updateFindingStatus(id: string, status: Finding['status']): void {
        const db = this.getDb();
        db.prepare('UPDATE findings SET status = ?, updated_at = datetime("now") WHERE id = ?').run(status, id);
    }

    private rowToFinding(row: Record<string, unknown>): Finding {
        return {
            id: row.id as string,
            targetId: row.target_id as string,
            type: row.type as string,
            severity: row.severity as Finding['severity'],
            url: row.url as string,
            parameter: row.parameter as string | undefined,
            payload: row.payload as string | undefined,
            evidence: row.evidence as string,
            description: row.description as string,
            aiAnalysis: row.ai_analysis as string | undefined,
            confidence: row.confidence as number,
            status: row.status as Finding['status'],
            createdAt: row.created_at as string,
            updatedAt: row.updated_at as string,
        };
    }

    // Session operations
    createSession(session: Omit<ScanSession, 'completedAt'>): ScanSession {
        const db = this.getDb();
        const stmt = db.prepare(`
      INSERT INTO scan_sessions (id, target_id, status, started_at, urls_scanned, findings_count, config)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

        stmt.run(
            session.id,
            session.targetId,
            session.status,
            session.startedAt,
            session.urlsScanned,
            session.findingsCount,
            session.config
        );

        return this.getSession(session.id)!;
    }

    getSession(id: string): ScanSession | null {
        const db = this.getDb();
        const row = db.prepare('SELECT * FROM scan_sessions WHERE id = ?').get(id) as Record<string, unknown> | undefined;
        return row ? this.rowToSession(row) : null;
    }

    updateSession(id: string, updates: Partial<Pick<ScanSession, 'status' | 'completedAt' | 'urlsScanned' | 'findingsCount'>>): void {
        const db = this.getDb();
        const setClauses: string[] = [];
        const values: unknown[] = [];

        if (updates.status !== undefined) {
            setClauses.push('status = ?');
            values.push(updates.status);
        }
        if (updates.completedAt !== undefined) {
            setClauses.push('completed_at = ?');
            values.push(updates.completedAt);
        }
        if (updates.urlsScanned !== undefined) {
            setClauses.push('urls_scanned = ?');
            values.push(updates.urlsScanned);
        }
        if (updates.findingsCount !== undefined) {
            setClauses.push('findings_count = ?');
            values.push(updates.findingsCount);
        }

        if (setClauses.length > 0) {
            values.push(id);
            db.prepare(`UPDATE scan_sessions SET ${setClauses.join(', ')} WHERE id = ?`).run(...values);
        }
    }

    private rowToSession(row: Record<string, unknown>): ScanSession {
        return {
            id: row.id as string,
            targetId: row.target_id as string,
            status: row.status as ScanSession['status'],
            startedAt: row.started_at as string,
            completedAt: row.completed_at as string | undefined,
            urlsScanned: row.urls_scanned as number,
            findingsCount: row.findings_count as number,
            config: row.config as string,
        };
    }

    // Crawled URL operations
    saveCrawledUrl(crawledUrl: CrawledUrl): void {
        const db = this.getDb();
        const stmt = db.prepare(`
      INSERT OR REPLACE INTO crawled_urls (id, target_id, session_id, url, method, status_code, content_type, response_size, parameters, crawled_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

        stmt.run(
            crawledUrl.id,
            crawledUrl.targetId,
            crawledUrl.sessionId,
            crawledUrl.url,
            crawledUrl.method,
            crawledUrl.statusCode,
            crawledUrl.contentType,
            crawledUrl.responseSize,
            crawledUrl.parameters,
            crawledUrl.crawledAt
        );
    }

    isUrlCrawled(sessionId: string, url: string): boolean {
        const db = this.getDb();
        const row = db.prepare('SELECT 1 FROM crawled_urls WHERE session_id = ? AND url = ?').get(sessionId, url);
        return !!row;
    }

    // Statistics
    getStats(): {
        totalTargets: number;
        totalFindings: number;
        findingsBySeverity: Record<string, number>;
        totalScans: number;
    } {
        const db = this.getDb();

        const totalTargets = (db.prepare('SELECT COUNT(*) as count FROM targets').get() as { count: number }).count;
        const totalFindings = (db.prepare('SELECT COUNT(*) as count FROM findings').get() as { count: number }).count;
        const totalScans = (db.prepare('SELECT COUNT(*) as count FROM scan_sessions').get() as { count: number }).count;

        const severityRows = db.prepare('SELECT severity, COUNT(*) as count FROM findings GROUP BY severity').all() as { severity: string; count: number }[];
        const findingsBySeverity: Record<string, number> = {};
        severityRows.forEach(row => {
            findingsBySeverity[row.severity] = row.count;
        });

        return { totalTargets, totalFindings, findingsBySeverity, totalScans };
    }

    close(): void {
        if (this.db) {
            this.db.close();
            this.db = null;
        }
    }
}

// Singleton database instance
export const db = new DatabaseManager();
