import express from 'express';
import mysql from 'mysql2/promise';
import { drizzle } from 'drizzle-orm/mysql2';
import { sql } from 'drizzle-orm';

const PORT = 3002;
const conn = await mysql.createConnection({
    host: '127.0.0.1',
    port: 3307,
    user: 'root',
    password: 'rootpass',
    database: 'pocdb',
    multipleStatements: true,
});
const db = drizzle(conn);

await conn.query(`
    CREATE TABLE IF NOT EXISTS audit_svc2 (
        id INT PRIMARY KEY AUTO_INCREMENT,
        event VARCHAR(200)
    )
`);
await conn.query('TRUNCATE TABLE audit_svc2');
await conn.query(`INSERT INTO audit_svc2 (event) VALUES ('bootstrap')`);

const app = express();
app.use(express.json());

app.post('/export', async (req, res) => {
    const { isolationLevel } = req.body ?? {};
    if (typeof isolationLevel !== 'string') {
        return res.status(400).json({ error: 'isolationLevel must be a string' });
    }

    try {
        await db.transaction(async (tx) => {
            await tx.execute(sql`INSERT INTO audit_svc2 (event) VALUES ('export-run')`);
        }, /** @type {any} */ ({ isolationLevel }));
    } catch (e) {
        return res.status(500).json({ error: String(e) });
    }

    res.json({ ok: true });
});

app.get('/audit', async (req, res) => {
    const [rows] = await conn.query('SELECT * FROM audit_svc2');
    res.json(rows);
});

app.get('/users', async (req, res) => {
    const [rows] = await conn.query(
        "SELECT User, Host FROM mysql.user WHERE User NOT IN ('mysql.sys','mysql.session','mysql.infoschema')"
    );
    res.json(rows);
});

app.listen(PORT, () => {
    console.log(`svc2-tx-config-injection listening on http://127.0.0.1:${PORT}`);
});
