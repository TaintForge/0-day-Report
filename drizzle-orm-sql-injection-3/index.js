import express from 'express';
import mysql from 'mysql2/promise';
import { mysqlTable, varchar, int } from 'drizzle-orm/mysql-core';
import { generateMySQLDrizzleJson, generateMySQLMigration } from 'drizzle-kit/api';

const PORT = 3003;
const conn = await mysql.createConnection({
    host: '127.0.0.1',
    port: 3307,
    user: 'root',
    password: 'rootpass',
    database: 'pocdb',
    multipleStatements: true,
});

await conn.query('DROP TABLE IF EXISTS flags_svc3');
await conn.query('CREATE TABLE flags_svc3 (id INT PRIMARY KEY AUTO_INCREMENT)');

const prevSchema = {
    flags: mysqlTable('flags_svc3', { id: int('id').primaryKey() }),
};
const prevSnapshot = await generateMySQLDrizzleJson(prevSchema);

const app = express();
app.use(express.json());

app.post('/add-flag', async (req, res) => {
    const { name, default: defValue } = req.body ?? {};
    if (!name || typeof name !== 'string') return res.status(400).json({ error: 'name required' });
    if (typeof defValue !== 'string')      return res.status(400).json({ error: 'default required' });
    const ident = name.replace(/[^a-zA-Z0-9_]/g, '_');

    const curSchema = {
        flags: mysqlTable('flags_svc3', {
            id: int('id').primaryKey(),
            [ident]: varchar(ident, { length: 255 }).notNull().default(defValue),
        }),
    };
    const curSnapshot = await generateMySQLDrizzleJson(curSchema);
    const statements = await generateMySQLMigration(prevSnapshot, curSnapshot);

    const ran = [];
    for (const stmt of statements) {
        try {
            await conn.query(stmt);
            ran.push({ stmt, ok: true });
        } catch (e) {
            ran.push({ stmt, ok: false, error: String(e) });
        }
    }
    res.json({ statements, executed: ran });
});

app.get('/schema', async (req, res) => {
    const [tables] = await conn.query("SHOW TABLES LIKE 'flags_svc3'");
    if (tables.length === 0) {
        return res.json({ table_exists: false, note: 'flags_svc3 has been DROPPED by injection' });
    }
    const [rows] = await conn.query('SHOW CREATE TABLE flags_svc3');
    res.json({ table_exists: true, create_table: rows[0]['Create Table'] });
});

app.listen(PORT, () => {
    console.log(`svc3-kit-default-injection listening on http://127.0.0.1:${PORT}`);
});
