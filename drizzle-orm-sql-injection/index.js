import express from 'express';
import mysql from 'mysql2/promise';
import { mysqlTable, mysqlView, varchar, int } from 'drizzle-orm/mysql-core';
import { eq } from 'drizzle-orm';
import { generateMySQLDrizzleJson, generateMySQLMigration } from 'drizzle-kit/api';

const PORT = 3001;
const conn = await mysql.createConnection({
    host: '127.0.0.1',
    port: 3307,
    user: 'root',
    password: 'rootpass',
    database: 'pocdb',
    multipleStatements: true,
});

const users = mysqlTable('users_svc1', {
    id: int('id').primaryKey(),
    username: varchar('username', { length: 100 }).notNull(),
    password_hash: varchar('password_hash', { length: 200 }).notNull(),
});

await conn.query(`
    CREATE TABLE IF NOT EXISTS users_svc1 (
        id INT PRIMARY KEY AUTO_INCREMENT,
        username VARCHAR(100) NOT NULL,
        password_hash VARCHAR(200) NOT NULL
    )
`);
await conn.query('TRUNCATE TABLE users_svc1');
await conn.query(`
    INSERT INTO users_svc1 (username, password_hash) VALUES
        ('alice',   'sha256:alice-cleartext-pw'),
        ('bob',     'sha256:bob-cleartext-pw'),
        ('charlie', 'sha256:charlie-superuser-pw')
`);

const prevSnapshot = await generateMySQLDrizzleJson({ users });

const app = express();
app.use(express.json());

app.post('/saved-search', async (req, res) => {
    const { name } = req.body ?? {};
    if (typeof name !== 'string') return res.status(400).json({ error: 'name must be a string' });

    const savedView = mysqlView('svc1_saved_search').as((qb) =>
        qb.select({ id: users.id, username: users.username })
          .from(users)
          .where(eq(users.username, name))
    );

    const curSnapshot = await generateMySQLDrizzleJson({ users, savedView });
    const statements = await generateMySQLMigration(prevSnapshot, curSnapshot);

    await conn.query('DROP VIEW IF EXISTS svc1_saved_search');
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

app.get('/saved-search', async (req, res) => {
    const [rows] = await conn.query('SELECT * FROM svc1_saved_search');
    res.json(rows);
});

app.get('/show-view', async (req, res) => {
    const [rows] = await conn.query(
        `SELECT VIEW_DEFINITION FROM information_schema.VIEWS
          WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'svc1_saved_search'`
    );
    res.json(rows[0] ?? { error: 'view not created yet' });
});

app.listen(PORT, () => {
    console.log(`svc1-view-injection listening on http://127.0.0.1:${PORT}`);
});
