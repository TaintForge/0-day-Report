# Title

Path traversal and link-following in `drizzle-orm` `readMigrationFiles` via attacker-controlled `_journal.json` `tag`, leading to arbitrary SQL execution at migration time and arbitrary file read through MySQL syntax-error oracle

### Summary

`drizzle-orm/src/migrator.ts` reads `meta/_journal.json` from the configured migrations folder and, for every entry, concatenates `journalEntry.tag` into a `fs.readFileSync(`${migrationFolderTo}/${journalEntry.tag}.sql`)` call with no validation. `..` segments survive verbatim, so an attacker who can write (or partially influence) `_journal.json` can have the migrator read and execute a `.sql` file from anywhere on disk the application user can read.

A symlink variant turns the same primitive into an arbitrary-file-read primitive over HTTP. `fs.readFileSync` follows symlinks by default, and MySQL echoes the offending SQL into its syntax-error response, so a tag pointing at a `.sql` filename that is in fact a symlink to `/etc/passwd` returns the contents of `/etc/passwd` in the JSON error returned to the attacker.

`readMigrationFiles` is imported by every dialect runner (`mysql2`, `node-postgres`, `neon-serverless`, `better-sqlite3`, `libsql`, `aws-data-api`). All inherit the same bug.

### Details

In `targets/drizzle-orm/drizzle-orm/src/migrator.ts:39-42`:

```ts
for (const journalEntry of journal.entries) {
    const migrationPath = `${migrationFolderTo}/${journalEntry.tag}.sql`;
    try {
        const query = fs.readFileSync(`${migrationFolderTo}/${journalEntry.tag}.sql`).toString();
        /* ... executes `query` against the live database via the dialect's session ... */
    } catch {
        throw new Error(`No file ${migrationPath} found in ${migrationFolderTo} folder`);
    }
}
```

`journalEntry.tag` is read directly from JSON. `path.resolve` is never called, no allowlist regex is applied, and the resolved path is never compared against `migrationFolderTo`. A tag of `../svc4-payload` resolves to `/tmp/svc4-migrations/../svc4-payload.sql`, which the OS normalises to `/tmp/svc4-payload.sql`.

There are two distinct attacker primitives.

The traversal primitive uses a `..`-bearing tag. It executes whatever `.sql` the attacker also planted at the resolved location. Typical chain: the attacker has a less-trusted write target (a world-writable `/tmp`, a CI scratch directory, a malicious npm package's `lib/`) and a separate write primitive into the migrations folder for `_journal.json`.

The symlink primitive uses a `..`-free tag that names a normal-looking `.sql` filename inside the migrations folder, but that filename is in fact a symlink to an arbitrary path. This bypasses any regex allowlist of the form `^[A-Za-z0-9_-]+$`. The attacker plants `migrations/leak.sql` as a symlink to `/etc/passwd` and a `_journal.json` entry with `tag: "leak"`. `fs.readFileSync` follows the symlink, MySQL fails to parse `/etc/passwd` as SQL, and the syntax-error response echoes the file contents back to the HTTP client.

The catch block re-throws an error string that includes the offending path and (depending on dialect adapter) the database's syntax-error response. With MySQL, the syntax-error response includes the leading bytes of the file content, so even a failed read produces a file-content oracle.

### PoC

Runnable service at `poc/services/svc4-migrator-traversal/`. The service exposes `POST /admin/run-migrations` that calls `drizzle-orm/mysql2/migrator`'s `migrate(db, { migrationsFolder })`. The `/attacker/plant` and `/attacker/plant-symlink` endpoints simulate a separate write primitive an attacker would already have in a realistic scenario (a separate vulnerability, a malicious npm package's migrations folder, or a compromised dev or CI host).

```js
app.post('/admin/run-migrations', async (req, res) => {
    await migrate(db, { migrationsFolder: MIGRATIONS_FOLDER });
    res.json({ ok: true });
});
```

Traversal primitive (arbitrary SQL execution):

```
cd poc/services
docker compose up -d mysql
cd svc4-migrator-traversal && npm install && node index.js   # listens on :3004

curl -X POST http://127.0.0.1:3004/admin/run-migrations
curl http://127.0.0.1:3004/admin/audit

curl -X POST http://127.0.0.1:3004/attacker/plant
curl http://127.0.0.1:3004/admin/journal

curl -X POST http://127.0.0.1:3004/admin/run-migrations

curl http://127.0.0.1:3004/admin/audit
curl http://127.0.0.1:3004/admin/users
```

After the attacker plants, `_journal.json` contains an entry with `tag: "../svc4-payload"`. The migrator resolves it to `/tmp/svc4-payload.sql` and executes its contents. The audit log gains an `ATTACKER WAS HERE` row, and the MySQL user `pwn4` is created.

Symlink primitive (arbitrary file read via syntax-error oracle):

```
curl -X POST http://127.0.0.1:3004/attacker/plant-symlink
curl -X POST http://127.0.0.1:3004/admin/run-migrations
```

The response:

```
{"error":"Error: Failed query: root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n..."}
```

The exact bytes of `/etc/passwd` arrive in the JSON error returned to the attacker. The tag `leak` would pass any reasonable regex allowlist.

### Impact

Two impact classes.

Arbitrary SQL execution against the production database at migrate time. Any application that exposes a migration runner (an admin endpoint, a CLI script triggered by deploy hooks, a startup-time `await migrate(...)`) becomes an arbitrary-SQL primitive when the attacker can write `_journal.json` plus one additional file. In a typical deployment, that means data exfiltration, data destruction, privilege escalation inside MySQL (`CREATE USER` / `GRANT`), or pivoting via UDFs and `SELECT ... INTO OUTFILE` to the host.

Arbitrary file read over HTTP. The symlink variant turns the migration runner into a generic file-read primitive for any path the migration process can read: `/etc/passwd`, `/proc/self/environ` (process environment, including secrets), `/run/secrets/*` (Docker and Kubernetes secrets), `.env` files mounted into the container, kubelet service-account tokens at `/var/run/secrets/kubernetes.io/serviceaccount/token`, and so on.

A related vector is the malicious-migrations-folder primitive. An npm package ships a `migrations/_journal.json` whose tags traverse back into the package's own `lib/` (or `/tmp/` after a postinstall hook). When the consumer calls `migrate(db, { migrationsFolder: './node_modules/<pkg>/migrations' })`, the package author chooses which SQL the consumer's database executes.

The same `readMigrationFiles` function is imported by every dialect's migrator, so the bug applies to MySQL, Postgres, SQLite, libsql, Neon, and AWS Data API consumers alike.

### Affected products

Ecosystem: npm.
Package name: `drizzle-orm`.
Affected versions: `<= 0.45.3` (`src/migrator.ts`).
Patched versions: none at time of report.

### Severity

CVSS 3.1 vector: `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` (score 6.4, Medium).

`AC:H` reflects that the attacker must obtain a write primitive into the migrations folder, or supply a malicious migrations folder via package distribution. `PR:H` reflects that the SQL execution happens with the privileges of the migration database account, which is typically a high-privilege schema-owner role.

### Weaknesses

CWE-22: Improper Limitation of a Pathname to a Restricted Directory (Path Traversal).
CWE-59: Improper Link Resolution Before File Access (Link Following) for the symlink variant.

### Fix

A regex allowlist alone is not sufficient because the symlink variant uses a tag that passes any reasonable allowlist. Combine an allowlist with `realpathSync` plus a boundary check.

```ts
import path from 'node:path';
import fs from 'node:fs';

const folderReal = fs.realpathSync(migrationFolderTo);
for (const journalEntry of journal.entries) {
    if (!/^[A-Za-z0-9_-]+$/.test(journalEntry.tag)) {
        throw new Error(`Invalid migration tag: ${journalEntry.tag}`);
    }
    const candidate = path.join(folderReal, `${journalEntry.tag}.sql`);
    const real = fs.realpathSync(candidate);
    if (!real.startsWith(folderReal + path.sep)) {
        throw new Error(`Migration file escapes folder: ${journalEntry.tag}`);
    }
    const query = fs.readFileSync(real).toString();
    /* ... */
}
```

The allowlist blocks `..` and weird filenames. `realpathSync` plus the boundary check blocks the symlink variant. Both are required.
