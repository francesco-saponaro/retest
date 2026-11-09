import { sql } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { rows, testDb, type TestDb } from "./helpers.js";

let t: TestDb;

beforeAll(async () => {
  t = await testDb();
});

afterAll(async () => {
  await t.close();
});

describe("migrations", () => {
  it("create the five tables and the imports table", async () => {
    const tables = await rows<{ table_name: string }>(
      t.db,
      sql`select table_name from information_schema.tables where table_schema = 'public' and table_name not like '__drizzle%' order by table_name`,
    );
    expect(tables.map((r) => r.table_name)).toEqual(["assessments", "assets", "audit_log", "evidence", "findings", "imports"]);
  });

  it("can be run twice without changing anything", async () => {
    await t.migrate();
    const applied = await rows<{ n: number }>(t.db, sql`select count(*)::int as n from drizzle.__drizzle_migrations`);
    expect(applied[0]!.n).toBe(1);
  });

  it("deletes a finding's evidence and audit lines with the finding, and a finding with its asset", async () => {
    const now = new Date().toISOString();
    await t.db.execute(sql`insert into assessments (id, owner_id, name, scope, phase, status, created_at, updated_at)
      values ('a1', 'u1', 'Lab', '{"targets":["127.0.0.1"],"exclusions":[],"authorizedBy":"me"}', 'scope', 'draft', ${now}, ${now})`);
    await t.db.execute(sql`insert into assets (id, assessment_id, kind, name, in_scope, tags) values ('as1', 'a1', 'host', '127.0.0.1', true, '[]')`);
    await t.db.execute(sql`insert into findings (id, assessment_id, asset_id, title, scope, impact, risk, severity, fix, phase, status, sources, mappings, created_at, updated_at)
      values ('f1', 'a1', 'as1', 'Open port', 'tcp/22', 'none', '{"severity":"info"}', 'info', 'none', 'recon', 'open', '[]', '{}', ${now}, ${now})`);
    await t.db.execute(sql`insert into evidence (id, finding_id, kind, content, redacted) values ('e1', 'f1', 'note', 'seen', false)`);
    await t.db.execute(sql`insert into audit_log (assessment_id, finding_id, actor, action, field, from_value, to_value, at) values ('a1', 'f1', 'u1', 'phase', 'phase', 'recon', 'assessment', ${now})`);
    await t.db.execute(sql`delete from assets where id = 'as1'`);
    const count = async (table: string) => (await rows<{ n: number }>(t.db, sql`select count(*)::int as n from ${sql.identifier(table)}`))[0]!.n;
    expect([await count("findings"), await count("evidence"), await count("audit_log")]).toEqual([0, 0, 0]);
  });

  it("keys an asset by (assessment, id), so two assessments can hold the same host", async () => {
    const now = new Date().toISOString();
    await t.db.execute(sql`insert into assessments (id, owner_id, name, scope, phase, status, created_at, updated_at)
      values ('a3', 'u1', 'Third', '{"targets":["127.0.0.1"],"exclusions":[],"authorizedBy":"me"}', 'scope', 'draft', ${now}, ${now})`);
    await t.db.execute(sql`insert into assets (id, assessment_id, kind, name, in_scope, tags) values ('asset-host-127-0-0-1', 'a1', 'host', '127.0.0.1', true, '[]')`);
    await t.db.execute(sql`insert into assets (id, assessment_id, kind, name, in_scope, tags) values ('asset-host-127-0-0-1', 'a3', 'host', '127.0.0.1', true, '[]')`);
    await expect(t.db.execute(sql`insert into assets (id, assessment_id, kind, name, in_scope, tags) values ('asset-host-127-0-0-1', 'a3', 'host', 'again', true, '[]')`)).rejects.toThrow();
  });

  it("refuses a finding on an asset of another assessment", async () => {
    const now = new Date().toISOString();
    await t.db.execute(sql`insert into assessments (id, owner_id, name, scope, phase, status, created_at, updated_at)
      values ('a2', 'u1', 'Other', '{"targets":["10.0.0.1"],"exclusions":[],"authorizedBy":"me"}', 'scope', 'draft', ${now}, ${now})`);
    await t.db.execute(sql`insert into assets (id, assessment_id, kind, name, in_scope, tags) values ('as2', 'a2', 'host', '10.0.0.1', true, '[]')`);
    await expect(
      t.db.execute(sql`insert into findings (id, assessment_id, asset_id, title, scope, impact, risk, severity, fix, phase, status, sources, mappings, created_at, updated_at)
      values ('f2', 'a1', 'as2', 'Open port', 'tcp/22', 'none', '{"severity":"info"}', 'info', 'none', 'recon', 'open', '[]', '{}', ${now}, ${now})`),
    ).rejects.toThrow();
  });
});
