import { Pool } from "pg";
import { brandRegistry, legitimatePatterns, scamTemplates } from "../packages/risk-engine/src/knowledge.js";

const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) {
  process.stderr.write("Usage: npm run seed (requires DATABASE_URL pointing at a migrated database)\n");
  process.exitCode = 1;
} else {
  const pool = new Pool({ connectionString: databaseUrl, max: 1 });
  try {
    for (const template of scamTemplates) {
      await pool.query(
        `INSERT INTO scam_templates (id, scam_type, language, phrase, source)
         VALUES ($1, $2, $3, $4, 'self-authored')
         ON CONFLICT (id) DO UPDATE SET scam_type = EXCLUDED.scam_type, language = EXCLUDED.language, phrase = EXCLUDED.phrase`,
        [template.id, template.scamType, template.language, template.phrase]
      );
    }
    for (const brand of brandRegistry) {
      await pool.query(
        `INSERT INTO brand_registry (name, aliases, official_domains, sector)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (name) DO UPDATE SET aliases = EXCLUDED.aliases, official_domains = EXCLUDED.official_domains, sector = EXCLUDED.sector, updated_at = now()`,
        [brand.name, brand.aliases, brand.officialDomains, brand.sector]
      );
    }
    for (const pattern of legitimatePatterns) {
      await pool.query(
        `INSERT INTO legitimate_patterns (id, description, patterns)
         VALUES ($1, $2, $3)
         ON CONFLICT (id) DO UPDATE SET description = EXCLUDED.description, patterns = EXCLUDED.patterns, updated_at = now()`,
        [pattern.id, pattern.description, pattern.patterns]
      );
    }
    process.stdout.write(`Seeded ${scamTemplates.length} templates, ${brandRegistry.length} brands and ${legitimatePatterns.length} legitimate patterns.\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "Seed failed"}\n`);
    process.exitCode = 1;
  } finally { await pool.end(); }
}
