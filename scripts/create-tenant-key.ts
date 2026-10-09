import { ScanRepository } from "../apps/api/src/repository.js";
import { generateApiKey } from "../packages/shared/src/crypto.js";

const name = process.argv.slice(2).join(" ").trim();
const databaseUrl = process.env.DATABASE_URL;
const pepper = process.env.API_KEY_PEPPER;
if (!name || !databaseUrl || !pepper || Buffer.byteLength(pepper) < 32) {
  process.stderr.write("Usage: npm run tenant:key -- <tenant name> (requires DATABASE_URL and API_KEY_PEPPER of at least 32 bytes)\n");
  process.exitCode = 1;
} else {
  const repository = new ScanRepository(databaseUrl);
  try {
    const tenantId = await repository.createTenant(name);
    const key = generateApiKey("test");
    await repository.createApiKey(tenantId, key, Buffer.from(pepper), ["scans:write"]);
    process.stdout.write(`Tenant ID: ${tenantId}\nAPI key (shown once): ${key}\n`);
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : "Tenant key creation failed"}\n`);
    process.exitCode = 1;
  } finally { await repository.close(); }
}
