import { readFileSync } from 'node:fs';

const path = process.argv[2] ?? 'aegis.sarif';
const data = JSON.parse(readFileSync(path, 'utf8'));
const results = data?.runs?.[0]?.results ?? [];
const findings = results.length;
const criticals = results.filter((r: { level?: string }) => r.level === 'error').length;

process.stdout.write(`self-scan: ${findings} findings, ${criticals} at error level\n`);

const MAX_FINDINGS = 80;
const MAX_CRITICALS = 60;

if (findings > MAX_FINDINGS) {
  process.stderr.write(`self-scan regression: ${findings} findings (ceiling ${MAX_FINDINGS})\n`);
  process.exit(1);
}
if (criticals > MAX_CRITICALS) {
  process.stderr.write(`self-scan regression: ${criticals} criticals (ceiling ${MAX_CRITICALS})\n`);
  process.exit(1);
}