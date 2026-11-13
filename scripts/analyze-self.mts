import { readFileSync } from 'node:fs';

const d = JSON.parse(readFileSync(process.argv[2] ?? '.aegis/self4.json', 'utf8'));
console.log('score:', d.score.score, d.score.grade, '| findings:', d.findings.length);
const by = {};
for (const f of d.findings) by[f.severity] = (by[f.severity] || 0) + 1;
console.log('by severity:', JSON.stringify(by));
const rules = {};
for (const f of d.findings) rules[f.ruleId] = (rules[f.ruleId] || 0) + 1;
console.log('top rules:', Object.entries(rules).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([k, v]) => `${k}:${v}`).join(', '));
console.log('');
console.log('files:', [...new Set(d.findings.map((f) => f.location.file))].slice(0, 12).join(', '));
console.log('');
for (const id of Object.entries(rules).sort((a, b) => b[1] - a[1]).slice(0, 5)) {
  const f = d.findings.find((x) => x.ruleId === id[0]);
  console.log(`${id[0]} (${id[1]}) ${f.severity} @ ${f.location.file}:${f.location.line}`);
  console.log('   ' + String(f.evidence).split('\n')[0].slice(0, 120));
}