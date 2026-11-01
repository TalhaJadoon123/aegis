/**
 * Generate a CycloneDX SBOM for the published package.
 *
 * `npm sbom` reads the working tree's `node_modules`, which for this repository
 * contains dev-only tooling (TypeScript, optional OpenTelemetry packages) that
 * is *not* shipped. That produces an SBOM describing the build machine rather
 * than the artifact. Because the published package has zero dependencies, the
 * correct SBOM is small and can be derived from the publish manifest plus the
 * tarball's hashes.
 *
 * Usage: node --experimental-strip-types scripts/sbom.mts [tarball]
 */

import { createHash, randomUUID } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';

interface PublishManifest {
  name: string;
  version: string;
  description?: string;
  license?: string;
  author?: string;
  homepage?: string;
  repository?: { url?: string };
  bugs?: { url?: string };
  dependencies?: Record<string, string>;
}

const root = process.cwd();
const pkg = JSON.parse(readFileSync(join(root, 'aegis.package.json'), 'utf8')) as PublishManifest;

const defaultTarball = join('dist', `talhajadoon123-aegis-${pkg.version}.tgz`);
const tarball = process.argv[2] ?? defaultTarball;

const hashes: Array<{ alg: string; content: string }> = [];
if (existsSync(join(root, tarball))) {
  const bytes = readFileSync(join(root, tarball));
  hashes.push({ alg: 'SHA-256', content: createHash('sha256').update(bytes).digest('hex') });
  hashes.push({ alg: 'SHA-512', content: createHash('sha512').update(bytes).digest('base64') });
} else {
  process.stderr.write(`warning: ${tarball} not found; SBOM will omit artifact hashes\n`);
}

const purl = `pkg:npm/${encodeURIComponent(pkg.name).replace(/%2F/g, '/')}@${pkg.version}`;
const ref = `${pkg.name}@${pkg.version}`;

const dependencies = Object.keys(pkg.dependencies ?? {});

const externalReferences: Array<{ type: string; url: string }> = [];
if (pkg.repository?.url) externalReferences.push({ type: 'vcs', url: pkg.repository.url });
if (pkg.homepage) externalReferences.push({ type: 'website', url: pkg.homepage });
if (pkg.bugs?.url) externalReferences.push({ type: 'issue-tracker', url: pkg.bugs.url });

const bom = {
  $schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json',
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    lifecycles: [{ phase: 'build' }],
    tools: [{ vendor: 'Aegis', name: 'aegis-sbom', version: pkg.version }],
    component: {
      'bom-ref': ref,
      type: 'application',
      name: pkg.name,
      version: pkg.version,
      description: pkg.description,
      author: pkg.author,
      purl,
      ...(hashes.length ? { hashes } : {}),
      licenses: pkg.license ? [{ license: { id: pkg.license } }] : [],
      externalReferences,
      properties: [
        { name: 'aegis:tarball', value: tarball },
        { name: 'aegis:runtime-dependencies', value: String(dependencies.length) },
      ],
    },
  },
  components: dependencies.map((name) => ({
    type: 'library',
    name,
    version: 'unknown',
    scope: 'required',
  })),
  dependencies: [{ ref, dependsOn: [] }],
};

const out = join(root, 'dist', 'sbom.json');
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(bom, null, 2) + '\n', 'utf8');

process.stdout.write(
  `SBOM written to ${out}\n` +
    `  component: ${ref}\n` +
    `  runtime dependencies: ${dependencies.length}\n` +
    `  hashes: ${hashes.map((h) => h.alg).join(', ') || 'none'}\n`,
);