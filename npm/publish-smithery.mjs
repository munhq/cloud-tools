#!/usr/bin/env node
// Publish a Smithery stdio release: the listing, its config schema, and the full
// tool card.
//
// A listing published by hand is a listing that describes an old version
// forever, so this is a script, and it reads its facts from the same files the
// npm package and server.json do.
//
// Three things the API requires that its error messages do not say plainly:
//   - `bundle` is required for a stdio release. Without it: 400 "Missing
//     required part: bundle".
//   - `payload` is a form field holding JSON *as a string*, not a file upload.
//   - `serverCard.serverInfo` requires BOTH name and version. Omitting version
//     returns 400 "Invalid input: expected string, received undefined", which
//     names no field at all.
//
// The homepage is munhq.com/products, NOT the GitHub URL. Smithery verifies
// ownership with a DNS TXT record on the homepage domain, and no TXT record can
// ever be added to github.com.
//
// Usage:
//   SMITHERY_API_KEY=… node npm/publish-smithery.mjs \
//     --card card.json --bundle cloud-tools-0.2.0.mcpb
// Optional: --namespace (default munhq), --server (default cloud-tools), --dry-run.
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const pkg = JSON.parse(readFileSync(path.join(here, 'package.json'), 'utf8'));
const server = JSON.parse(readFileSync(path.join(root, 'server.json'), 'utf8'));

const argv = process.argv.slice(2);
const argOf = (n, d = null) => {
  const i = argv.indexOf(n);
  return i === -1 ? d : argv[i + 1];
};
const has = (n) => argv.includes(n);

const namespace = argOf('--namespace', 'munhq');
const name = argOf('--server', 'cloud-tools');
const cardPath = argOf('--card');
const bundlePath = argOf('--bundle');
const dryRun = has('--dry-run');

const die = (msg) => {
  process.stderr.write(`publish-smithery: ${msg}\n`);
  process.exit(1);
};

if (!cardPath || !bundlePath) die('need --card <tools.json> and --bundle <file.mcpb>');
const key = process.env.SMITHERY_API_KEY;
if (!key && !dryRun) {
  die('SMITHERY_API_KEY is not set. It is the bearer token from smithery.ai; nothing else authenticates this API.');
}

const card = JSON.parse(readFileSync(cardPath, 'utf8'));
const tools = card.tools || card.result?.tools || [];
if (!tools.length) die(`${cardPath} declares no tools — refusing to publish a listing with an empty tool card`);

// Mirrors smithery.yaml. No credential is collected here: cloud-tools reads each
// cloud from that cloud's own mechanism in the environment of the machine the
// server runs on, and a stdio launcher runs it on the user's own machine.
const configSchema = {
  type: 'object',
  properties: {
    mode: {
      type: 'string',
      title: 'Server mode',
      description:
        'MCP over stdio, or the HTTP API. The binary reads CLOUD_TOOLS_MODE and defaults to mcp, so an MCP client needs no configuration at all.',
      enum: ['mcp', 'http'],
      default: 'mcp',
    },
  },
  required: [],
};

const payload = {
  type: 'stdio',
  runtime: 'node',
  configSchema,
  serverCard: {
    serverInfo: {
      name,
      title: server.title,
      version: pkg.version,
      description: server.description,
      // The verification TXT record is checked against this domain.
      websiteUrl: 'https://munhq.com/products',
    },
    tools,
  },
};

const qualified = encodeURIComponent(`${namespace}/${name}`);
const url = `https://api.smithery.ai/servers/${qualified}/releases`;

if (dryRun) {
  process.stdout.write(
    `dry run: PUT ${url}\n  version ${pkg.version}, ${tools.length} tools, bundle ${path.basename(bundlePath)}\n`
  );
  process.exit(0);
}

const form = new FormData();
// A string field. Sent as a file part, the API answers "expected string,
// received undefined" and names nothing.
form.append('payload', JSON.stringify(payload));
form.append(
  'bundle',
  new Blob([readFileSync(bundlePath)], { type: 'application/zip' }),
  path.basename(bundlePath)
);

const res = await fetch(url, { method: 'PUT', headers: { authorization: `Bearer ${key}` }, body: form });
const text = await res.text();
if (!res.ok) die(`PUT ${url} -> HTTP ${res.status}: ${text}`);

let body;
try {
  body = JSON.parse(text);
} catch {
  die(`unparseable response: ${text.slice(0, 200)}`);
}
process.stdout.write(
  `published ${namespace}/${name} ${pkg.version}: status=${body.status} ` +
    `deployment=${body.deploymentId} url=${body.mcpUrl}\n` +
    `  ${tools.length} tools on the card\n`
);
for (const w of body.warnings || []) process.stderr.write(`  warning: ${w}\n`);
if (body.status && !['SUCCESS', 'QUEUED', 'WORKING'].includes(body.status)) {
  die(`release status is ${body.status}`);
}
