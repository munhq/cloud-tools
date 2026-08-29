#!/usr/bin/env node
// Build the .mcpb bundle: the artefact Smithery requires for a stdio release,
// and the one Claude Desktop installs with a double click.
//
// `PUT /servers/{namespace}%2F{server}/releases` refuses a stdio release without
// a `bundle` part — it answers `Missing required part: bundle`.
//
// What goes in it, and what does not: the wrapper, not the binary. Six platforms
// of compiled server would make a bundle that is almost entirely dead weight for
// every user, so the bundle carries the same resolve-and-verify wrapper the npm
// package uses, and it fetches the one asset the host actually needs.
//
// Every fact here is read from npm/package.json and server.json. Nothing is
// typed twice: a description copied into this file is a description that goes
// stale the first time the real one is edited.
//
// Usage: node npm/build-mcpb.mjs [--card <tools.json>] [--out <file.mcpb>]
//   --card  a `tools/list` result captured from the real server, so the declared
//           tool list cannot drift from the code. Optional: without it the
//           bundle simply declares no tools.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(here, '..');
const pkg = JSON.parse(readFileSync(path.join(here, 'package.json'), 'utf8'));
const server = JSON.parse(readFileSync(path.join(root, 'server.json'), 'utf8'));

const argv = process.argv.slice(2);
const argOf = (name) => {
  const i = argv.indexOf(name);
  return i === -1 ? null : argv[i + 1];
};
// Resolved, because zip runs with cwd set to the staging directory: a relative
// --out would be created inside a temp dir that is deleted moments later, and
// zip simply answers "Could not create output file".
const out = path.resolve(argOf('--out') || path.join(root, `cloud-tools-${pkg.version}.mcpb`));
const cardPath = argOf('--card');

let tools = [];
if (cardPath) {
  const card = JSON.parse(readFileSync(cardPath, 'utf8'));
  const list = card.tools || card.result?.tools || [];
  tools = list.map((t) => ({ name: t.name, description: t.description || '' }));
}

const entry = path.basename(pkg.bin ? Object.values(pkg.bin)[0] : 'bin/cloud-tools-mcp.js');

const stage = mkdtempSync(path.join(tmpdir(), 'cloud-tools-mcpb-'));
try {
  mkdirSync(path.join(stage, 'server'));
  for (const f of [entry, 'resolve.js']) {
    copyFileSync(path.join(here, 'bin', f), path.join(stage, 'server', f));
  }
  // resolve.js reads ../package.json for the version whose release it downloads.
  // Keeping that layout means the bundle cannot disagree with the npm package
  // about which binary it wants.
  writeFileSync(
    path.join(stage, 'package.json'),
    JSON.stringify({ name: pkg.name, version: pkg.version, private: true }, null, 2) + '\n'
  );

  const manifest = {
    manifest_version: '0.3',
    name: 'cloud-tools',
    display_name: server.title,
    version: pkg.version,
    description: server.description,
    long_description: pkg.description,
    author: { name: 'munhq', url: 'https://github.com/munhq' },
    homepage: pkg.homepage,
    repository: { type: 'git', url: server.repository.url },
    license: pkg.license,
    keywords: pkg.keywords,
    // The bundle is what Claude Desktop installs, and its manifest is the only
    // place that install can get an icon from. Referenced by URL rather than
    // packed in, so the small bundle stays small.
    ...(server.icons?.length ? { icons: server.icons.map((i) => ({ src: i.src, size: i.sizes?.[0] })) } : {}),
    server: {
      type: 'node',
      entry_point: `server/${entry}`,
      mcp_config: { command: 'node', args: [`\${__dirname}/server/${entry}`] },
    },
    tools,
    tools_generated: false,
    compatibility: { platforms: ['darwin', 'win32', 'linux'], runtimes: { node: '>=18.0.0' } },
  };
  writeFileSync(path.join(stage, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');

  rmSync(out, { force: true });
  // zip, not a JS zip library: this runs on a release runner and in a terminal,
  // and both have it. A dependency here would be the only one in the package.
  execFileSync('zip', ['-qr', out, '.'], { cwd: stage });
} finally {
  rmSync(stage, { recursive: true, force: true });
}

const bytes = readFileSync(out);
process.stdout.write(
  `${path.basename(out)}  ${statSync(out).size} bytes  sha256=${createHash('sha256').update(bytes).digest('hex')}\n` +
    `  version ${pkg.version}, ${tools.length} tool(s) declared\n`
);
