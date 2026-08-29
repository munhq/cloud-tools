#!/usr/bin/env node
// The MCP server entry point: resolve the binary, then become it.
//
// `npx -y @munhq/cloud-tools` lands here. Every argument is passed straight through.
'use strict';

const { spawnSync } = require('child_process');
const { resolveBinary, log } = require('./resolve.js');

(async () => {
  let bin;
  try {
    bin = await resolveBinary();
  } catch (err) {
    log(`could not start: ${err.message}`);
    process.exit(1);
  }

  // The client speaks JSON-RPC over this process's stdio, so the child inherits
  // all three streams untouched.
  const args = process.argv.slice(2);

  const res = spawnSync(bin, args, { stdio: 'inherit' });
  if (res.error) {
    log(`failed to exec ${bin}: ${res.error.message}`);
    process.exit(1);
  }
  // Relay the child's fate exactly: a signal death must not look like exit 0.
  if (res.signal) process.kill(process.pid, res.signal);
  process.exit(res.status === null ? 1 : res.status);
})();
