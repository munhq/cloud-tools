# @munhq/cloud-tools

Multi-cloud cost, inventory and waste analysis over MCP — what you spend by service, region and account, and what is idle, oversized, previous-generation, unattached or a commitment you are not consuming. AWS, GCP, Cloudflare and OVH, each behind that cloud's own credential mechanism. Thirteen tools, and every finding carries the utilisation evidence behind it.

```
npx -y @munhq/cloud-tools
```

No account, no API key, no configuration.

## Add it to a client

Claude Code:

```
claude mcp add cloud-tools -- npx -y @munhq/cloud-tools
```

Anything that reads a JSON config (Claude Desktop, Cursor, Windsurf, Zed, Cline):

```json
{
  "mcpServers": {
    "cloud-tools": {
      "command": "npx",
      "args": [
        "-y",
        "@munhq/cloud-tools"
      ]
    }
  }
}
```

## Why this is an npm package when the server is not JavaScript

cloud-tools is a compiled binary. This package is a small wrapper: on install it resolves the release asset for your platform, verifies it against the `SHA256SUMS` published beside it, caches it under `~/.cache/cloud-tools/bin/cloud-tools-<version>`, and executes it. `CLOUD_TOOLS_BIN` overrides everything, for a local build; `PATH` is deliberately not searched, because this package declares one version to the MCP registry.

Source, the other install paths and the full tool list: **https://github.com/munhq/cloud-tools**
