<img src="docs/brand/logo.svg" alt="cloud-tools" height="72">

Multi-cloud cost, inventory and waste analysis in Rust — exposed as an **MCP server** so an AI agent can query spend and waste directly, and as an **HTTP API** for everything else.

It reports spend and waste: idle instances, oversized nodes, previous-generation hardware, unattached resources, and commitments you are not using.

## Tools

Thirteen tools. Each one names the cloud it queries, because the credentials
differ per cloud and an agent has to know which it is being asked for.

| Tool | Answers |
|---|---|
| `get_aws_costs` | AWS spend grouped by service for a date range |
| `compare_aws_costs` | Month over month, over identical day windows so a partial month does not read as a drop |
| `get_aws_data_transfer` | Data transfer cost by usage type: internet egress, cross-AZ, inter-region |
| `get_aws_savings_plans` | Savings Plans utilisation, coverage and what a further commitment would save |
| `find_aws_waste` | Idle and oversized EC2, stopped instances, orphaned volumes, unattached addresses |
| `get_gcp_inventory` | GCE instances, disks, addresses, snapshots and images across projects |
| `get_gcp_recommendations` | The GCP Recommender API: idle VMs, rightsizing, idle disks and addresses |
| `find_gcp_waste` | Idle and oversized GCE instances, stopped instances, unattached disks |
| `get_cloudflare_costs` | Subscriptions with prices, and zone plan costs |
| `get_cloudflare_inventory` | Zones, DNS records per zone, certificates, Workers |
| `get_ovh_costs` | Recent invoices with amounts |
| `get_ovh_inventory` | Cloud instances and active services, with renewal dates and monthly cost |
| `get_cross_cloud_summary` | One combined cost and waste report over every cloud you pass credentials for |

## Coverage

**AWS** — EC2, RDS, S3, Lambda, DynamoDB, ECS, ElastiCache, ELB, NAT Gateway, CloudWatch and CloudWatch Logs, Cost Explorer, the Pricing API with per-region pricing, Compute Optimizer, Organizations for multi-account scans, and Savings Plans analysis.

**GCP** — Compute, GKE (including per-pod), Cloud Run, Cloud SQL, Cloud Functions, Cloud NAT, Cloud VPN, Cloud IDS, Artifact Registry, Storage, Networking, Monitoring, Recommender, Committed Use Discounts, Resource Manager and Billing.

**Cloudflare** — zones, DNS, certificates, Workers, billing.

**OVH** — instances, services, billing.

Each provider sits behind its own auth module, so credentials follow that cloud's normal mechanism rather than a bespoke config format.

## Waste detection

The analyzers combine inventory with utilisation metrics rather than flagging on a single dimension:

- **Idle** — provisioned and running, no meaningful traffic or CPU over the window.
- **Oversized** — utilisation well below the instance class, with the right-size target named.
- **Previous generation** — same or better performance available cheaper on current hardware.
- **Unattached** — NAT gateways, load balancers and volumes with nothing behind them.
- **Commitment gaps** — Savings Plans and Committed Use Discounts you are paying for and not consuming.

Each finding carries the utilisation evidence behind it — the CPU and network
series the verdict was drawn from, not the verdict alone.

## Install

### As an MCP server

```bash
claude mcp add cloud-tools -- npx -y @munhq/cloud-tools
```

Anything that reads a JSON config — Claude Desktop, Cursor, Windsurf, Zed, Cline:

```json
{ "mcpServers": { "cloud-tools": { "command": "npx", "args": ["-y", "@munhq/cloud-tools"] } } }
```

The npm package is a small wrapper, because the server is a compiled binary and
not JavaScript. On install it resolves the release asset for your platform,
verifies it against the published `SHA256SUMS`, caches it under
`~/.cache/cloud-tools/bin/` and executes it.

### As a binary

Prebuilt binaries for Linux, macOS and Windows, x86_64 and arm64, are attached to
each [release](https://github.com/munhq/cloud-tools/releases). The script below
downloads the one for your machine and checks it against `SHA256SUMS`:

```bash
curl -sSL https://raw.githubusercontent.com/munhq/cloud-tools/main/install.sh | bash
```

Or take a single asset directly:

```bash
curl -fsSLO https://github.com/munhq/cloud-tools/releases/latest/download/cloud-tools-x86_64-linux
chmod +x cloud-tools-x86_64-linux
```

### As a container

```bash
docker run -i --rm \
  -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_REGION \
  munhq/cloud-tools
```

## Running it

Built as a library (`cloud_tools`) with an optional binary. Two feature flags, both on by default:

- `mcp` — MCP server over stdio and streamable HTTP, via `rmcp`
- `http` — HTTP API via axum

```bash
cargo build --release
./target/release/cloud-tools            # MCP server on stdio
```

As an MCP server it plugs into any MCP-capable agent. The agent calls the thirteen tools above directly and reasons over the results.

To embed it instead, depend on the library and turn the binary features off:

```toml
cloud-tools = { git = "https://github.com/munhq/cloud-tools", default-features = false }
```

## Credentials

Read from each provider's standard source — the AWS credential chain, GCP application-default credentials or a service-account JSON, a Cloudflare API token, OVH application keys. Nothing is stored by the tool. Read-only permissions are sufficient for every tool; nothing here mutates your infrastructure.

## Status

Working and used against live AWS, GCP, Cloudflare and OVH accounts. The AWS and GCP analyzers are the most complete; Cloudflare and OVH cover cost and inventory but have fewer waste rules. Contributions adding provider coverage are welcome.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
