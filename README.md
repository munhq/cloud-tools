# cloud-tools

Multi-cloud cost, inventory and waste analysis in Rust — exposed as an **MCP server** so an AI agent can query spend and waste directly, and as an **HTTP API** for everything else.

It reports spend and waste: idle instances, oversized nodes, previous-generation hardware, unattached resources, and commitments you are not using.

## Tools

Four tools, each spanning every configured cloud:

| Tool | Answers |
|---|---|
| `cost` | What am I spending, broken down by service, region and account |
| `waste` | What is idle, oversized, previous-generation or unattached |
| `inventory` | What exists, across providers and accounts |
| `metrics` | Utilisation data behind the cost and waste findings |

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

Each finding carries the utilisation evidence behind it. The `metrics` tool exposes that evidence directly.

## Install

Prebuilt binaries for Linux and macOS, x86_64 and arm64, are attached to each
[release](https://github.com/munhq/cloud-tools/releases):

```bash
curl -sSL https://github.com/munhq/cloud-tools/releases/latest/download/cloud-tools-<version>-x86_64-unknown-linux-gnu.tar.gz | tar xz
./cloud-tools
```

## Running it

Built as a library (`cloud_tools`) with an optional binary. Two feature flags, both on by default:

- `mcp` — MCP server over stdio and streamable HTTP, via `rmcp`
- `http` — HTTP API via axum

```bash
cargo build --release
./target/release/cloud-tools            # MCP server on stdio
```

As an MCP server it plugs into any MCP-capable agent; the agent calls `cost`, `waste`, `inventory` and `metrics` directly and reasons over the results.

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
