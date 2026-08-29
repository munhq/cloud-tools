<img src="docs/brand/logo.svg" alt="cloud-tools" height="72">

Multi-cloud cost, inventory and waste analysis in Rust — exposed as an **MCP server** so an AI agent can query spend and waste directly, and as an **HTTP API** for everything else.

It reports spend and waste: idle instances, oversized nodes, previous-generation hardware, unattached resources, and commitments you are not using.

## What each cloud needs, and what it gives back

Credentials are per cloud, and they are passed differently per cloud. Nothing is
stored, and every call is read-only.

| Cloud | What you provide | Where it goes |
|---|---|---|
| AWS | Credentials on the machine, plus a `role_arn` on every call | The server assumes that role |
| GCP | `project_ids`, and ADC or a service-account JSON | Per call |
| Cloudflare | `api_token` and `account_id` | Per call |
| OVH | `app_key`, `app_secret`, `consumer_key` | Per call |

### AWS — 5 tools

AWS is the one cloud that does not read your credentials directly. The server
resolves its own credentials first, then calls `sts:AssumeRole` on the `role_arn`
you pass with every call. The role must trust the identity the server is running
as. This suits a service scanning many accounts; for your own single account you
still need a role in it that trusts you.

Credentials are resolved in this order, and the first that answers wins:

1. `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`.
2. `~/.aws/credentials`, profile from `AWS_PROFILE`, otherwise `[default]`.
3. An ECS task role.
4. An EC2 instance role.

An SSO-only profile is not read. Export it first:
`aws configure export-credentials --profile <name> --format env`.

| Tool | Returns |
|---|---|
| `get_aws_costs` | Spend by service over a date range, sorted by cost |
| `compare_aws_costs` | This month against last, over identical day windows, so a partial month does not read as a fall |
| `get_aws_data_transfer` | Transfer cost by usage type over 30 days: internet egress, cross-AZ, inter-region |
| `get_aws_savings_plans` | Utilisation of what you committed to, coverage of what is eligible, and the saving a further commitment would give |
| `find_aws_waste` | Every finding below, with the monthly cost of each |

`find_aws_waste` reads EC2 instances, volumes, snapshots, AMIs, Elastic IPs,
key pairs and reserved instances; RDS instances; S3 buckets; Lambda functions;
DynamoDB tables; ECS services; ElastiCache clusters; load balancers; NAT
gateways; CloudWatch log groups with no retention; and Compute Optimizer. It
takes CPU series from CloudWatch for EC2 and RDS, so idle and oversized are
measured rather than guessed, and it reads Organizations to name the account.

Not available over MCP: a resource inventory, cost split per account, and the
organisation-wide scan. All three exist, on the HTTP API only.

### GCP — 3 tools

Application Default Credentials by default, so `gcloud auth application-default
login` is enough. Pass `service_account_json` instead to use a service account.
`project_ids` is required and takes a list.

| Tool | Returns |
|---|---|
| `get_gcp_inventory` | GCE instances, disks, addresses, snapshots, forwarding rules, GKE clusters with node pools, Cloud SQL, Cloud Functions, Cloud Run, GCS buckets, Cloud NAT, Cloud IDS, Artifact Registry, VPN gateways, subnets, PSC endpoints and Cloud Logging ingestion — with a per-project summary |
| `find_gcp_waste` | Idle and oversized instances by CPU, stopped instances, orphaned disks, unattached addresses, snapshots over 90 days, idle Cloud SQL, GKE clusters with no nodes, Cloud Functions and Cloud Run with no invocations, buckets with no lifecycle rule, and expiring committed use discounts |
| `get_gcp_recommendations` | The Recommender API across every zone and region: idle VMs, rightsizing, idle disks and addresses, idle and oversized Cloud SQL |

Not available over MCP: **cost and billing**. `gcp/billing.rs` implements both,
and only the HTTP API exposes them. So GCP answers what you have and what is
wasted, but not what you spend.

### Cloudflare — 2 tools

An API token with read access to account resources, and the account ID.

| Tool | Returns |
|---|---|
| `get_cloudflare_costs` | Subscriptions with prices, and zone plan costs |
| `get_cloudflare_inventory` | Zones with plan and price, DNS records per zone split proxied against dns-only, certificates with hosts and expiry, and Workers with invocation counts |

### OVH — 2 tools

An application key, an application secret and a consumer key. `endpoint`
defaults to `ovh-eu`; `ovh-us` and `ovh-ca` are the alternatives.

| Tool | Returns |
|---|---|
| `get_ovh_costs` | The 6 most recent invoices with amounts |
| `get_ovh_inventory` | Cloud instances, and active services with renewal dates and monthly cost |

### Across clouds — 1 tool

`get_cross_cloud_summary` takes credentials for GCP, OVH and Cloudflare, skips
any it is not given, and returns one report with a grand total. **It does not
include AWS**, which needs a role assumption the other three do not.

## Coverage is not symmetric

Worth knowing before you install, because the shape is uneven:

| | Cost | Inventory | Waste | Recommendations |
|---|---|---|---|---|
| AWS | yes | no | yes | Compute Optimizer, inside waste |
| GCP | no | yes | yes | yes |
| Cloudflare | yes | yes | no | no |
| OVH | yes | yes | no | no |

The gaps are gaps, not decisions. AWS inventory and GCP billing are both
implemented and reachable over the HTTP API; neither is wired to a tool.

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

## Status

Working and used against live AWS, GCP, Cloudflare and OVH accounts. The AWS and GCP analyzers are the most complete; Cloudflare and OVH cover cost and inventory but have fewer waste rules. Contributions adding provider coverage are welcome.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
