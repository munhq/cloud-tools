<img src="docs/brand/logo.svg" alt="cloud-tools" height="72">

Multi-cloud cost, inventory and waste analysis in Rust — exposed as an **MCP server** so an AI agent can query spend and waste directly, and as an **HTTP API** for everything else.

It reports spend and waste: idle instances, oversized nodes, previous-generation hardware, unattached resources, and commitments you are not using.

## Seven tools, one shape

Every tool takes the same two arguments: `cloud`, and `credentials` for that
cloud. Nothing is stored, and every call is read-only.

```json
{ "cloud": "aws", "credentials": { "aws": {} } }
{ "cloud": "gcp", "credentials": { "gcp": { "project_ids": ["example-prod"] } } }
```

| Tool | AWS | GCP | Cloudflare | OVH |
|---|:--:|:--:|:--:|:--:|
| `get_costs` | yes | needs `billing_table` | yes | yes |
| `compare_costs` | yes | needs `billing_table` | — | — |
| `get_inventory` | — | yes | yes | yes |
| `get_waste` | yes | yes | — | — |
| `get_commitments` | yes | yes | — | — |
| `get_recommendations` | — | yes | — | — |
| `get_cross_cloud_summary` | all four at once; a cloud you omit is skipped | | | |

A dash is not a silent empty result. The tool answers, for example,
`waste analysis is not implemented for ovh; supported: aws, gcp`, so an agent
cannot read a gap as a clean bill.

Coverage is uneven because the analysis behind it is uneven. Waste rules for
Cloudflare and OVH would be guesses rather than measurements, so they are
absent rather than wrong. AWS inventory is the one gap that is only unbuilt: the
listing calls exist and `get_waste` already uses them.

## Credentials, per cloud

### AWS

Resolved on the machine running the server, in this order, first match winning:

1. `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
2. `~/.aws/credentials`, profile from `AWS_PROFILE`, otherwise `[default]`
3. An ECS task role
4. An EC2 instance role

An SSO-only profile is not read directly. Export it first:
`aws configure export-credentials --profile <name> --format env`.

```json
{ "aws": {} }                                                  // your own account
{ "aws": { "role_arn": "arn:aws:iam::…:role/ReadOnly" } }      // assume a role
{ "aws": { "role_arn": "…", "external_id": "…" } }             // …with an external ID
```

`role_arn` is optional. Give it to scan an account other than the one whose
credentials the server holds; omit it to use those credentials directly.

`get_waste` reads EC2 instances, volumes, snapshots, AMIs, Elastic IPs, key
pairs and reserved instances; RDS; S3; Lambda; DynamoDB; ECS; ElastiCache; load
balancers; NAT gateways; CloudWatch log groups with no retention; and Compute
Optimizer. Idle and oversized come from CloudWatch CPU series, so they are
measured rather than guessed.

### GCP

Application Default Credentials by default — `gcloud auth application-default
login` is enough. `project_ids` is required.

```json
{ "gcp": { "project_ids": ["example-prod", "example-dev"] } }
{ "gcp": { "project_ids": ["…"], "service_account_json": "{…}" } }
{ "gcp": { "project_ids": ["…"], "billing_table": "example.billing.gcp_billing_export_v1_XXXX" } }
```

`billing_table` matters. Google publishes no per-service spend API, so real
costs come from the BigQuery billing export. Without it, `get_costs` falls back
to the Budgets API and labels the result `"source": "budgets"` with a note
saying these are budget amounts, not spend. `compare_costs` requires it outright.

### Cloudflare

```json
{ "cloudflare": { "api_token": "…", "account_id": "…" } }
```

A token with read access to account resources.

### OVH

```json
{ "ovh": { "app_key": "…", "app_secret": "…", "consumer_key": "…", "endpoint": "ovh-eu" } }
```

`endpoint` defaults to `ovh-eu`; `ovh-us` and `ovh-ca` are the alternatives.

## Install

> **Not released yet.** The newest tag is `v0.1.0`, which shipped `.tar.gz`
> archives under the old asset names, and `@munhq/cloud-tools` is not on npm. The
> three commands below start working the moment `v0.2.0` is tagged. Until then,
> build from source: `cargo build --release`.


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

Working and used against live AWS, GCP, Cloudflare and OVH accounts. Waste
analysis exists for AWS and GCP only — Cloudflare and OVH have none at all, not
merely fewer rules, and `get_waste` says so rather than returning an empty list.
AWS has no inventory tool yet, though the listing calls behind one already exist.
Contributions adding provider coverage are welcome.

## Privacy Policy

cloud-tools collects nothing. There is no telemetry, no analytics and no
phone-home of any kind — verified by the fact that the only hosts in the source
are cloud provider APIs plus github.com, which the npm wrapper uses to download
the binary for your platform.

**What is collected.** Nothing. No account, no sign-up, no identifier.

**What is processed, and where.** Credentials you pass are used to sign requests
to your own cloud provider and are held in memory for the life of that call. The
server runs on your machine, so nothing is sent to munhq or to any third party.
The responses go back to the MCP client that asked for them and nowhere else.

**Storage and retention.** Nothing is written to disk and nothing is retained.
The one exception is the npm wrapper, which caches the downloaded binary under
`~/.cache/cloud-tools/bin/` so it is not re-fetched on every run. That cache
holds a program, never your data or your credentials.

**Logging.** Diagnostics go to stderr, which your MCP client captures.
Credentials are never logged. Error messages quote the provider's own response,
which may name a project, an account id or a resource — the same information the
tool was asked to report.

**Third-party sharing.** None. The only network destinations are the cloud APIs
of the providers whose credentials you supply:
AWS (`*.amazonaws.com`), Google Cloud (`*.googleapis.com`), Cloudflare
(`api.cloudflare.com`) and OVH (`*.api.ovh.com`, `api.us.ovhcloud.com`).

**Permissions.** Read-only is sufficient for every tool. All seven declare
`readOnlyHint: true`, and nothing in this server creates, modifies or deletes a
cloud resource.

**Contact.** hello@munhq.com. The canonical version of this policy is at
https://munhq.com/privacy/cloud-tools.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
