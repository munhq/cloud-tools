<img src="docs/brand/logo.svg" alt="cloud-tools" height="72">

[![MCP Registry](https://img.shields.io/badge/MCP%20Registry-io.github.munhq%2Fcloud--tools-000)](https://registry.modelcontextprotocol.io/v0/servers?search=cloud-tools)
[![Smithery](https://img.shields.io/badge/Smithery-munhq%2Fcloud--tools-7c3aed)](https://smithery.ai/servers/munhq/cloud-tools)
[![Glama](https://img.shields.io/badge/Glama-munhq%2Fcloud--tools-4f46e5)](https://glama.ai/mcp/servers/munhq/cloud-tools)

[![Install in Cursor](https://img.shields.io/badge/Install-Cursor-000?logo=cursor)](cursor://anysphere.cursor-deeplink/mcp/install?name=cloud-tools&config=eyJjb21tYW5kIjoibnB4IiwiYXJncyI6WyIteSIsIkBtdW5ocS9jbG91ZC10b29scyJdfQ==)
[![Install in VS Code](https://img.shields.io/badge/Install-VS%20Code-007ACC?logo=visualstudiocode)](vscode:mcp/install?%7B%22name%22%3A%22cloud-tools%22%2C%22command%22%3A%22npx%22%2C%22args%22%3A%5B%22-y%22%2C%22%40munhq%2Fcloud-tools%22%5D%7D)

Multi-cloud cost, inventory and waste analysis in Rust — exposed as an **MCP server** so an AI agent can query spend and waste directly, and as an **HTTP API** for everything else.

It reports spend and waste: idle instances, oversized nodes, previous-generation hardware, unattached resources, and commitments you are not using.

## Eight tools, one shape

Every tool takes `cloud` and nothing else it does not need. **Credentials never
appear in a tool call** — the server reads them from its own environment, so the
agent never handles a secret and never needs to be told one.

```json
{ "cloud": "aws" }
{ "cloud": "gcp" }
```

Start with `check_access`. It takes no arguments, contacts no cloud, and reports
which clouds this server can reach and what is missing for the ones it cannot.

| Tool | AWS | GCP | Cloudflare | OVH |
|---|:--:|:--:|:--:|:--:|
| `check_access` | reports configuration for all four | | | |
| `get_costs` | yes | needs a billing table | yes | yes |
| `compare_costs` | yes | needs a billing table | — | — |
| `get_inventory` | — | yes | yes | yes |
| `get_waste` | yes | yes | — | — |
| `get_commitments` | yes | yes | — | — |
| `get_recommendations` | — | yes | — | — |
| `get_cross_cloud_summary` | every cloud the server can reach | | | |

A dash is not a silent empty result. The tool answers, for example,
`waste analysis is not implemented for ovh; supported: aws, gcp`, so an agent
cannot read a gap as a clean bill.

### Reading a zero correctly

`get_waste` and `get_inventory` return a `coverage` field and an `errors` list.
A zero total means one of two entirely different things:

| coverage | meaning |
|---|---|
| `complete` | Nothing is wasted. |
| `PARTIAL — N API call(s) failed…` | **Part of the account could not be read.** |

A partial result is not a clean bill of health.

## Configuring the server

Credentials are read from the environment of the machine running cloud-tools.
Nothing is stored, and every call is read-only.

### AWS

Resolved in this order, first match winning:

1. `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`
2. `~/.aws/credentials`, profile from `AWS_PROFILE`, otherwise `[default]`
3. An ECS task role
4. An EC2 instance role

An SSO-only profile is not read directly. Export it first:
`aws configure export-credentials --profile <name> --format env`.

To scan a *different* account, pass a role to assume. A role ARN is not a
secret, so it stays an argument:

```json
{ "cloud": "aws", "target": { "role_arn": "arn:aws:iam::…:role/ReadOnly" } }
```

`CLOUD_TOOLS_AWS_ROLE_ARN` and `CLOUD_TOOLS_AWS_EXTERNAL_ID` set a default for
that, if every call should assume the same role.

`get_waste` reads EC2 instances, volumes, snapshots, AMIs, Elastic IPs, key
pairs and reserved instances; RDS; S3; Lambda; DynamoDB; ECS; ElastiCache; load
balancers; NAT gateways; CloudWatch log groups with no retention; and Compute
Optimizer. Idle and oversized come from CloudWatch CPU series, so they are
measured rather than guessed.

### GCP

Application Default Credentials — `gcloud auth application-default login` is
enough — or `GOOGLE_APPLICATION_CREDENTIALS` pointing at a service-account file.

| Variable | Purpose |
|---|---|
| `CLOUD_TOOLS_GCP_PROJECTS` | Comma-separated project IDs to query |
| `CLOUD_TOOLS_GCP_BILLING_TABLE` | BigQuery billing export, `project.dataset.table` |

Projects can also be chosen per call with `target.project_ids`, which is how one
agent scans several.

`billing_table` matters. Google publishes no per-service spend API, so real
costs come from the BigQuery billing export. Without it, `get_costs` falls back
to the Budgets API and labels the result `"source": "budgets"` with a note
saying these are budget amounts, not spend. `compare_costs` requires it outright.

### Cloudflare

```
CLOUDFLARE_API_TOKEN     a token with read access to account resources
CLOUDFLARE_ACCOUNT_ID
```

### OVH

```
OVH_APPLICATION_KEY
OVH_APPLICATION_SECRET
OVH_CONSUMER_KEY
OVH_ENDPOINT             ovh-eu (default), ovh-us or ovh-ca
```

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

As an MCP server it plugs into any MCP-capable agent. The agent calls the tools above directly and reasons over the results.

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

**Permissions.** Read-only is sufficient for every tool. All eight declare
`readOnlyHint: true`, and nothing in this server creates, modifies or deletes a
cloud resource.

**Contact.** hello@munhq.com. The canonical version of this policy is at
https://munhq.com/privacy/cloud-tools.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
