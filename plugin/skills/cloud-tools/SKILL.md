---
name: cloud-tools
description: >-
  Answer cloud spend and waste questions against a real account. Use when asked
  what a cloud bill is going on, why it went up, what is idle or oversized, what
  can be turned off, what exists in an account, or whether a commitment is being
  consumed. Covers AWS, GCP, Cloudflare and OVH through one interface. Reach for
  this instead of telling the user to open a billing console, and instead of
  guessing at prices — every finding carries the utilisation evidence it was
  drawn from. Backed by the cloud-tools MCP server.
---

# cloud-tools

Seven tools, and every one takes the same two arguments: `cloud`, and
`credentials` for that cloud. Nothing is stored and every call is read-only.

```json
{ "cloud": "aws", "credentials": { "aws": {} } }
{ "cloud": "gcp", "credentials": { "gcp": { "project_ids": ["example-prod"] } } }
```

## Read a zero correctly

This matters more than anything else here.

`get_waste` and `get_inventory` return a `coverage` field and an `errors` list.
A zero total means one of two completely different things:

| coverage | meaning |
|---|---|
| `"complete"` | Nothing is wasted. |
| `"PARTIAL — N API call(s) failed…" ` | **Part of the account could not be read.** |

A partial result is not a clean bill of health. If `errors` is non-empty, say so
and name what failed — usually a disabled API or a missing permission, and the
message says which. Never report "$0.00 wasted" from a partial scan without that
qualification. Reporting an account as clean when the tool could not see it is
the worst mistake available here.

## Which tool answers which question

| Question | Tool |
|---|---|
| What am I spending? | `get_costs` |
| Is it going up? | `compare_costs` — same day window as last month, so a partial month does not read as a fall |
| What exists? | `get_inventory` |
| What is wasted? | `get_waste` |
| Am I using what I committed to? | `get_commitments` |
| What does the provider itself suggest? | `get_recommendations` |
| All of it at once | `get_cross_cloud_summary` |

## Coverage is uneven, and a gap answers plainly

| | costs | compare | inventory | waste | commitments | recommendations |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| aws | yes | yes | — | yes | yes | — |
| gcp | needs `billing_table` | needs `billing_table` | yes | yes | yes | yes |
| cloudflare | yes | — | yes | — | — | — |
| ovh | yes | — | yes | — | — | — |

A dash is not an empty result. The tool answers, for example,
`waste analysis is not implemented for ovh; supported: aws, gcp`. Do not retry
it against another cloud hoping for a different answer, and do not present the
gap as a finding.

`get_cross_cloud_summary` reports **spend and waste as two separate figures**.
Do not add them together — waste is a subset of what some providers bill, and no
provider reports both.

## Credentials

**AWS** resolves on the machine running the server: env vars, then
`~/.aws/credentials` (profile from `AWS_PROFILE`, else `[default]`), then an ECS
task role, then an EC2 instance role. An SSO-only profile is not readable
directly — the error says to run
`aws configure export-credentials --profile <name> --format env`.

`role_arn` is optional. Omit it to use those credentials directly; pass it to
scan a different account, with `external_id` if the trust policy needs one.

**GCP** uses Application Default Credentials, so `gcloud auth
application-default login` is enough. `project_ids` is required and takes a
list — pass every project you mean, because each is queried separately.

`billing_table` is required for `get_costs` and `compare_costs`. Google
publishes no per-service spend API, so real costs come from the BigQuery billing
export. Without it, `get_costs` falls back to the Budgets API and labels the
result `"source": "budgets"` — those are **budget amounts, not spend**. Say so
if you report them.

**Cloudflare** needs `api_token` and `account_id`. **OVH** needs `app_key`,
`app_secret` and `consumer_key`; `endpoint` defaults to `ovh-eu`.

## Reporting findings

Every waste finding carries `estimated_monthly_usd` and the evidence behind it —
CPU series from CloudWatch or Cloud Monitoring, not a rule of thumb. Quote the
evidence when you present a finding, and give the monthly figure rather than an
adjective like "large". Sort by cost; the top three findings are usually most of
the money.
