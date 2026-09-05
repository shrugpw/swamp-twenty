---
name: twenty
description: >
  Task playbook for the @shrug/twenty model — driving a Twenty CRM instance over
  its REST v1 API and running the push_leads contact-form lead sink. Use when
  working with an @shrug/twenty model: first-run field provisioning
  (ensureLeadFields → introspectSchema), running push_leads (dryRun vs confirm),
  understanding the leadId idempotency contract and the emergency path, reading
  the pushRun audit via CEL, wiring the Twenty API token to a vault, or reasoning
  about Twenty's role/permission model (why the token can't manage RBAC and how
  emergency-record visibility is actually restricted). Triggers on "twenty",
  "twenty crm", "push_leads", "ensureLeadFields", "leadId", "lead sink",
  contact-form lead ingestion into Twenty, "isEmergency".
---

# @shrug/twenty — CRM model playbook

`@shrug/twenty` is one model type with two layers:

1. **A generic Twenty REST v1 surface** — read/create People, Companies,
   Opportunities, and Notes; look records up by an immutable `leadId` marker (or
   by composite `emails.primaryEmail` / `domainName` filters); introspect
   object/field metadata; and self-provision the custom fields the idempotency
   scheme needs.
2. **`push_leads`** — the single fan-out method (swamp repo rule 6) that ingests
   a batch of contact-form leads into Twenty in one execution, safely and
   idempotently.

Validated against Twenty **v2.38.1** (REST v1).

## Configuration (`globalArguments`)

- `baseUrl` — Twenty base URL, no trailing slash (e.g. `https://crm.example.com`).
- `apiToken` — **sensitive**; a Twenty REST bearer token. Resolve from a vault,
  never a literal: `${{ vault.get("twenty", "api-token") }}`. It is logged
  length-only and never snapshotted.
- `opportunityStage` — stage for new Opportunities (default `NEW`; Twenty's
  enum is `NEW, SCREENING, MEETING, PROPOSAL, CUSTOMER`).
- `emailDomainBlocklist` — consumer/free domains that never get a Company
  created/linked (replaces the built-in default when set).
- `emergencyRestrictedRole` — **documentation only** (see Permissions below); it
  is never used to make an API call.

Mint a token in Twenty under *Settings → API & Webhooks* (or, for a self-hosted
instance, the `workspace:generate-api-key` CLI in a dev/test build), then vault
it. The token inherits whatever **role** you assign the API key (see Permissions).

## First-run setup (do this once per workspace)

The `leadId`/`isEmergency` filters only work once the custom fields exist. Run:

```bash
swamp model method run <name> ensureLeadFields --input confirm=true
swamp model method run <name> introspectSchema
swamp data get <name> schema --json     # requiredFields all present:true
```

`ensureLeadFields` is **confirm-gated** because it mutates workspace object
metadata (`POST /rest/metadata/fields`). It creates, idempotently:

- `leadId` (TEXT) on **Person**, **Opportunity**, **Note** — the dedup marker.
- `isEmergency` (BOOLEAN) on **Person**, **Opportunity** — the emergency marker.

Already-present fields are skipped, so it is safe to re-run. Verify with
`introspectSchema` before trusting any `leadId` filter.

## `push_leads` — the lead sink

One method handles the whole batch internally — **do not** loop per-lead calls
(rule 6). Always plan with `dryRun` first; it does lookups + a plan and writes
nothing.

```bash
# Plan only — writes NOTHING.
swamp model method run <name> push_leads --input dryRun=true --input-file leads.json
# Real run.
swamp model method run <name> push_leads --input confirm=true --input-file leads.json
```

`leads.json` is `{ "leads": [ … ] }`. Each lead requires all of:
`id` (the `leadId` marker), `name`, `email`, `phone`, `message`, `contact_type`
(`individual` | `business` | `emergency`), `company`, `received_at` (ISO, FIFO
key), `status`, `geo`. `geo` is a **string** — if your upstream stores it as an
object, stringify it (e.g. `"Bedford, MA, US"`) before passing.

### The contract push_leads guarantees

- **Validate + sanitize first.** Every field is validated/scrubbed before any
  write; a bad lead (missing id, invalid email) is reported `failed` with **no
  writes**. Emails/domains are RFC-shaped and URL-encoded before they touch a
  `filter=` query (anti filter-injection).
- **Idempotent on `leadId`.** The Opportunity is the idempotent unit — a
  `leadId` hit **skips** creation. Safe to re-run whether or not the upstream
  store marked the lead processed.
- **Non-destructive.** An existing Person (matched by `leadId`, then email) is
  **reused, never structurally mutated** — a returning prospect's record is never
  overwritten from unverified form data.
- **Company only when it makes sense.** Created/linked only for `business` leads
  on a real corporate domain (not blocklisted), and set on a **newly created**
  Person only.
- **Always a Note.** The per-lead message Note is ensured on **every** run, even
  when the Opportunity was skipped, so a Note lost to a prior partial failure is
  recovered.
- **Emergency path is independent of the skip.** For `contact_type: emergency`,
  even when the Opportunity already exists the run still flags the result
  `emergency: true` (so a downstream workflow can fire an urgent alert — a lost
  alert can never happen) and sets the `isEmergency` marker.
- **Batch isolation + FIFO.** `status == 'new'` only, oldest-first, capped at
  `maxBatch` (default 200); the remainder count is reported so nothing starves.
  One bad lead never aborts the batch.

### Reading the result

`push_leads` writes a `pushRun` resource: `{ synced, skipped, failed, results[],
audit }`, each result `{ leadId, action, status, personId?, opportunityId?,
companyId?, emergency, noteEnsured, error? }` — **no raw PII beyond the opaque
`leadId`** and Twenty record ids. Reference it with CEL, e.g.
`data.latest("<name>", "pushRun").attributes.results`. A Phase-4 workflow reads
it to fire notifications for `emergency: true` results and to write status back.

Standalone idempotency checks: `findPersonByLeadId` / `findOpportunityByLeadId`
(the latter is the primary check) snapshot a `record` reference only on a hit.

## Permissions — Twenty's model (important)

Twenty gates access with **role-based permissions** in three layers, applied in
the workspace UI (*Settings → Members → Roles*):

- **Object-level** — see / edit / delete / destroy per object type.
- **Field-level** — See / Edit / No Access per field.
- **Row-level** — restrict which individual records a role sees (a **Premium**
  feature). More specific settings win (field > object > default).

Roles assign to workspace members, **API keys**, and AI agents. So **this model's
`apiToken` inherits whatever role its API key is given** — scope the key to
exactly the objects/fields the lead sink needs (read/create on
Person/Company/Opportunity/Note + the two custom fields). There is **no REST
endpoint to create or assign roles** — role and visibility config is UI-only.

**Emergency-record visibility** therefore is a workspace pre-config, not
something this model can enforce over the API. `push_leads` only *sets* the
`isEmergency` marker; to actually restrict who sees flagged records, configure a
restricted role + a saved view filtered on `isEmergency = true` (or a row-level
rule) in the UI. `emergencyRestrictedRole` just documents that role's name.

## Surfacing records to a human

Twenty record URLs follow `<baseUrl>/object/<objectNameSingular>/<recordId>` —
e.g. `<baseUrl>/object/person/<personId>` or
`<baseUrl>/object/opportunity/<opportunityId>`. Build links from the ids in the
`pushRun` result rather than exposing raw ids.

## Gotchas

- **Run `ensureLeadFields` before any `leadId` filter** — filtering on a field
  that doesn't exist yet silently returns the wrong (degraded) path.
- **Phone numbers** are normalized toward E.164 with a NANP (`+1`) default;
  Twenty rejects bare national numbers. If a number still isn't dialable the
  Person is created without it rather than dropping the lead.
- **`geo` is a string**, not an object (stringify upstream geo before passing).
- **Never hard-code `apiToken`** — it's sensitive; swamp rejects a literal. Vault
  + CEL only.
- **`ensureLeadFields` mutates live workspace metadata** — treat a production
  workspace with the same care as any schema change; it is additive
  (deactivatable in the UI) but confirm-gate it deliberately.
