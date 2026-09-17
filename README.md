# @shrug/twenty

Drive a [Twenty](https://twenty.com) CRM instance over its REST v1 API from
[swamp](https://github.com/swamp-club/swamp), and ingest contact-form leads into
it idempotently.

Two layers, one model type:

1. **A generic Twenty REST surface** — read/create People, Companies,
   Opportunities, and Notes; look records up by an immutable `leadId` marker (or
   by composite `emails.primaryEmail` / `domainName` filters); introspect
   object/field metadata; and self-provision the custom fields the idempotency
   scheme needs.
2. **`push_leads`** — the one fan-out method that ingests a batch of
   contact-form leads into Twenty in a single execution, safely and
   idempotently.

Built for the Shrug PW contact-form lead sink (Fastly KV → Twenty), but the REST
surface is generic.

## Install

```bash
swamp extension pull @shrug/twenty
```

Or, developing locally from a checkout:

```bash
swamp extension source add /path/to/swamp-twenty --only models
```

## Configure

`push_leads` and every write need a Twenty REST **bearer token**. It is marked
sensitive, so it cannot be stored as a literal — put it in a vault and reference
it with a CEL expression:

```bash
swamp vault create @webframp/pass twenty --config '{"prefix":"shrug.host/twenty"}'
swamp vault put twenty api-token '<TWENTY_REST_TOKEN>'

swamp model create @shrug/twenty crm \
  --global-arg baseUrl=https://crm.example.com \
  --global-arg 'apiToken=${{ vault.get("twenty", "api-token") }}'
```

### Global arguments

| Argument                  | Default                 | Purpose                                                                                          |
| ------------------------- | ----------------------- | ------------------------------------------------------------------------------------------------ |
| `baseUrl`                 | `https://crm.example.com`  | Twenty base URL (no trailing slash).                                                              |
| `apiToken`                | — (required, sensitive) | Twenty REST bearer token. Vault-resolved; never logged (length-only).                            |
| `opportunityStage`        | `NEW`                   | Stage for new Opportunities. Twenty defaults: `NEW`, `SCREENING`, `MEETING`, `PROPOSAL`, `CUSTOMER`. |
| `emailDomainBlocklist`    | consumer/free providers | Domains that never get a Company created/linked. Replaces the built-in default when set.         |
| `emergencyRestrictedRole` | `""`                    | Informational only (see [Emergency handling](#emergency-handling)).                              |

## First-run setup

Provision the custom fields the lead sink depends on, then confirm they exist:

```bash
swamp model method run crm ensureLeadFields --input confirm=true
swamp model method run crm introspectSchema
swamp data get crm schema --json          # requiredFields all present:true
```

`ensureLeadFields` creates (idempotently):

- `leadId` (TEXT) on **Person**, **Opportunity**, and **Note** — the dedup marker.
- `isEmergency` (BOOLEAN) on **Person** and **Opportunity** — the emergency marker.

## `push_leads`

The core fan-out. One method handles the whole batch internally (swamp repo
rule 6 — no per-lead method loops).

```bash
# Plan only — validates, looks up, and reports intended actions; writes NOTHING.
swamp model method run crm push_leads --input dryRun=true --input "leads=$(cat leads.json)"

# Real run.
swamp model method run crm push_leads --input confirm=true --input "leads=$(cat leads.json)"
```

### Lead shape

```jsonc
{
  "id": "LEAD-abc-123",          // REQUIRED — immutable upstream id; the leadId marker
  "name": "Ada Lovelace",         // split on the last space into first/last
  "email": "ada@example.com",   // REQUIRED — validated + lowercased
  "phone": "+1 (781) 555-0100",   // normalized toward E.164 (+1 default for US)
  "message": "…",                 // sanitized (HTML/control chars stripped), lands in the Note
  "contact_type": "business",     // individual | business | emergency
  "company": "Example Corp",      // used only for business leads on a corporate domain
  "received_at": "2026-09-01T09:00:00Z", // FIFO ordering key (oldest first)
  "status": "new",                // only 'new' leads are processed
  "geo": "Springfield, IL"        // coarse geo, appended to the Note
}
```

### What it guarantees

- **Validate + sanitize first.** Every field is validated/scrubbed before any
  write. A bad lead (missing id, invalid email) is reported `failed` with **no
  writes**. Emails and domains are RFC-shaped and URL-encoded before they touch a
  `filter=` query (anti filter-injection).
- **Idempotent on `leadId`.** The Opportunity is the idempotent unit: if one
  already carries the lead's `leadId`, creation is **skipped**. Safe to re-run
  regardless of whether the upstream store marked the lead processed.
- **Non-destructive.** An existing Person (matched by `leadId`, then email) is
  **reused, never structurally mutated** — a returning prospect's earlier record
  is never overwritten from unverified form data (anti record-poisoning).
- **Company only when it makes sense.** Created/linked only for `business` leads
  whose email domain is a real corporate domain (not on the consumer blocklist),
  and set on a **newly created** Person only.
- **Always a Note.** The per-lead message Note is ensured on **every** run —
  even when the Opportunity was skipped — so a Note lost to a prior partial
  failure is recovered.
- **Batch isolation + FIFO.** `status == 'new'` only, oldest-first, capped at
  `maxBatch` (default 200); the remainder count is reported so nothing starves.
  One bad lead never aborts the batch.
- **No raw PII in the audit.** The `pushRun` result carries per-lead outcomes
  keyed by the opaque `leadId` and Twenty record ids — no email/name/phone/message.

### Result

`push_leads` writes a `pushRun` resource: `{synced, skipped, failed, results[],
audit}`. Each result is `{leadId, action, status, personId?, opportunityId?,
companyId?, emergency, noteEnsured, error?}`. The downstream (Phase-4) workflow
reads it to fire urgent notifications for `emergency: true` results.

## Emergency handling

Leads with `contact_type: "emergency"` are handled **independently of the
idempotency skip** — even when the Opportunity already exists, the run still:

1. flags the result `emergency: true` (so the downstream workflow fires an
   urgent notification — a lost alert can never happen), and
2. sets the `isEmergency` marker on the Person and Opportunity.

**Visibility restriction is a workspace pre-config, not an API call.** Twenty
v2.38.1's REST API cannot manage roles/permissions (there is no `role` object;
`/rest/roles` 400s). So this extension only *sets the marker*. To actually
restrict who sees emergency records, configure the workspace once in the UI:
create a restricted role and a saved view filtered on `isEmergency = true`. The
`emergencyRestrictedRole` global documents that role's name; it is not used to
make an API call.

## Methods

| Method                   | Kind    | Purpose                                                                    |
| ------------------------ | ------- | -------------------------------------------------------------------------- |
| `ping`                   | read    | Reachability + auth probe (authed `GET /rest/people?limit=1`).             |
| `introspectSchema`       | read    | Objects, Opportunity stage enum, required-field presence.                  |
| `ensureLeadFields`       | write¹  | Idempotently provision the `leadId` / `isEmergency` custom fields.         |
| `findPersonByLeadId`     | read    | Look up a Person by the `leadId` marker.                                   |
| `findOpportunityByLeadId`| read    | Look up an Opportunity by the `leadId` marker (the primary idempotency check). |
| `push_leads`             | write¹  | The fan-out lead sink (see above).                                         |
| `upsertOpportunity`      | write¹  | Idempotent (on `leadId`) Opportunity create-or-update with the full field set — see [upsertOpportunity fields](#upsertopportunity-fields). |
| `upsertRecord`           | write¹  | Generic idempotent create-or-update for an allowlisted custom object (`subscription`, `channelPartner`), keyed on a scalar natural-key field. |
| `listNotesByOpportunity` | read    | Body-free discovery of the Notes linked to an Opportunity (via `noteTargets`) — compact views only, NO body (SR-1 preserved). Finds a `noteId` for `getNoteBody`. |
| `getNoteBody`            | read²   | **SR-1 exception** — reads ONE Note's body (`bodyV2.markdown`) across the privacy boundary that every other method withholds. Per-id, `confirm=true`-gated, short-TTL snapshot. |

¹ Confirm-gated (`confirm=true`), and guarded by a live reachability pre-flight
check. `push_leads`, `upsertOpportunity`, and `upsertRecord` also support
`dryRun=true` for a no-write plan.

² `getNoteBody` is a **read**, but requires `confirm=true` as an explicit
acknowledgement that it crosses the SR-1 note-body privacy boundary (bodies are
withheld by every other method). It returns the body to a **short-TTL (`3d`)**
`noteBodyRead` snapshot. Per-id gating bounds a single call — not a scripted
`listNotes`→`getNoteBody` loop, which can still reconstruct a bulk read one
audited call at a time.

### upsertOpportunity fields

`upsertOpportunity` finds any existing Opportunity by the immutable `leadId`
marker (hit ⇒ PATCH, miss ⇒ create) and writes the fields you supply. Every
field is **omitted when unset** (never nulled), so a re-run only touches what you
pass. Beyond `name` / `amount` / `stage` / `closeDate` / company / point-of-contact
/ `isEmergency`, it writes these typed SELECT/TEXT fields (each validated against
the live workspace metadata, exactly like `stage`):

| Arg              | Type   | Notes                                                                                          |
| ---------------- | ------ | ---------------------------------------------------------------------------------------------- |
| `lineOfBusiness` | SELECT | Segmentation (`CONSULTING` / `HOSTING` / `GAMES`). Validated against the live enum.             |
| `sourceChannel`  | SELECT | Segmentation (`DIRECT` / `REFERRAL` / `CONSULTING_HANDOFF`). Validated against the live enum.   |
| `asn`            | TEXT   | Autonomous System Number. Guarded to `^AS\d{1,10}$` (AS + 1–10 digits — a 32-bit ASN maxes at 4294967295; case-insensitive input, uppercased on store); a non-empty value that doesn't match is rejected. |
| `qualStatus`     | SELECT | Technical-qualification state. Validated against the live `opportunity.qualStatus` enum.        |
| `offering`       | SELECT | Offering segmentation (`MANAGED`/`SUBSTRATE`/`PROJECT`/`RETAINER`/`LOCAL_IT`/`PEERING`). Validated against the live `opportunity.offering` enum; provisioned via `ensureOpportunitySegmentation`. |
| `channelPartnerId` | RELATION | Link to a `channelPartner` record (marketplace attribution). A UUID, validated early; sets the `opportunity.channelPartner` FK. Takes precedence over `channelPartnerName`. |
| `channelPartnerName` | (resolver) | Resolve-and-link a `channelPartner` by name (link-only, e.g. `Globex`/`Initech`) when `channelPartnerId` is unset; no match ⇒ recorded as skipped, never created. |

An empty string for any of these means **leave unchanged** (not "clear").

**`customFields` (generic scalar escape hatch).** For scalar Opportunity custom
fields without a typed argument, pass
`customFields: { <fieldName>: <string|number|boolean> }`. It is **fail-closed**:

- if opportunity metadata is unreadable, the whole map is rejected (no blind write);
- every key must be a camelCase field that **exists** on `opportunity` and is a
  **scalar** TYPE (`TEXT` / `NUMBER` / `BOOLEAN` / `DATE_TIME` / `SELECT` / `UUID`) —
  unknown keys and composite types (`CURRENCY` / `RELATION` / …) are rejected pre-write;
- **reserved keys are rejected**: the `leadId` idempotency marker, every field owned
  by a typed argument (`name`, `stage`, `amount`, `currencyCode`, `closeDate`,
  company / point-of-contact, `isEmergency`, `lineOfBusiness`, `sourceChannel`,
  `asn`, `qualStatus`), and the base system fields — so the escape hatch can never
  rewrite the marker or collide with a typed arg (set those via their typed arg);
- `SELECT` values are validated against the live enum; strings are sanitized;
- an empty string means unset (omitted); `null` is not permitted.

## Development

```bash
~/.swamp/deno/deno check extensions/models/twenty.ts   # type-check
~/.swamp/deno/deno test  extensions/models/             # unit tests (pure logic)
~/.swamp/deno/deno fmt   extensions/models/             # format
```

The security-critical logic (email/domain validation, text sanitization, the
blocklist, name split, FIFO/cap selection, per-lead planning) is all pure and
unit-tested without a live Twenty.

## License

MIT © 2026 Neil Hanlon
