# Changelog

All notable changes to `@shrug/twenty`. Versions are CalVer (`YYYY.MM.DD.micro`).

## 2026.09.05.1

Initial release.

### Added

- **`@shrug/twenty` model** — a generic Twenty CRM REST v1 surface plus the
  `push_leads` contact-form lead sink, in one type.
- **Generic REST surface**
  - `ping` — reachability + auth probe (authed `GET /rest/people?limit=1`).
  - `introspectSchema` — snapshot objects, the Opportunity stage enum, and
    whether the required `leadId` / `isEmergency` custom fields are present.
  - `ensureLeadFields` — idempotently provision the custom fields the lead sink
    depends on: `leadId` (TEXT) on Person/Opportunity/Note and `isEmergency`
    (BOOLEAN) on Person/Opportunity. Confirm-gated.
  - `findPersonByLeadId` / `findOpportunityByLeadId` — idempotency lookups by
    the immutable `leadId` marker.
- **`push_leads`** — the one fan-out method (repo rule 6) that ingests a batch of
  leads in a single execution:
  - validates + sanitizes every field before any write (email/domain RFC-shaped
    and URL-encoded → anti filter-injection; HTML/control chars stripped → anti
    record-poisoning);
  - dedups within the batch and against Twenty, keyed on `leadId` (the
    Opportunity is the idempotent unit — a `leadId` hit skips creation);
  - reuses but never structurally mutates an existing Person;
  - creates/links a Company only for business leads on a real corporate domain
    (consumer/free domains blocklisted);
  - always ensures the per-lead message Note, even when the Opportunity is
    skipped;
  - evaluates the emergency path (urgent-alert flag + `isEmergency` marker)
    independently of the skip, so a lost alert can never happen;
  - selects `status == 'new'` leads FIFO by `received_at`, capped at `maxBatch`
    (default 200), reporting the remainder;
  - returns a `pushRun` audit with no raw PII beyond the opaque `leadId`.
  - Confirm-gated with a `dryRun` no-write planning mode; guarded by a live
    reachability pre-flight.
- **Security discipline** — the `apiToken` global is marked sensitive
  (vault-resolved, never a literal, logged length-only); mutations are audited.
- **Bundled Claude skill** (`skills/twenty`) — a task playbook covering first-run
  field provisioning, the `push_leads` idempotency + emergency contract, reading
  the `pushRun` audit via CEL, and Twenty's role/permission model (why the token
  can't manage RBAC and how emergency-record visibility is actually restricted).

### Notes

- Phone numbers are normalized toward E.164 with a NANP (`+1`) default, since
  Twenty rejects bare national numbers. If a number is still not dialable, the
  Person is created without it rather than dropping the lead.
- Emergency-record **visibility restriction** is a documented workspace
  pre-config (a restricted role + a saved view filtered on `isEmergency`), not an
  API call — Twenty v2.38.1's REST API cannot manage RBAC.
- Verified against Twenty **v2.38.1**.
