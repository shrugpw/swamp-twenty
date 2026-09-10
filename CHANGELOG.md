# Changelog

All notable changes to `@shrug/twenty`. Versions are CalVer (`YYYY.MM.DD.micro`).

## 2026.09.10.2

### Changed

- **`upsertOpportunity` can now write the two Opportunity segmentation `SELECT`
  fields.** Two optional arguments — `lineOfBusiness` (CONSULTING / HOSTING /
  GAMES) and `sourceChannel` (DIRECT / REFERRAL / BRAINTRUST / RAMP / CANOPY /
  CONSULTING_HANDOFF) — let existing opportunities be flagged declaratively.
  Each token is validated against the live field's enum options (via the same
  `fetchOpportunityMeta` read that already validates `stage`), so an invalid
  token fails fast with the valid set rather than a blind Twenty 4xx; validation
  is skipped best-effort when the field's options are unreadable, matching
  `stage`. Written on **both** the create and update paths, and — like every
  other `upsertOpportunity` field — omitted from the request body when unset, so
  a partial update never nulls a value a re-run didn't set. The `opportunityUpsert`
  snapshot now carries the two tokens when written. `push_leads` (which stamps
  `sourceChannel` on the leads it creates) is unchanged.

## 2026.09.10.1

### Added

- **`ensureField`** — the generalized, idempotent field-provisioning foundation
  (`POST /rest/metadata/fields`) for `TEXT` / `BOOLEAN` / `NUMBER` / `DATE_TIME` /
  `SELECT`. Non-destructive: an absent field is created; a present scalar field
  is a no-op (a differing type is **reported**, never mutated); a present `SELECT`
  gets its options **appended** — existing options preserved verbatim (never
  dropped, reordered, or recolored), reusing `ensureStageOption`'s append-only +
  optimistic-concurrency (re-read + drift-abort) discipline. The `SELECT` option
  planner (`planSelectOptions`) and per-option normalizer
  (`normalizeRequestedOption`) are pure and unit-tested: values UPPER_SNAKE,
  colors palette-validated, labels defaulted to the title-cased token, duplicate
  requested values collapsed, new options positioned after the current max. Field
  names are camelCase-validated before any write. `confirm`-gated with a no-write
  `dryRun` (`planned-create` / `planned-append`); wrapped in `redactError`;
  guarded by the `reachable` live pre-flight. Snapshots a `fieldEnsured` resource.
- **`ensureOpportunitySegmentation`** — a single fan-out (repo rule 6) that
  provisions the two Opportunity segmentation `SELECT` fields in one execution
  (one metadata GET, one lock): **Line of Business** (Consulting / Hosting /
  Games) and **Source Channel** (Direct / Referral / Braintrust / Ramp / Canopy /
  Consulting hand-off). Analytics only — NOT a pipeline gate. Append-only, so a
  re-run is a clean no-op. `confirm`-gated + `dryRun`. Snapshots one
  `fieldEnsured` per field.
- **`fieldEnsured` resource** — the per-field outcome (action taken, `SELECT`
  options added/present, non-mutating drift notes, any type mismatch).

### Changed

- **`ensureLeadFields` is now a thin wrapper over the shared `ensureFieldOnce`
  core** — same `leadId`/`isEmergency` provisioning, same
  `created`/`alreadyPresent`/`failed` report shape and per-field resilience, now
  routed through the one non-destructive path so `ensureField` and
  `ensureLeadFields` cannot diverge.
- **`push_leads` stamps `sourceChannel`** on Opportunities it **creates**, from
  the new `leadSourceChannel` global. Contact-form leads are inbound-direct, so
  the value is `DIRECT` once the field is provisioned. The global defaults to `""`
  (do not set), so until the `opportunity.sourceChannel` `SELECT` exists the
  create body is byte-identical to before — no risk of writing an unprovisioned
  field. Set only on create (never on an idempotent skip/update).

### Notes

- `globalArguments` gains one **optional** field, `leadSourceChannel` (default
  `""`), so existing pinned instances upgrade lazily with no behavior change (the
  `2026.09.10.1` upgrade is a no-op attribute migration).
- Live PATCH/POST body shape for new `SELECT` options mirrors `ensureStageOption`
  (each new option carries a client-generated `id`); reconfirm against a live
  instance before the first `confirm:true` run.

## 2026.09.08.1

### Added

- **`listPeople` / `listCompanies` / `listNotes`** — three additive, read-only
  fan-out snapshot reads (repo rule 6) so a workflow can snapshot the whole CRM,
  not just the opportunity pipeline. Each optionally filters (people:
  `companyId`/`leadId`; companies: `domain`/`name`; notes: `leadId`), composes
  clauses with AND, sends the immutable composite `order_by=createdAt,id`, pages
  Twenty's cursor pagination at `PAGE_SIZE=60` up to a per-call cap
  (`limit` 1..500, default 60), dedups by id, and records a compact page
  snapshot. For `listPeople`, emergency-restricted rows are excluded by default
  via a NULL-safe clause (`or(isEmergency[eq]:false,isEmergency[is]:NULL)`) so the
  NULL/unset majority is kept; `includeEmergency:true` opts them in. `listNotes`
  omits emergency filtering entirely (no `includeEmergency` arg, no `isEmergency`
  in its view) because this extension does not provision `isEmergency` on Note —
  only on Person/Opportunity — so there is no marker on a Note to filter or
  surface. A per-CALL cap is not a snapshot ceiling: each call returns `hasMore` +
  `nextCursor` for a workflow to continue via `startingAfter`, and an honesty
  envelope (`incomplete` + `stopReason`) that reports `complete` only on a clean
  end reconciled against Twenty's `totalCount`. No writes, no per-id loop; compact
  views carry only join keys — never person name/email/phone, never a Note body,
  and a Note title only when it matches the machine `Inbound lead ` pattern.
- **`peopleList` / `companyList` / `noteList` resources** — the bulk snapshots,
  keyed by a SHA-256 of the canonical `(filter, cursor)` so each page gets its
  own instance. Finite `lifetime: 3d` + `garbageCollection: 5` — bulk snapshots
  do not inherit the refs' infinite retention.

### Changed

- **`listOpportunities`** now routes through the shared generic cursor paginator
  (single-sourcing cursor advance, dedup, guards, and continuation across all
  four list methods) and sends the immutable `order_by=createdAt,id` for gap-free,
  byte-stable paging. Its `opportunityList` output shape is unchanged.
- **`redactError`** now also scrubs the bearer token (`Bearer <token>` and any
  exact literal token the caller passes) plus the `filter=` and `starting_after=`
  query values from captured error strings (which embed raw leadId/name/domain
  and the opaque cursor), not just the email/digit PII shapes.
- **`limit` is a soft per-call floor, not a hard ceiling.** All four list
  methods page in whole `PAGE_SIZE` (60) pages: the call stops after the first
  full page that reaches `limit`, so a call may return up to `PAGE_SIZE - 1` more
  rows than `limit` (rounded up to the page boundary). This is what makes the
  continuation cursor safe (see Fixed).

### Fixed

- **Continuation is now gap-free and duplication-free (whole-page capping).** The
  paginator never slices a page mid-way: it consumes each page in full and only
  ever hands back the `endCursor` of a fully-consumed page, so the next call
  resumes strictly after it — no duplicated rows when `limit` is not a multiple
  of the page size, and no skipped rows when `limit < PAGE_SIZE` (a sub-page
  `limit` simply returns the first full page then stops with `hasMore=true`).
- **Per-call completeness no longer masks cross-call state.** A single call
  cannot know its cumulative offset, so completeness is now end-of-cursor:
  `stopReason='complete'` + `incomplete=false` whenever the loop ends on
  `hasNextPage=false`; `cap-reached` (with a valid `nextCursor`) and the
  `max-pages` backstop are continuable and NOT flagged incomplete. A count is
  reconciled against `totalCount` only for a single-call whole-set read (no
  `startingAfter`, `hasMore=false`) → `count-mismatch` / `no-total`; cumulative
  reconciliation across a page loop is the workflow's job, using the `totalCount`
  the envelope still exposes. `incomplete=true` is reserved for an untrustworthy
  cursor (`no-progress` / `cursor-repeat`).
- **`max-pages` backstop no longer strands the workflow** — it now returns
  `hasMore=true` + `nextCursor` (the last consumed page boundary) so paging can
  continue.
- **Note title guard is anchored** — a title is snapshotted only when it matches
  exactly `Inbound lead <leadId>` (the leadId re-validated), so a title with a
  free-text tail or a non-leadId suffix is dropped.

## 2026.09.06.3

### Added

- **`upsertPerson`** — first-class, idempotent-on-email curated-contact writer
  mirroring `upsertOpportunity`'s shape, so a Person can be curated directly
  (name / phone / jobTitle / city + Company link) rather than only as an
  opportunity's link-only point-of-contact or via the `push_leads` lead flow.
  Enables backfilling contacts that already exist upstream and adding secondary
  contacts. Find-or-create by `primaryEmail`: a hit PATCHes only the provided
  fields (`action=updated`); a miss creates (`action=created`). NEVER stamps a
  `leadId` — curated contacts stay out of the `leadId`→Person namespace
  `push_leads` relies on. Company deduped by domain then exact name, created and
  linked only when a domain is supplied (name-only miss left unlinked with a
  `companyNote`). Name subfields merge on update so a partial
  `{firstName|lastName}` never nulls the other; a bad phone is dropped, never
  blocks the contact. `create → conflict → refind → update` fallback keyed on
  email so concurrent runs converge on one Person. `confirm`-gated with a
  no-write `dryRun`; whole execute wrapped in `redactError` (snapshot carries no
  raw PII).
- **`personUpsert` resource** — records the action taken, the resolved Person id,
  the fields set, and the Company link.

### Changed

- Version bump to `2026.09.06.3` with a no-op `upgrades[]` entry
  (globalArguments unchanged) so existing pinned instances upgrade lazily.

## 2026.09.06.2

### Added

- **`ensureStageOption`** — idempotently provisions a SELECT option on an
  allowlisted picklist field (default `opportunity.stage`), closing a real gap:
  `upsertOpportunity` validates stage against the live enum but nothing could
  ADD to it (e.g. a `CLOSED` stage). Reads every existing option's full
  `{id,value,label,color,position}` and appends the new one, preserving existing
  entries verbatim (hard-stops rather than rebuild a lossy array); options-only
  partial PATCH so sibling metadata survives; re-reads immediately before the
  write and aborts on drift (optimistic concurrency). `(object,field)` allowlist
  so a typo can't append to the wrong SELECT; SELECT-only (MULTI_SELECT and
  every other type rejected); value UPPER_SNAKE-validated, color
  palette-validated. Confirm-gated, `dryRun`-previewable, execute wrapped in
  `redactError`; mirrors `ensureLeadFields`.
- **`stageOption` resource** — records the provisioned option and the field it
  was appended to.

### Changed

- Version bump to `2026.09.06.2` with a no-op `upgrades[]` entry
  (globalArguments unchanged) so existing pinned instances upgrade lazily.

## 2026.09.06.1

### Added

- **Read surface** — first-class, side-effect-free READ methods so
  reconcile/dedup audits no longer abuse `upsertOpportunity --dryRun` as a
  probe: `findPerson` (email | leadId), `findCompany` (domain | name),
  `getOpportunity` (leadId | id), `listOpportunities` (companyId and/or stage,
  paginated fan-out), plus `getPersonById` / `getCompanyById` reverse lookups so
  the reconcile report can walk an opportunity's `pointOfContactId` /
  `companyId` back to a contact/company. Cursor pagination with a no-progress
  guard (zero-new-id or repeated cursor hard-stops) and dedup by id, so a wrong
  cursor field can never infinite-loop; multi-clause AND composed as one
  comma-joined `filter=` param with each value UUID/filter-safe validated and
  URL-encoded; every read wrapped in `redactError` so an ambiguous-match throw or
  4xx never leaks the raw email/name. Additive only — `push_leads` and every
  write path untouched.
- **`personRef` / `companyRef` / `opportunityRef` / `opportunityList`
  snapshots** — misses recorded as `found:false` ("looked, not there" vs "never
  looked").

### Changed

- Version bump to `2026.09.06.1` with a no-op `upgrades[]` entry
  (globalArguments unchanged) so existing pinned instances upgrade lazily.

## 2026.09.05.2

### Added

- **`upsertOpportunity`** — generalized, idempotent Opportunity upsert keyed on
  `leadId` (create → conflict → update fallback for the check-then-act race).
  Sets the full field set the lead-sink `createOpportunity` omits: `name`,
  `amount` (whole units → currency micros), `stage` (validated against the live
  SELECT enum), `closeDate` (formatted per the live DATE vs DATE_TIME field
  type), a linked Company (dedup by domain, else filter-safe exact name;
  created only when a domain is supplied), a link-only point-of-contact Person
  (dedup by email; never created or leadId-stamped), and an optional Note.
  Defaults the stage only on create and preserves an existing opportunity's
  stage/currency on an amount-only update. `confirm`-gated with a no-write
  `dryRun`; writes an `opportunityUpsert` resource.
- **`opportunityUpsert` resource** — records the action taken and the resolved
  opportunity/company/contact ids plus any skip/degrade notes.

### Changed

- Version bump to `2026.09.05.2` with a no-op `upgrades[]` entry (globalArguments
  unchanged) so existing pinned instances upgrade lazily.

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
