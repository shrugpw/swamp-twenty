/**
 * @shrug/twenty — drive a Twenty CRM instance over its REST v1 API.
 *
 * Two layers in one type:
 *
 *  1. A **generic Twenty REST surface**: read/create People, Companies,
 *     Opportunities, and Notes; look records up idempotently by an immutable
 *     `leadId` marker (or by composite `emails.primaryEmail` / `domainName`
 *     filters); introspect object/field metadata; and self-provision the custom
 *     `leadId` / `isEmergency` fields the idempotency scheme depends on.
 *
 *  2. **`push_leads`** — the one fan-out method (repo rule 6) that ingests a
 *     batch of contact-form leads into Twenty. It validates + sanitizes every
 *     field BEFORE any write, dedups within the batch and against Twenty, REUSES
 *     but never structurally mutates an existing Person (anti record-poisoning),
 *     creates exactly one Opportunity per lead keyed on `leadId` (the idempotent
 *     unit), ALWAYS attaches a per-lead message Note, and evaluates the
 *     emergency path (urgent-alert flag + restricted-visibility marker)
 *     INDEPENDENTLY of the opportunity-exists skip so a lost alert can never
 *     happen. It shares this file's transport, validation, and idempotency
 *     helpers directly rather than looping model-method calls.
 *
 * Idempotency linchpin (proven against Twenty v2.38.1): a custom `leadId` TEXT
 * field on Person/Opportunity/Note, created + server-side filterable via the
 * metadata API. `findOpportunityByLeadId` hit => skip creation, so re-runs are
 * safe regardless of whether the upstream KV lead was marked processed.
 *
 * Emergency visibility: Twenty v2.38.1's REST API cannot manage RBAC (no `role`
 * object, `/rest/roles` 400s), so `setEmergencyVisibility` only SETS an
 * `isEmergency` marker on the records. Actual restriction is a documented
 * workspace pre-config — a restricted role + a saved view filtered on that
 * marker (see README). The extension's job is to set the marker reliably.
 *
 * Auth: a Twenty REST bearer token. Resolve it from a swamp vault via CEL, e.g.
 * `--global-arg 'apiToken=${{ vault.get("twenty", "api-token") }}'`. Never
 * hard-code it; it is meta-tagged sensitive and only ever logged length-only.
 */
import { z } from "npm:zod@4";

// --- Global arguments -------------------------------------------------------

/**
 * Default consumer / free-mail domains. A lead whose email domain is on this
 * list never gets a Company created or linked (a personal address is not a
 * company), even for a `business` contact_type. Override via the
 * `emailDomainBlocklist` global to extend or replace it.
 */
export const DEFAULT_EMAIL_DOMAIN_BLOCKLIST: readonly string[] = [
  "gmail.com",
  "googlemail.com",
  "yahoo.com",
  "ymail.com",
  "hotmail.com",
  "outlook.com",
  "live.com",
  "msn.com",
  "aol.com",
  "icloud.com",
  "me.com",
  "mac.com",
  "proton.me",
  "protonmail.com",
  "pm.me",
  "gmx.com",
  "gmx.net",
  "mail.com",
  "zoho.com",
  "yandex.com",
  "fastmail.com",
  "hey.com",
  "tutanota.com",
  "comcast.net",
  "verizon.net",
  "att.net",
  "sbcglobal.net",
];

const GlobalArgsSchema = z.object({
  baseUrl: z
    .string()
    .default("https://crm.example.com")
    .describe(
      "Twenty base URL (no trailing slash), e.g. https://crm.example.com",
    ),
  apiToken: z
    .string()
    .meta({ sensitive: true })
    .describe(
      "Twenty REST API bearer token — resolve from a vault via CEL, do not hard-code",
    ),
  opportunityStage: z
    .string()
    .default("NEW")
    .describe(
      "Stage assigned to newly created Opportunities. Twenty v2.38.1 defaults: NEW, SCREENING, MEETING, PROPOSAL, CUSTOMER.",
    ),
  emailDomainBlocklist: z
    .array(z.string())
    .default([...DEFAULT_EMAIL_DOMAIN_BLOCKLIST])
    .describe(
      "Consumer/free-mail domains that never get a Company created/linked. Replaces the built-in default when set.",
    ),
  emergencyRestrictedRole: z
    .string()
    .default("")
    .describe(
      "INFORMATIONAL: name of the pre-configured Twenty role whose saved view restricts records carrying the isEmergency marker. Twenty's REST API cannot assign roles, so this is documentation only — setEmergencyVisibility just sets the marker; visibility is enforced by workspace config.",
    ),
});
type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/** The slice of globals the transport + helpers need. */
interface TwentyCfg {
  baseUrl: string;
  apiToken: string;
}

// --- Transport --------------------------------------------------------------

/**
 * Minimal Twenty REST client over fetch. Throws on non-2xx, with the token
 * never echoed and the response body truncated. Twenty serves the REST API
 * under `/rest`; metadata under `/rest/metadata`. `path` is the full path
 * INCLUDING that prefix (e.g. `/rest/people`).
 */
export async function twentyRequest(
  cfg: TwentyCfg,
  method: string,
  path: string,
  body?: Record<string, unknown>,
): Promise<unknown> {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const resp = await fetch(`${base}${path}`, {
    method,
    headers: {
      "Authorization": `Bearer ${cfg.apiToken}`,
      "Accept": "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(
      `Twenty ${method} ${path} failed: ${resp.status} ${resp.statusText} — ${
        text.slice(0, 300)
      }`,
    );
  }
  return text ? JSON.parse(text) : {};
}

/** Extract a list from a Twenty REST list response (`{data:{<plural>:[...]}}`). */
function unwrapList(
  json: unknown,
  plural: string,
): Array<Record<string, unknown>> {
  const data = (json as { data?: Record<string, unknown> })?.data;
  const list = data?.[plural];
  return Array.isArray(list) ? (list as Array<Record<string, unknown>>) : [];
}

/** Extract the created/updated record from a mutation response (`{data:{<op>:{...}}}`). */
function unwrapRecord(json: unknown, op: string): Record<string, unknown> {
  const data = (json as { data?: Record<string, unknown> })?.data;
  const rec = data?.[op];
  return (rec ?? {}) as Record<string, unknown>;
}

/**
 * Reachability + auth probe: an authed `GET /rest/people?limit=1`. A 2xx proves
 * the instance is up AND the token authenticates (a bad/absent token 401/403s).
 * Anything else throws with the status for the pre-flight check to report.
 */
async function probeReachable(cfg: TwentyCfg): Promise<boolean> {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const resp = await fetch(`${base}/rest/people?limit=1`, {
    headers: {
      "Authorization": `Bearer ${cfg.apiToken}`,
      "Accept": "application/json",
    },
  });
  if (!resp.ok) {
    const text = (await resp.text()).slice(0, 200);
    throw new Error(
      `GET /rest/people probe failed: ${resp.status} ${resp.statusText} — ${text}`,
    );
  }
  return true;
}

// --- Pure validation / sanitization (exported for tests) --------------------

// Deliberately permissive-but-safe email shape. Twenty stores whatever we send;
// the point is to reject garbage and anything that could break out of a filter,
// not to be an RFC 5322 oracle.
const EMAIL_RE =
  /^[^\s@"'<>()[\]\\,;:]+@[^\s@"'<>()[\]\\,;:]+\.[^\s@"'<>()[\]\\,;:]+$/;
const DOMAIN_RE = /^([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/;

/**
 * Lowercase + validate an email. Returns the normalized address, or null if it
 * is missing/malformed/too long. Rejecting here is what makes it safe to
 * interpolate (URL-encoded) into a Twenty `filter=` query.
 */
export function validateEmail(raw: unknown): string | null {
  if (raw == null) return null;
  const s = String(raw).trim().toLowerCase();
  if (s.length < 3 || s.length > 254) return null;
  return EMAIL_RE.test(s) ? s : null;
}

/** The domain part of a validated email (lowercased), or null. */
export function domainOfEmail(email: string): string | null {
  const at = email.lastIndexOf("@");
  if (at === -1) return null;
  return validateDomain(email.slice(at + 1));
}

/** Validate a bare domain (lowercased) for company dedup; null if malformed. */
export function validateDomain(raw: unknown): string | null {
  if (raw == null) return null;
  const s = String(raw).trim().toLowerCase();
  if (s.length < 3 || s.length > 253) return null;
  return DOMAIN_RE.test(s) ? s : null;
}

/** True if the (validated) domain is a consumer/free-mail domain to skip. */
export function isBlockedDomain(
  domain: string,
  blocklist: readonly string[],
): boolean {
  return blocklist.includes(domain.toLowerCase());
}

/**
 * Normalize a phone toward E.164 (`+<countrycode><number>`), which is what
 * Twenty's phone field accepts. Strips to `+`/digits, keeps a single leading
 * `+`, and defaults the North American country code: a bare 10-digit number
 * becomes `+1XXXXXXXXXX` and `1XXXXXXXXXX` becomes `+1XXXXXXXXXX` (Bedford, MA
 * is US-facing). Anything else gets a best-effort `+` prefix — if that is still
 * not dialable, {@link createPerson} drops the phone rather than the lead.
 * Empty string if nothing usable.
 */
export function normalizePhone(raw: unknown): string {
  if (raw == null) return "";
  let s = String(raw).replace(/[^\d+]/g, "");
  // Keep only a single leading '+'.
  s = s.replace(/(?!^)\+/g, "");
  if (!s.startsWith("+")) {
    if (s.length === 10) s = "+1" + s; // NANP 10-digit
    else if (s.length === 11 && s.startsWith("1")) s = "+" + s;
    else if (s.length > 0) s = "+" + s; // best-effort E.164
  }
  return s.slice(0, 20);
}

/**
 * Strip HTML/markup tags and control chars, collapse whitespace, and cap
 * length. This is the anti-injection / anti-poisoning scrub applied to every
 * free-text field before it is written to Twenty.
 */
export function sanitizeText(raw: unknown, maxLen: number): string {
  if (raw == null) return "";
  let s = String(raw);
  s = s.replace(/<[^>]*>/g, " "); // strip HTML/XML-ish tags
  s = s.replace(/\p{Cc}/gu, " "); // strip control chars (Unicode Control category)
  s = s.replace(/\s+/g, " ").trim();
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

/**
 * Backslash-escape the markdown constructs that could turn an attacker-submitted
 * free-text value into a live link or image once the Note's `bodyV2.markdown` is
 * rendered — e.g. `![](http://attacker/beacon.png)` (tracking pixel) or
 * `[click](http://phish)`. Escaping the link/image/code delimiters neutralizes
 * those while leaving the text readable. Assumes {@link sanitizeText} has already
 * stripped tags/control chars.
 */
export function escapeMarkdown(s: string): string {
  return s.replace(/([\\`*_{}\[\]()#+!|~<>])/g, "\\$1");
}

// Email/long-digit-run shapes to scrub from captured error strings before they
// are persisted, so a REST validation error that echoes the submitted value
// (e.g. "email already exists: foo@bar.com") can't leak PII into the audit.
const EMAIL_IN_TEXT_RE =
  /[^\s@"'<>()[\]\\,;:]+@[^\s@"'<>()[\]\\,;:]+\.[a-z]{2,}/gi;
const LONG_DIGITS_RE = /\+?\d[\d ().-]{6,}\d/g;

/**
 * Redact PII-shaped substrings (emails, long digit runs) from a captured error
 * message and cap its length, so the per-lead audit keeps its "no raw PII beyond
 * leadId" guarantee even when Twenty echoes the offending value back in a 4xx.
 */
export function redactError(raw: unknown, maxLen = 300): string {
  let s = raw instanceof Error ? raw.message : String(raw ?? "");
  s = s.replace(EMAIL_IN_TEXT_RE, "[email]").replace(
    LONG_DIGITS_RE,
    "[number]",
  );
  return s.length > maxLen ? s.slice(0, maxLen) : s;
}

/**
 * Split a full name into {firstName, lastName} on the LAST space. A single
 * token becomes the lastName (per the approved spec), leaving firstName empty.
 */
export function splitName(
  full: unknown,
): { firstName: string; lastName: string } {
  const s = sanitizeText(full, 120);
  if (!s) return { firstName: "", lastName: "" };
  const idx = s.lastIndexOf(" ");
  if (idx === -1) return { firstName: "", lastName: s };
  return {
    firstName: s.slice(0, idx).trim(),
    lastName: s.slice(idx + 1).trim(),
  };
}

/**
 * Build a Twenty REST filter path: `<basePath>?filter=<field>[eq]:<encoded>`.
 * The value is URL-encoded so a validated-but-hostile value can never break out
 * of the query (anti filter-injection). Callers MUST pass an already-validated
 * value (validated email/domain/leadId), not raw user input.
 */
export function buildFilterPath(
  basePath: string,
  field: string,
  value: string,
): string {
  return `${basePath}?filter=${field}[eq]:${encodeURIComponent(value)}`;
}

// A leadId is an opaque upstream identifier, not PII. Keep it filter-safe.
const LEAD_ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;

/** Validate the opaque upstream lead id used as the idempotency marker. */
export function validateLeadId(raw: unknown): string | null {
  if (raw == null) return null;
  const s = String(raw).trim();
  return LEAD_ID_RE.test(s) ? s : null;
}

// --- Lead record + pure lead planning ---------------------------------------

/** One inbound contact-form lead (the shape push_leads ingests). */
const LeadRecordSchema = z.object({
  id: z.string().describe("Immutable upstream lead id — the leadId marker"),
  name: z.string().default("").describe("Submitter name (free text)"),
  email: z.string().describe("Submitter email"),
  phone: z.string().default("").describe("Submitter phone (free text)"),
  message: z.string().default("").describe("Free-text message body"),
  contact_type: z
    .enum(["individual", "business", "emergency"])
    .default("individual")
    .describe("Lead kind; drives company-linking and the emergency path"),
  company: z.string().default("").describe("Company name (business leads)"),
  received_at: z
    .string()
    .default("")
    .describe("ISO timestamp for FIFO ordering (oldest processed first)"),
  status: z
    .string()
    .default("new")
    .describe("Upstream status; only 'new' leads are processed"),
  geo: z.string().default("").describe(
    "Coarse geo string, appended to the Note",
  ),
}).passthrough();
type LeadRecord = z.infer<typeof LeadRecordSchema>;

/** A lead that failed validation (no writes will happen for it). */
export interface PlannedLeadInvalid {
  ok: false;
  leadId: string | null;
  reason: string;
}

/** A validated + sanitized lead, ready for the idempotent write sequence. */
export interface PlannedLeadValid {
  ok: true;
  leadId: string;
  email: string;
  firstName: string;
  lastName: string;
  phone: string;
  message: string;
  geo: string;
  contactType: "individual" | "business" | "emergency";
  emergency: boolean;
  /** Company name to use IF a company is created (business + real domain only). */
  companyName: string;
  /** Corporate domain for the company, or null when none/blocked/consumer. */
  companyDomain: string | null;
}

export type PlannedLead = PlannedLeadValid | PlannedLeadInvalid;

/**
 * Validate + sanitize ONE lead with no I/O. This is step (1) of the push_leads
 * contract, factored out so the security-critical rules (email validation,
 * text scrubbing, consumer-domain blocklist, name split) are unit-testable
 * without a live Twenty.
 */
export function planLead(
  lead: LeadRecord,
  blocklist: readonly string[],
): PlannedLead {
  const leadId = validateLeadId(lead.id);
  if (!leadId) {
    return { ok: false, leadId: null, reason: "missing or malformed lead id" };
  }
  const email = validateEmail(lead.email);
  if (!email) {
    return { ok: false, leadId, reason: "invalid email" };
  }
  const { firstName, lastName } = splitName(lead.name);
  const contactType = lead.contact_type ?? "individual";
  const emergency = contactType === "emergency";

  // Company only for business leads with a real, non-consumer corporate domain.
  let companyDomain: string | null = null;
  if (contactType === "business") {
    const d = domainOfEmail(email);
    if (d && !isBlockedDomain(d, blocklist)) companyDomain = d;
  }
  const companyName = sanitizeText(lead.company || companyDomain || "", 120);

  return {
    ok: true,
    leadId,
    email,
    firstName,
    lastName,
    phone: normalizePhone(lead.phone),
    message: sanitizeText(lead.message, 5000),
    geo: sanitizeText(lead.geo, 200),
    contactType,
    emergency,
    companyName,
    companyDomain,
  };
}

/**
 * Select the batch to process: `status == 'new'`, sorted FIFO by `received_at`
 * ascending (oldest first, no starvation), capped at `maxBatch`. Pure so the
 * ordering + cap are testable. Reports the cap and how many remain.
 */
export function selectBatch(
  leads: LeadRecord[],
  maxBatch: number,
): { batch: LeadRecord[]; cap: number; remaining: number; eligible: number } {
  const eligible = leads.filter((l) => (l.status ?? "new") === "new");
  eligible.sort((a, b) => {
    const av = a.received_at ?? "";
    const bv = b.received_at ?? "";
    if (av === bv) return 0;
    return av < bv ? -1 : 1;
  });
  const batch = eligible.slice(0, maxBatch);
  return {
    batch,
    cap: maxBatch,
    remaining: Math.max(0, eligible.length - batch.length),
    eligible: eligible.length,
  };
}

// --- Idempotency helpers (I/O, shared by base methods + push_leads) ---------

async function findPersonByLeadId(
  cfg: TwentyCfg,
  leadId: string,
): Promise<Record<string, unknown> | null> {
  const json = await twentyRequest(
    cfg,
    "GET",
    buildFilterPath("/rest/people", "leadId", leadId),
  );
  return unwrapList(json, "people")[0] ?? null;
}

async function findPersonByEmail(
  cfg: TwentyCfg,
  email: string,
): Promise<Record<string, unknown> | null> {
  const json = await twentyRequest(
    cfg,
    "GET",
    buildFilterPath("/rest/people", "emails.primaryEmail", email),
  );
  return unwrapList(json, "people")[0] ?? null;
}

interface CreatePersonInput {
  firstName: string;
  lastName: string;
  email: string;
  phone?: string;
  companyId?: string;
  leadId: string;
}

async function createPerson(
  cfg: TwentyCfg,
  p: CreatePersonInput,
): Promise<Record<string, unknown>> {
  const body: Record<string, unknown> = {
    name: { firstName: p.firstName, lastName: p.lastName },
    emails: { primaryEmail: p.email },
    leadId: p.leadId,
  };
  if (p.phone) body.phones = { primaryPhoneNumber: p.phone };
  if (p.companyId) body.companyId = p.companyId;
  try {
    const json = await twentyRequest(cfg, "POST", "/rest/people", body);
    return unwrapRecord(json, "createPerson");
  } catch (e) {
    // Never drop a lead (especially an emergency one) over an unparseable phone
    // — retry once without it. Gated on a phone-shaped error so real failures
    // (auth, validation of other fields) still surface.
    const msg = e instanceof Error ? e.message : String(e);
    if (body.phones && /phone/i.test(msg)) {
      delete body.phones;
      const json = await twentyRequest(cfg, "POST", "/rest/people", body);
      return unwrapRecord(json, "createPerson");
    }
    throw e;
  }
}

async function findCompanyByDomain(
  cfg: TwentyCfg,
  domain: string,
): Promise<Record<string, unknown> | null> {
  const json = await twentyRequest(
    cfg,
    "GET",
    buildFilterPath("/rest/companies", "domainName.primaryLinkUrl", domain),
  );
  return unwrapList(json, "companies")[0] ?? null;
}

async function createCompany(
  cfg: TwentyCfg,
  input: { name: string; domain?: string | null },
): Promise<Record<string, unknown>> {
  const body: Record<string, unknown> = { name: input.name };
  if (input.domain) body.domainName = { primaryLinkUrl: input.domain };
  const json = await twentyRequest(cfg, "POST", "/rest/companies", body);
  return unwrapRecord(json, "createCompany");
}

async function findOpportunityByLeadId(
  cfg: TwentyCfg,
  leadId: string,
): Promise<Record<string, unknown> | null> {
  const json = await twentyRequest(
    cfg,
    "GET",
    buildFilterPath("/rest/opportunities", "leadId", leadId),
  );
  return unwrapList(json, "opportunities")[0] ?? null;
}

interface CreateOpportunityInput {
  name: string;
  stage: string;
  pointOfContactId: string;
  companyId?: string;
  leadId: string;
}

async function createOpportunity(
  cfg: TwentyCfg,
  o: CreateOpportunityInput,
): Promise<Record<string, unknown>> {
  const body: Record<string, unknown> = {
    name: o.name,
    stage: o.stage,
    pointOfContactId: o.pointOfContactId,
    leadId: o.leadId,
  };
  if (o.companyId) body.companyId = o.companyId;
  const json = await twentyRequest(cfg, "POST", "/rest/opportunities", body);
  return unwrapRecord(json, "createOpportunity");
}

async function findNoteByLeadId(
  cfg: TwentyCfg,
  leadId: string,
): Promise<Record<string, unknown> | null> {
  const json = await twentyRequest(
    cfg,
    "GET",
    buildFilterPath("/rest/notes", "leadId", leadId),
  );
  return unwrapList(json, "notes")[0] ?? null;
}

/**
 * Attach the per-lead Note idempotently: if a Note already carries this leadId,
 * do nothing; otherwise create the Note (markdown body) and link it to the
 * given person/opportunity via separate noteTarget records. Returns whether a
 * new Note was created.
 */
async function ensureNoteForLead(
  cfg: TwentyCfg,
  input: {
    leadId: string;
    body: string;
    personId?: string;
    opportunityId?: string;
  },
): Promise<{ noteId: string; created: boolean }> {
  const existing = await findNoteByLeadId(cfg, input.leadId);
  let noteId: string;
  let created: boolean;
  if (existing) {
    noteId = String(existing.id ?? "");
    created = false;
  } else {
    const json = await twentyRequest(cfg, "POST", "/rest/notes", {
      title: `Inbound lead ${input.leadId}`,
      bodyV2: { markdown: input.body },
      leadId: input.leadId,
    });
    noteId = String(unwrapRecord(json, "createNote").id ?? "");
    created = true;
  }
  if (!noteId) return { noteId, created };

  // Ensure the person/opportunity target links exist — idempotently, whether or
  // not the Note is new. The Note record and its two target links are separate
  // writes, so a crash between them (Note created + one link, other link fails)
  // would otherwise orphan the message from a target forever: findNoteByLeadId
  // would find the Note next run and never repair the missing link. So we always
  // reconcile the links against what is already there.
  const targets = unwrapList(
    await twentyRequest(
      cfg,
      "GET",
      buildFilterPath("/rest/noteTargets", "noteId", noteId),
    ),
    "noteTargets",
  );
  const hasPerson = targets.some((t) => t.targetPersonId != null);
  const hasOpportunity = targets.some((t) => t.targetOpportunityId != null);
  if (input.personId && !hasPerson) {
    await twentyRequest(cfg, "POST", "/rest/noteTargets", {
      noteId,
      targetPersonId: input.personId,
    });
  }
  if (input.opportunityId && !hasOpportunity) {
    await twentyRequest(cfg, "POST", "/rest/noteTargets", {
      noteId,
      targetOpportunityId: input.opportunityId,
    });
  }
  return { noteId, created };
}

/**
 * Set the `isEmergency` marker (true) on the given person and/or opportunity.
 * This is the ONLY thing the extension can do about emergency visibility over
 * REST — actual restriction is enforced by a pre-configured role + saved view
 * (see README). Best-effort per record; a marker failure is reported but never
 * aborts the lead.
 */
async function setEmergencyMarker(
  cfg: TwentyCfg,
  input: { personId?: string; opportunityId?: string },
): Promise<void> {
  if (input.personId) {
    await twentyRequest(cfg, "PATCH", `/rest/people/${input.personId}`, {
      isEmergency: true,
    });
  }
  if (input.opportunityId) {
    await twentyRequest(
      cfg,
      "PATCH",
      `/rest/opportunities/${input.opportunityId}`,
      { isEmergency: true },
    );
  }
}

/**
 * The custom fields the idempotency + emergency schemes depend on. `leadId` is
 * the dedup marker on the three record kinds; `isEmergency` marks records the
 * restricted view hides.
 */
const REQUIRED_FIELDS: ReadonlyArray<
  { object: string; name: string; label: string; type: string }
> = [
  { object: "person", name: "leadId", label: "Lead ID", type: "TEXT" },
  { object: "opportunity", name: "leadId", label: "Lead ID", type: "TEXT" },
  { object: "note", name: "leadId", label: "Lead ID", type: "TEXT" },
  {
    object: "person",
    name: "isEmergency",
    label: "Is Emergency",
    type: "BOOLEAN",
  },
  {
    object: "opportunity",
    name: "isEmergency",
    label: "Is Emergency",
    type: "BOOLEAN",
  },
];

/** Map object nameSingular -> objectMetadataId from GET /rest/metadata/objects. */
async function objectMetadataIds(
  cfg: TwentyCfg,
): Promise<Map<string, string>> {
  const json = await twentyRequest(cfg, "GET", "/rest/metadata/objects");
  const objs = ((json as { data?: unknown }).data ?? []) as Array<
    Record<string, unknown>
  >;
  const m = new Map<string, string>();
  for (const o of objs) {
    const name = String(o.nameSingular ?? "");
    const id = String(o.id ?? "");
    if (name && id) m.set(name, id);
  }
  return m;
}

// --- Resource schemas -------------------------------------------------------

const CapabilitySchema = z.object({
  baseUrl: z.string(),
  reachable: z.boolean(),
  authenticated: z.boolean(),
  detail: z.string().optional(),
  retrievedAt: z.iso.datetime(),
});

const FieldPresenceSchema = z.object({
  object: z.string(),
  name: z.string(),
  present: z.boolean(),
});

const SchemaSnapshotSchema = z.object({
  baseUrl: z.string(),
  objects: z.array(z.string()).describe("nameSingular of every object"),
  opportunityStages: z
    .array(z.string())
    .describe("Discovered Opportunity stage enum, if readable"),
  requiredFields: z
    .array(FieldPresenceSchema)
    .describe("Presence of each leadId/isEmergency custom field"),
  retrievedAt: z.iso.datetime(),
});

const RecordRefSchema = z.object({
  baseUrl: z.string(),
  id: z.string(),
  kind: z.string(),
  leadId: z.string().optional(),
  retrievedAt: z.iso.datetime(),
});

const FieldsEnsuredSchema = z.object({
  baseUrl: z.string(),
  created: z.array(z.string()).describe("`object.field` created this run"),
  alreadyPresent: z.array(z.string()),
  failed: z.array(z.object({ field: z.string(), error: z.string() })),
  retrievedAt: z.iso.datetime(),
});

// push_leads per-lead result. Carries NO raw PII beyond the opaque leadId — no
// email/name/phone/message. `action` is the OPPORTUNITY outcome (the idempotent
// unit); `status` is the overall per-lead outcome.
const LeadResultSchema = z.object({
  leadId: z.string(),
  action: z.enum(["created", "skipped", "failed"]),
  status: z.enum(["synced", "skipped", "failed"]),
  personId: z.string().optional(),
  opportunityId: z.string().optional(),
  companyId: z.string().optional(),
  emergency: z.boolean(),
  noteEnsured: z.boolean(),
  markerFailed: z.boolean().optional().describe(
    "Emergency isEmergency marker PATCH failed (non-fatal; retried on re-run)",
  ),
  error: z.string().optional(),
});

const PushRunSchema = z.object({
  baseUrl: z.string(),
  dryRun: z.boolean(),
  synced: z.number(),
  skipped: z.number(),
  failed: z.number(),
  results: z.array(LeadResultSchema),
  audit: z.object({
    at: z.iso.datetime(),
    cap: z.number(),
    eligible: z.number(),
    processed: z.number(),
    remaining: z.number(),
    emergencies: z.number(),
    perLead: z.array(
      z.object({
        leadId: z.string(),
        action: z.string(),
        status: z.string(),
        emergency: z.boolean(),
      }),
    ),
  }),
});

// --- Execute context --------------------------------------------------------

interface MethodLogger {
  debug(message: string, properties?: Record<string, unknown>): void;
  info(message: string, properties?: Record<string, unknown>): void;
  warning(message: string, properties?: Record<string, unknown>): void;
  error(message: string, properties?: Record<string, unknown>): void;
}

interface ExecuteContext {
  globalArgs: GlobalArgs;
  logger: MethodLogger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

// --- push_leads orchestration -----------------------------------------------

interface PerLead {
  leadId: string;
  action: "created" | "skipped" | "failed";
  status: "synced" | "skipped" | "failed";
  personId?: string;
  opportunityId?: string;
  companyId?: string;
  emergency: boolean;
  noteEnsured: boolean;
  markerFailed?: boolean;
  error?: string;
}

/**
 * Process ONE already-planned, valid lead through the idempotent write
 * sequence, using the shared in-execution caches. Isolated by the caller in a
 * try/catch so a single bad lead never aborts the batch. When `dryRun`, does
 * lookups + planning only and writes nothing.
 */
async function syncPlannedLead(
  cfg: GlobalArgs,
  p: PlannedLeadValid,
  caches: {
    emailToPersonId: Map<string, string>;
    domainToCompanyId: Map<string, string>;
    leadIdToOpportunityId: Map<string, string>;
  },
  dryRun: boolean,
): Promise<PerLead> {
  // (2) PERSON — idempotent + non-destructive. leadId first, then email.
  let personId = caches.emailToPersonId.get(p.email);
  let personIsNew = false;
  if (!personId) {
    const byLead = await findPersonByLeadId(cfg, p.leadId);
    const existing = byLead ?? (await findPersonByEmail(cfg, p.email));
    if (existing) {
      // REUSE — never PATCH an existing person's structured fields.
      personId = String(existing.id ?? "");
    } else if (!dryRun) {
      personIsNew = true;
    }
    if (personId) caches.emailToPersonId.set(p.email, personId);
  }

  // (3) COMPANY — business + real corporate domain only; link to NEW person only.
  let companyId: string | undefined;
  if (p.companyDomain) {
    companyId = caches.domainToCompanyId.get(p.companyDomain);
    if (!companyId) {
      const existingCo = await findCompanyByDomain(cfg, p.companyDomain);
      if (existingCo) {
        companyId = String(existingCo.id ?? "");
      } else if (!dryRun) {
        const co = await createCompany(cfg, {
          name: p.companyName,
          domain: p.companyDomain,
        });
        companyId = String(co.id ?? "");
      }
      if (companyId) caches.domainToCompanyId.set(p.companyDomain, companyId);
    }
  }

  // Create the person now (after company, so a NEW person can carry companyId).
  if (personIsNew && !dryRun) {
    const person = await createPerson(cfg, {
      firstName: p.firstName,
      lastName: p.lastName,
      email: p.email,
      phone: p.phone,
      companyId,
      leadId: p.leadId,
    });
    personId = String(person.id ?? "");
    if (personId) caches.emailToPersonId.set(p.email, personId);
  }

  // (4) OPPORTUNITY — the idempotent unit. Skip if one already carries leadId.
  let opportunityId = caches.leadIdToOpportunityId.get(p.leadId);
  let action: "created" | "skipped";
  if (!opportunityId) {
    const existingOpp = await findOpportunityByLeadId(cfg, p.leadId);
    if (existingOpp) {
      opportunityId = String(existingOpp.id ?? "");
      action = "skipped";
    } else if (dryRun) {
      action = "created"; // planned
    } else {
      const opp = await createOpportunity(cfg, {
        name: `Inbound — ${p.firstName} ${p.lastName}`.replace(/\s+/g, " ")
          .trim(),
        stage: cfg.opportunityStage,
        pointOfContactId: personId ?? "",
        companyId,
        leadId: p.leadId,
      });
      opportunityId = String(opp.id ?? "");
      action = "created";
    }
    if (opportunityId) {
      caches.leadIdToOpportunityId.set(p.leadId, opportunityId);
    }
  } else {
    action = "skipped";
  }

  // (5) NOTE — ALWAYS (even when the opportunity was skipped), so a Note lost to
  // a prior partial failure is recovered on re-run. The free-text message + geo
  // are markdown-escaped so an attacker-submitted body can't inject a live
  // image/link into the CRM note (tracking-pixel / phishing) once rendered.
  let noteEnsured = false;
  if (!dryRun) {
    const bodyParts = [escapeMarkdown(p.message)];
    if (p.geo) bodyParts.push(`\n\n_Geo: ${escapeMarkdown(p.geo)}_`);
    const note = await ensureNoteForLead(cfg, {
      leadId: p.leadId,
      body: bodyParts.join("").trim() || `Inbound lead ${p.leadId}`,
      personId,
      opportunityId,
    });
    noteEnsured = Boolean(note.noteId);
  }

  // (6) EMERGENCY — evaluated ALWAYS, independent of the opportunity skip, so an
  // urgent alert can never be dropped: the `emergency` flag on the result (below)
  // is what fires the downstream notification. The isEmergency VISIBILITY marker,
  // however, is only set on records this run CREATED. The per-lead Opportunity is
  // safe (it belongs to this leadId). An EXISTING (reused) Person is NOT marked:
  // People are deduped by public-facing email, so flipping isEmergency on a
  // reused record would let an anonymous form submitter hide/reclassify a real
  // third party's contact. Best-effort — a marker failure never fails an
  // already-written lead (it retries on re-run).
  let markerFailed = false;
  if (p.emergency && !dryRun) {
    try {
      await setEmergencyMarker(cfg, {
        personId: personIsNew ? personId : undefined,
        opportunityId,
      });
    } catch (_e) {
      markerFailed = true;
    }
  }

  return {
    leadId: p.leadId,
    action,
    status: action === "skipped" ? "skipped" : "synced",
    personId,
    opportunityId,
    companyId,
    emergency: p.emergency,
    noteEnsured,
    ...(markerFailed ? { markerFailed: true } : {}),
  };
}

// --- Model ------------------------------------------------------------------

export const model = {
  type: "@shrug/twenty",
  version: "2026.09.05.1",
  description:
    "Drive a Twenty CRM instance over REST v1: People/Companies/Opportunities/Notes CRUD, leadId/email/domain idempotency finders, schema introspection, custom-field provisioning, and the push_leads fan-out that ingests contact-form leads (validate + sanitize + dedup + non-destructive reuse + always-Note + independent emergency path). Mutations are confirm-gated, support dryRun, and run a live reachability pre-flight.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "capability": {
      description: "Reachability + auth probe snapshot",
      schema: CapabilitySchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "schema": {
      description:
        "Introspection snapshot: objects, opportunity stage enum, required custom-field presence",
      schema: SchemaSnapshotSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "fieldsEnsured": {
      description: "Record of an ensureLeadFields run (created/present/failed)",
      schema: FieldsEnsuredSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "record": {
      description:
        "Reference to a single Person/Company/Opportunity/Note touched by a base method",
      schema: RecordRefSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "pushRun": {
      description:
        "Audit of one push_leads run: counts + per-lead results (no raw PII beyond leadId)",
      schema: PushRunSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
  },
  methods: {
    ping: {
      description:
        "Probe the Twenty instance: an authed GET /rest/people?limit=1. A 2xx proves it is reachable AND the token authenticates. Snapshots a `capability` resource.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        let reachable = false;
        let detail: string | undefined;
        try {
          await probeReachable(cfg);
          reachable = true;
          context.logger.info("Twenty {baseUrl} reachable + authenticated", {
            baseUrl: cfg.baseUrl,
          });
        } catch (e) {
          detail = e instanceof Error ? e.message : String(e);
          context.logger.warning("Twenty {baseUrl} probe failed: {detail}", {
            baseUrl: cfg.baseUrl,
            detail,
          });
        }
        const handle = await context.writeResource("capability", "capability", {
          baseUrl: cfg.baseUrl,
          reachable,
          authenticated: reachable,
          detail,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    introspectSchema: {
      description:
        "Read live object/field metadata (GET /rest/metadata/objects): list objects, discover the Opportunity stage enum, and report whether the required leadId/isEmergency custom fields exist on Person/Opportunity/Note. Snapshots a `schema` resource. Run this before trusting leadId filters.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const json = await twentyRequest(cfg, "GET", "/rest/metadata/objects");
        const objs = ((json as { data?: unknown }).data ?? []) as Array<
          Record<string, unknown>
        >;
        const byName = new Map<string, Record<string, unknown>>();
        for (const o of objs) byName.set(String(o.nameSingular ?? ""), o);

        const fieldNames = (o?: Record<string, unknown>): Set<string> => {
          const flds = (o?.fields ?? []) as Array<Record<string, unknown>>;
          return new Set(
            (Array.isArray(flds) ? flds : []).map((f) => String(f.name ?? "")),
          );
        };
        const requiredFields = REQUIRED_FIELDS.map((rf) => ({
          object: rf.object,
          name: rf.name,
          present: fieldNames(byName.get(rf.object)).has(rf.name),
        }));

        // Opportunity stage enum, if the SELECT field exposes its options.
        let opportunityStages: string[] = [];
        const oppFields = (byName.get("opportunity")?.fields ?? []) as Array<
          Record<string, unknown>
        >;
        const stageField = (Array.isArray(oppFields) ? oppFields : []).find(
          (f) => String(f.name ?? "") === "stage",
        );
        const opts = (stageField?.options ?? []) as Array<
          Record<string, unknown>
        >;
        if (Array.isArray(opts)) {
          opportunityStages = opts.map((o) => String(o.value ?? o.label ?? ""))
            .filter(Boolean);
        }

        const handle = await context.writeResource("schema", "schema", {
          baseUrl: cfg.baseUrl,
          objects: [...byName.keys()].filter(Boolean).sort(),
          opportunityStages,
          requiredFields,
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    ensureLeadFields: {
      description:
        "Idempotently provision the custom fields the lead sink depends on: leadId (TEXT) on Person/Opportunity/Note and isEmergency (BOOLEAN) on Person/Opportunity, via POST /rest/metadata/fields. Already-present fields are skipped. Confirm-gated (mutates workspace metadata). Snapshots a `fieldsEnsured` resource.",
      arguments: z.object({
        confirm: z
          .boolean()
          .default(false)
          .describe(
            "Must be true to apply — mutates workspace object metadata",
          ),
      }),
      execute: async (
        args: { confirm: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        if (!args.confirm) {
          throw new Error(
            "Refusing to ensure fields without confirm:true (mutates workspace metadata)",
          );
        }
        const ids = await objectMetadataIds(cfg);
        // Presence per object.
        const json = await twentyRequest(cfg, "GET", "/rest/metadata/objects");
        const objs = ((json as { data?: unknown }).data ?? []) as Array<
          Record<string, unknown>
        >;
        const present = new Map<string, Set<string>>();
        for (const o of objs) {
          const flds = (o.fields ?? []) as Array<Record<string, unknown>>;
          present.set(
            String(o.nameSingular ?? ""),
            new Set(
              (Array.isArray(flds) ? flds : []).map((f) =>
                String(f.name ?? "")
              ),
            ),
          );
        }
        const created: string[] = [];
        const alreadyPresent: string[] = [];
        const failed: Array<{ field: string; error: string }> = [];
        for (const rf of REQUIRED_FIELDS) {
          const key = `${rf.object}.${rf.name}`;
          if (present.get(rf.object)?.has(rf.name)) {
            alreadyPresent.push(key);
            continue;
          }
          const objectMetadataId = ids.get(rf.object);
          if (!objectMetadataId) {
            failed.push({ field: key, error: `object ${rf.object} not found` });
            continue;
          }
          try {
            await twentyRequest(cfg, "POST", "/rest/metadata/fields", {
              name: rf.name,
              label: rf.label,
              type: rf.type,
              objectMetadataId,
            });
            created.push(key);
          } catch (e) {
            failed.push({ field: key, error: redactError(e) });
          }
        }
        context.logger.info(
          "ensureLeadFields: {created} created, {present} present, {failed} failed",
          {
            created: created.length,
            present: alreadyPresent.length,
            failed: failed.length,
          },
        );
        const handle = await context.writeResource(
          "fieldsEnsured",
          "fieldsEnsured",
          {
            baseUrl: cfg.baseUrl,
            created,
            alreadyPresent,
            failed,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    findPersonByLeadId: {
      description:
        "Look up a Person by the immutable leadId marker (GET /rest/people?filter=leadId[eq]:<id>). Snapshots a `record` reference if found; writes nothing if not.",
      arguments: z.object({
        leadId: z.string().describe("Opaque upstream lead id"),
      }),
      execute: async (
        args: { leadId: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const leadId = validateLeadId(args.leadId);
        if (!leadId) throw new Error("Invalid leadId");
        const person = await findPersonByLeadId(cfg, leadId);
        if (!person) {
          context.logger.info("No person for leadId {leadId}", { leadId });
          return { dataHandles: [] };
        }
        const handle = await context.writeResource(
          "record",
          `person-${person.id}`,
          {
            baseUrl: cfg.baseUrl,
            id: String(person.id ?? ""),
            kind: "person",
            leadId,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    findOpportunityByLeadId: {
      description:
        "Look up an Opportunity by the immutable leadId marker (GET /rest/opportunities?filter=leadId[eq]:<id>) — the primary idempotency check. Snapshots a `record` reference if found.",
      arguments: z.object({
        leadId: z.string().describe("Opaque upstream lead id"),
      }),
      execute: async (
        args: { leadId: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const leadId = validateLeadId(args.leadId);
        if (!leadId) throw new Error("Invalid leadId");
        const opp = await findOpportunityByLeadId(cfg, leadId);
        if (!opp) return { dataHandles: [] };
        const handle = await context.writeResource(
          "record",
          `opportunity-${opp.id}`,
          {
            baseUrl: cfg.baseUrl,
            id: String(opp.id ?? ""),
            kind: "opportunity",
            leadId,
            retrievedAt: new Date().toISOString(),
          },
        );
        return { dataHandles: [handle] };
      },
    },
    push_leads: {
      description:
        "THE fan-out lead sink (repo rule 6). Ingest a batch of contact-form leads into Twenty in one execution: select status=='new', FIFO by received_at, capped at maxBatch. Per lead, isolated in try/catch: validate + sanitize every field FIRST (bad lead => failed, no writes); reuse but NEVER structurally mutate an existing Person; create/link a Company only for business leads on a real corporate domain; create exactly one Opportunity keyed on leadId (skip if it exists); ALWAYS ensure the per-lead message Note; and set the emergency alert flag + isEmergency marker INDEPENDENTLY of the opportunity skip. dryRun=true does lookups + a plan and writes nothing. confirm=true is required for a real run. Returns counts + per-lead results (no raw PII beyond leadId) in a `pushRun` resource.",
      arguments: z.object({
        leads: z
          .array(LeadRecordSchema)
          .describe(
            "Inbound leads (typically mapped from the Fastly KV store)",
          ),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true for a real run (writes to Twenty)"),
        dryRun: z
          .boolean()
          .default(false)
          .describe("Validate + plan + look up, but write nothing"),
        maxBatch: z
          .number()
          .int()
          .positive()
          .default(200)
          .describe(
            "Max leads processed this run (oldest first; rest reported)",
          ),
      }),
      execute: async (
        args: {
          leads: LeadRecord[];
          confirm: boolean;
          dryRun: boolean;
          maxBatch: number;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        if (!args.dryRun && !args.confirm) {
          throw new Error(
            "Refusing to push leads without confirm:true (use dryRun:true to plan)",
          );
        }
        const { batch, cap, remaining, eligible } = selectBatch(
          args.leads,
          args.maxBatch,
        );
        context.logger.info(
          "push_leads: {eligible} eligible, processing {n} (cap {cap}), {remaining} remaining{dry}",
          {
            eligible,
            n: batch.length,
            cap,
            remaining,
            dry: args.dryRun ? " [dryRun]" : "",
          },
        );

        const caches = {
          emailToPersonId: new Map<string, string>(),
          domainToCompanyId: new Map<string, string>(),
          leadIdToOpportunityId: new Map<string, string>(),
        };
        const results: PerLead[] = [];
        for (const lead of batch) {
          const planned = planLead(lead, cfg.emailDomainBlocklist);
          if (!planned.ok) {
            results.push({
              leadId: planned.leadId ?? "unknown",
              action: "failed",
              status: "failed",
              emergency: false,
              noteEnsured: false,
              error: planned.reason,
            });
            continue;
          }
          try {
            results.push(
              await syncPlannedLead(cfg, planned, caches, args.dryRun),
            );
          } catch (e) {
            results.push({
              leadId: planned.leadId,
              action: "failed",
              status: "failed",
              emergency: planned.emergency,
              noteEnsured: false,
              error: redactError(e),
            });
          }
        }

        const synced = results.filter((r) => r.status === "synced").length;
        const skipped = results.filter((r) => r.status === "skipped").length;
        const failed = results.filter((r) => r.status === "failed").length;
        const emergencies = results.filter((r) => r.emergency).length;

        const handle = await context.writeResource("pushRun", "pushRun", {
          baseUrl: cfg.baseUrl,
          dryRun: args.dryRun,
          synced,
          skipped,
          failed,
          results,
          audit: {
            at: new Date().toISOString(),
            cap,
            eligible,
            processed: batch.length,
            remaining,
            emergencies,
            perLead: results.map((r) => ({
              leadId: r.leadId,
              action: r.action,
              status: r.status,
              emergency: r.emergency,
            })),
          },
        });
        context.logger.info(
          "push_leads done: {synced} synced, {skipped} skipped, {failed} failed, {emergencies} emergencies",
          { synced, skipped, failed, emergencies },
        );
        return { dataHandles: [handle] };
      },
    },
  },
  checks: {
    "reachable": {
      description:
        "Verify the Twenty instance responds and the API token authenticates (authed GET /rest/people?limit=1) before a write.",
      labels: ["live"],
      appliesTo: ["ensureLeadFields", "push_leads"],
      execute: async (
        context: { globalArgs: GlobalArgs; logger?: MethodLogger },
      ): Promise<{ pass: boolean; errors?: string[] }> => {
        const cfg = context.globalArgs;
        try {
          await probeReachable(cfg);
          context.logger?.info("Twenty {baseUrl} reachable", {
            baseUrl: cfg.baseUrl,
          });
          return { pass: true };
        } catch (e) {
          return {
            pass: false,
            errors: [
              `Twenty instance ${cfg.baseUrl} is not reachable or the API ` +
              `token is invalid: ` +
              (e instanceof Error ? e.message : String(e)),
            ],
          };
        }
      },
    },
  },
};
