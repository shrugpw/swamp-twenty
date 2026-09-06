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

// --- Generalized opportunity upsert helpers ---------------------------------

/**
 * Twenty CURRENCY composite for a whole-currency amount. Twenty stores money as
 * integer micros (1 unit = 1_000_000 micros), so $50,000 -> 50_000_000_000.
 */
export function toCurrency(
  amount: number,
  currencyCode: string,
): { amountMicros: number; currencyCode: string } {
  return { amountMicros: Math.round(amount * 1_000_000), currencyCode };
}

const DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Normalize a close date to an ISO datetime (Twenty's closeDate is DATE_TIME).
 * A bare `YYYY-MM-DD` is anchored to midnight UTC; any other parseable string is
 * passed through Date. Returns null for empty/unparseable input.
 */
export function normalizeCloseDate(raw: unknown): string | null {
  if (raw == null) return null;
  const s = String(raw).trim();
  if (!s) return null;
  if (DATE_ONLY_RE.test(s)) return `${s}T00:00:00.000Z`;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

/** Fields writable on an Opportunity by upsertOpportunity. */
interface OpportunityWriteFields {
  name?: string;
  stage?: string;
  amount?: { amountMicros: number; currencyCode: string };
  closeDate?: string;
  pointOfContactId?: string;
  companyId?: string;
  isEmergency?: boolean;
}

/** Assemble a REST body from only the fields that are set (partial-update safe). */
function buildOpportunityBody(
  f: OpportunityWriteFields,
): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  if (f.name !== undefined) body.name = f.name;
  if (f.stage !== undefined) body.stage = f.stage;
  if (f.amount !== undefined) body.amount = f.amount;
  if (f.closeDate !== undefined) body.closeDate = f.closeDate;
  if (f.pointOfContactId) body.pointOfContactId = f.pointOfContactId;
  if (f.companyId) body.companyId = f.companyId;
  if (f.isEmergency !== undefined) body.isEmergency = f.isEmergency;
  return body;
}

/** Create an Opportunity with the full generalized field set, keyed on leadId. */
async function createOpportunityFull(
  cfg: TwentyCfg,
  leadId: string,
  f: OpportunityWriteFields,
): Promise<Record<string, unknown>> {
  const body = { ...buildOpportunityBody(f), leadId };
  const json = await twentyRequest(cfg, "POST", "/rest/opportunities", body);
  return unwrapRecord(json, "createOpportunity");
}

/** Patch an existing Opportunity by id with only the provided fields. */
async function updateOpportunity(
  cfg: TwentyCfg,
  id: string,
  f: OpportunityWriteFields,
): Promise<Record<string, unknown>> {
  const json = await twentyRequest(
    cfg,
    "PATCH",
    `/rest/opportunities/${id}`,
    buildOpportunityBody(f),
  );
  return unwrapRecord(json, "updateOpportunity");
}

/**
 * Twenty filter-DSL operator characters. A value containing any of these is not
 * safe to interpolate into a `filter=field[eq]:<value>` expression even
 * URL-encoded, so callers reject/skip such values (defense-in-depth beyond the
 * URL-encoding in buildFilterPath).
 */
const FILTER_UNSAFE_RE = /[[\]():;,]/;

/** True if a free-text value is safe to use as a filter [eq] value. */
export function isFilterSafe(value: string): boolean {
  return value.length > 0 && !FILTER_UNSAFE_RE.test(value);
}

/**
 * Find exactly one Company by domain. Throws on an ambiguous (>1) match rather
 * than silently taking the first, so a mislink can't happen unnoticed.
 */
async function findOneCompanyByDomain(
  cfg: TwentyCfg,
  domain: string,
): Promise<Record<string, unknown> | null> {
  const list = unwrapList(
    await twentyRequest(
      cfg,
      "GET",
      buildFilterPath("/rest/companies", "domainName.primaryLinkUrl", domain),
    ),
    "companies",
  );
  if (list.length > 1) {
    throw new Error(
      `Ambiguous company domain '${domain}': ${list.length} matches`,
    );
  }
  return list[0] ?? null;
}

/**
 * Find exactly one Company by exact name. The name must already be filter-safe
 * (see isFilterSafe). Throws on an ambiguous (>1) match; returns null if the
 * name field is not filterable on this instance rather than aborting the call.
 */
async function findOneCompanyByName(
  cfg: TwentyCfg,
  name: string,
): Promise<Record<string, unknown> | null> {
  try {
    const list = unwrapList(
      await twentyRequest(
        cfg,
        "GET",
        buildFilterPath("/rest/companies", "name", name),
      ),
      "companies",
    );
    if (list.length > 1) {
      throw new Error(
        `Ambiguous company name '${name}': ${list.length} matches`,
      );
    }
    return list[0] ?? null;
  } catch (e) {
    if (e instanceof Error && /^Ambiguous/.test(e.message)) throw e;
    return null; // name not filterable on this instance
  }
}

/** Find exactly one Person by primary email. Throws on an ambiguous match. */
async function findOnePersonByEmail(
  cfg: TwentyCfg,
  email: string,
): Promise<Record<string, unknown> | null> {
  const list = unwrapList(
    await twentyRequest(
      cfg,
      "GET",
      buildFilterPath("/rest/people", "emails.primaryEmail", email),
    ),
    "people",
  );
  if (list.length > 1) {
    throw new Error(
      `Ambiguous person email '${email}': ${list.length} matches`,
    );
  }
  return list[0] ?? null;
}

// --- Read-surface helpers (TWENTY-READ-SURFACE) -----------------------------

// A Twenty record id is a UUID. Validating it before path interpolation keeps a
// hostile value from breaking out of `/rest/<object>/<id>` (path-injection) and
// lets get-by-id reject junk before a round-trip.
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Validate a Twenty UUID id (lowercased); null if malformed. */
export function validateUuid(raw: unknown): string | null {
  if (raw == null) return null;
  const s = String(raw).trim().toLowerCase();
  return UUID_RE.test(s) ? s : null;
}

/** Inverse of {@link toCurrency}: integer micros back to whole currency units. */
export function amountFromMicros(micros: number): number {
  return micros / 1_000_000;
}

/** Pull {amount (whole units), currencyCode} out of a Twenty CURRENCY composite. */
function extractAmount(
  rec: Record<string, unknown>,
): { amount?: number; currencyCode?: string } {
  const a = rec.amount as
    | { amountMicros?: unknown; currencyCode?: unknown }
    | null
    | undefined;
  if (!a || typeof a.amountMicros !== "number") return {};
  const out: { amount?: number; currencyCode?: string } = {
    amount: amountFromMicros(a.amountMicros),
  };
  if (a.currencyCode) out.currencyCode = String(a.currencyCode);
  return out;
}

/** Reconcile-facing view of an Opportunity record (no bulk PII). */
export interface OppView {
  id: string;
  leadId?: string;
  name: string;
  stage: string;
  amount?: number;
  currencyCode?: string;
  closeDate?: string;
  companyId?: string;
}

/** Map a raw Opportunity REST record to the compact {@link OppView}. */
export function mapOppView(rec: Record<string, unknown>): OppView {
  const { amount, currencyCode } = extractAmount(rec);
  const v: OppView = {
    id: String(rec.id ?? ""),
    name: String(rec.name ?? ""),
    stage: String(rec.stage ?? ""),
  };
  if (rec.leadId != null && rec.leadId !== "") v.leadId = String(rec.leadId);
  if (amount !== undefined) v.amount = amount;
  if (currencyCode) v.currencyCode = currencyCode;
  if (rec.closeDate) v.closeDate = String(rec.closeDate);
  if (rec.companyId) v.companyId = String(rec.companyId);
  return v;
}

/**
 * GET a single record by id, returning null on a 404 (record absent) rather than
 * throwing. `op` is the singular object key in the `{data:{<op>:{...}}}` envelope
 * Twenty returns for a by-id read. Any non-404 error still throws.
 */
async function getByIdOrNull(
  cfg: TwentyCfg,
  path: string,
  op: string,
): Promise<Record<string, unknown> | null> {
  try {
    const json = await twentyRequest(cfg, "GET", path);
    const rec = unwrapRecord(json, op);
    return rec && Object.keys(rec).length ? rec : null;
  } catch (e) {
    if (e instanceof Error && /failed: 404\b/.test(e.message)) return null;
    throw e;
  }
}

const getOpportunityById = (cfg: TwentyCfg, id: string) =>
  getByIdOrNull(cfg, `/rest/opportunities/${id}`, "opportunity");
const getPersonById = (cfg: TwentyCfg, id: string) =>
  getByIdOrNull(cfg, `/rest/people/${id}`, "person");
const getCompanyById = (cfg: TwentyCfg, id: string) =>
  getByIdOrNull(cfg, `/rest/companies/${id}`, "company");

// Twenty caps a single REST page at 60 records; MAX_LIST_CAP bounds how many a
// single listOpportunities call will page through before flagging `truncated`.
const PAGE_SIZE = 60;
const MAX_LIST_CAP = 500;

/**
 * Fan-out read (repo rule 6): page through all Opportunities matching the given
 * filters in ONE call. Filters compose with AND (comma-joined `field[eq]:value`
 * clauses in a single `filter=` param — each value is UUID/filter-safe validated
 * by the caller and URL-encoded here). Cursor pagination advances on
 * `pageInfo.endCursor`; a no-progress guard (a page yielding zero *new* ids, a
 * missing/repeated cursor) hard-stops so a wrong cursor field can never
 * infinite-loop, and items are deduped by id. `truncated` is set only when the
 * result is actually capped at MAX_LIST_CAP/limit with more records available.
 */
async function listOpportunitiesFiltered(
  cfg: TwentyCfg,
  opts: { companyId?: string; stage?: string; limit: number },
): Promise<{ items: Array<Record<string, unknown>>; truncated: boolean }> {
  const cap = Math.min(Math.max(1, Math.floor(opts.limit)), MAX_LIST_CAP);
  const clauses: string[] = [];
  if (opts.companyId) {
    clauses.push(`companyId[eq]:${encodeURIComponent(opts.companyId)}`);
  }
  if (opts.stage) clauses.push(`stage[eq]:${encodeURIComponent(opts.stage)}`);
  const filterQ = clauses.length ? `filter=${clauses.join(",")}&` : "";

  const seen = new Set<string>();
  const items: Array<Record<string, unknown>> = [];
  let cursor: string | undefined;
  let truncated = false;
  // Backstop on page count in case the instance never reports hasNextPage:false.
  const maxPages = Math.ceil(cap / PAGE_SIZE) + 2;
  for (let page = 0; page < maxPages; page++) {
    const path = `/rest/opportunities?${filterQ}limit=${PAGE_SIZE}` +
      (cursor ? `&starting_after=${encodeURIComponent(cursor)}` : "");
    const json = await twentyRequest(cfg, "GET", path);
    const batch = unwrapList(json, "opportunities");
    let newInPage = 0;
    let hitCap = false;
    for (const rec of batch) {
      const id = String(rec.id ?? "");
      if (!id || seen.has(id)) continue;
      newInPage++;
      if (items.length >= cap) {
        hitCap = true;
        break;
      }
      seen.add(id);
      items.push(rec);
    }
    if (hitCap) {
      truncated = true;
      break;
    }
    // No-progress guard: a wrong/looping cursor surfaces zero new ids -> stop.
    if (newInPage === 0) break;
    const pageInfo = (json as {
      pageInfo?: { hasNextPage?: boolean; endCursor?: string };
    }).pageInfo;
    if (
      !pageInfo?.hasNextPage || !pageInfo.endCursor ||
      pageInfo.endCursor === cursor
    ) {
      break;
    }
    cursor = pageInfo.endCursor;
  }
  return { items, truncated };
}

/**
 * Read the Opportunity object's live metadata: the `stage` SELECT enum values
 * and the `closeDate` field type (DATE vs DATE_TIME). Used to fail fast on an
 * invalid stage and to format closeDate correctly for the instance.
 */
async function fetchOpportunityMeta(
  cfg: TwentyCfg,
): Promise<{ stages: string[]; closeDateType: string | null }> {
  const json = await twentyRequest(cfg, "GET", "/rest/metadata/objects");
  const objs = ((json as { data?: unknown }).data ?? []) as Array<
    Record<string, unknown>
  >;
  const opp = objs.find((o) => String(o.nameSingular ?? "") === "opportunity");
  const fields = (opp?.fields ?? []) as Array<Record<string, unknown>>;
  const list = Array.isArray(fields) ? fields : [];
  const stageField = list.find((f) => String(f.name ?? "") === "stage");
  const opts = (stageField?.options ?? []) as Array<Record<string, unknown>>;
  const stages = Array.isArray(opts)
    ? opts.map((o) => String(o.value ?? o.label ?? "")).filter(Boolean)
    : [];
  const cdField = list.find((f) => String(f.name ?? "") === "closeDate");
  const closeDateType = cdField ? (String(cdField.type ?? "") || null) : null;
  return { stages, closeDateType };
}

// --- SELECT-option provisioning helpers (TWENTY-STAGE-OPTION) ----------------

// SO-4: only these (object,field) pairs may be targeted, so a typo/CEL slip can
// never append an option to the wrong picklist. Extend deliberately.
const STAGE_OPTION_ALLOWLIST = new Set<string>(["opportunity.stage"]);

// Twenty option tokens are UPPER_SNAKE (letters/digits/underscore, no spaces).
const STAGE_OPTION_VALUE_RE = /^[A-Z][A-Z0-9_]*$/;

// Twenty's SELECT-option color palette. `gray` is the neutral default.
const STAGE_OPTION_COLORS = new Set<string>([
  "green",
  "turquoise",
  "sky",
  "blue",
  "purple",
  "pink",
  "red",
  "orange",
  "yellow",
  "gray",
]);

/** Default label for an option token: CLOSED -> "Closed", CLOSED_WON -> "Closed Won". */
export function titleCaseToken(value: string): string {
  return value
    .split("_")
    .filter(Boolean)
    .map((w) => w[0] + w.slice(1).toLowerCase())
    .join(" ");
}

interface SelectOption {
  id?: string;
  value: string;
  label: string;
  color: string;
  position: number;
}

interface SelectFieldMeta {
  objectId: string;
  fieldId: string;
  type: string;
  options: SelectOption[];
}

/**
 * Read a SELECT field's full metadata: object id, field id, type, and every
 * existing option as a complete {id?,value,label,color,position} object. Richer
 * than {@link fetchOpportunityMeta} (which returns stage VALUES only) because a
 * safe append-and-PATCH must rebuild the WHOLE options array verbatim.
 *
 * HARD-stops (throws) rather than degrading if: the object/field is absent, the
 * field is not exactly SELECT (SO-6 — MULTI_SELECT and every other type are
 * rejected in v1), the field has no id, or ANY existing option is missing
 * value/label/color/position (SO-1 — never write a lossy array that would drop
 * fields the server round-trips). Reading metadata is mandatory here, unlike
 * upsertOpportunity's best-effort posture.
 */
async function fetchSelectField(
  cfg: TwentyCfg,
  objectNameSingular: string,
  fieldName: string,
): Promise<SelectFieldMeta> {
  const json = await twentyRequest(cfg, "GET", "/rest/metadata/objects");
  const objs = ((json as { data?: unknown }).data ?? []) as Array<
    Record<string, unknown>
  >;
  const obj = objs.find((o) =>
    String(o.nameSingular ?? "") === objectNameSingular
  );
  if (!obj) {
    throw new Error(
      `Object '${objectNameSingular}' not found in workspace metadata`,
    );
  }
  const objectId = String(obj.id ?? "");
  const fields = (obj.fields ?? []) as Array<Record<string, unknown>>;
  const field = (Array.isArray(fields) ? fields : []).find((f) =>
    String(f.name ?? "") === fieldName
  );
  if (!field) {
    throw new Error(
      `Field '${objectNameSingular}.${fieldName}' not found in workspace metadata`,
    );
  }
  const type = String(field.type ?? "");
  if (type !== "SELECT") {
    throw new Error(
      `Field '${objectNameSingular}.${fieldName}' is type '${type}', not SELECT — v1 supports SELECT only`,
    );
  }
  const fieldId = String(field.id ?? "");
  if (!fieldId) {
    throw new Error(
      `Field '${objectNameSingular}.${fieldName}' has no id in metadata; cannot safely PATCH its options`,
    );
  }
  const rawOpts = field.options;
  if (!Array.isArray(rawOpts)) {
    throw new Error(
      `Field '${objectNameSingular}.${fieldName}' exposes no readable options array; refusing a lossy write`,
    );
  }
  const options: SelectOption[] = rawOpts.map((o, i) => {
    const opt = o as Record<string, unknown>;
    const { value, label, color, position } = opt;
    if (
      typeof value !== "string" || typeof label !== "string" ||
      typeof color !== "string" || typeof position !== "number"
    ) {
      throw new Error(
        `Option #${i} on '${objectNameSingular}.${fieldName}' is missing value/label/color/position; refusing to rebuild a lossy options array`,
      );
    }
    const so: SelectOption = { value, label, color, position };
    if (typeof opt.id === "string" && opt.id) so.id = opt.id;
    return so;
  });
  return { objectId, fieldId, type, options };
}

/** True if two option arrays are equivalent (keyed by value; id/label/color/position). */
function optionsEquivalent(a: SelectOption[], b: SelectOption[]): boolean {
  if (a.length !== b.length) return false;
  const key = (o: SelectOption) =>
    JSON.stringify([o.value, o.label, o.color, o.position, o.id ?? ""]);
  const setB = new Set(b.map(key));
  return a.every((o) => setB.has(key(o)));
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

const OpportunityUpsertSchema = z.object({
  baseUrl: z.string(),
  action: z.enum(["created", "updated", "planned-create", "planned-update"]),
  dryRun: z.boolean(),
  leadId: z.string(),
  opportunityId: z.string().optional(),
  name: z.string(),
  stage: z.string(),
  amount: z.number().optional().describe("Deal value in whole currency units"),
  currencyCode: z.string().optional(),
  closeDate: z.string().optional(),
  companyId: z.string().optional(),
  companyLinked: z.boolean().describe("A company was found/created and linked"),
  companyNote: z
    .string()
    .optional()
    .describe("Why a company was not linked (degraded path), if applicable"),
  pointOfContactId: z.string().optional(),
  pocSkipped: z
    .string()
    .optional()
    .describe("Why the point of contact was not linked, if applicable"),
  noteEnsured: z.boolean(),
  retrievedAt: z.iso.datetime(),
});

// --- Read-surface snapshots (TWENTY-READ-SURFACE) ---------------------------
// Existence-check snapshots for the reconcile audit. `found` distinguishes
// "looked, not there" from "never looked". Deliberately carry NO bulk PII — only
// the opaque join keys the caller supplied or needs (ids, leadId, companyId,
// business domain/name), never an email/phone body.

const PersonRefSchema = z.object({
  baseUrl: z.string(),
  found: z.boolean(),
  id: z.string().optional(),
  leadId: z.string().optional(),
  companyId: z.string().optional(),
  retrievedAt: z.iso.datetime(),
});

const CompanyRefSchema = z.object({
  baseUrl: z.string(),
  found: z.boolean(),
  id: z.string().optional(),
  domain: z.string().optional(),
  name: z.string().optional(),
  retrievedAt: z.iso.datetime(),
});

const OpportunityRefSchema = z.object({
  baseUrl: z.string(),
  found: z.boolean(),
  id: z.string().optional(),
  leadId: z.string().optional(),
  name: z.string().optional(),
  stage: z.string().optional(),
  amount: z.number().optional().describe("Deal value in whole currency units"),
  currencyCode: z.string().optional(),
  closeDate: z.string().optional(),
  companyId: z.string().optional(),
  pointOfContactId: z.string().optional(),
  retrievedAt: z.iso.datetime(),
});

const OppViewSchema = z.object({
  id: z.string(),
  leadId: z.string().optional(),
  name: z.string(),
  stage: z.string(),
  amount: z.number().optional(),
  currencyCode: z.string().optional(),
  closeDate: z.string().optional(),
  companyId: z.string().optional(),
});

const OpportunityListSchema = z.object({
  baseUrl: z.string(),
  count: z.number(),
  truncated: z
    .boolean()
    .describe("True if the result was capped with more records available"),
  filter: z.object({
    companyId: z.string().optional(),
    stage: z.string().optional(),
  }),
  items: z.array(OppViewSchema),
  retrievedAt: z.iso.datetime(),
});

// --- SELECT-option snapshot (TWENTY-STAGE-OPTION) ---------------------------

const StageOptionSchema = z.object({
  baseUrl: z.string(),
  object: z.string(),
  field: z.string(),
  value: z.string(),
  label: z.string(),
  color: z.string(),
  action: z.enum(["present", "created", "planned-create"]),
  mismatchNote: z
    .string()
    .optional()
    .describe(
      "Set when the value already exists with a different label/color (left unchanged)",
    ),
  options: z
    .array(
      z.object({
        value: z.string(),
        label: z.string(),
        color: z.string(),
        position: z.number(),
      }),
    )
    .describe("The resulting (or planned, on dryRun) full option set"),
  retrievedAt: z.iso.datetime(),
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
  version: "2026.09.06.2",
  description:
    "Drive a Twenty CRM instance over REST v1: People/Companies/Opportunities/Notes CRUD, leadId/email/domain idempotency finders, schema introspection, custom-field provisioning, and the push_leads fan-out that ingests contact-form leads (validate + sanitize + dedup + non-destructive reuse + always-Note + independent emergency path). Mutations are confirm-gated, support dryRun, and run a live reachability pre-flight.",
  globalArguments: GlobalArgsSchema,
  upgrades: [
    {
      toVersion: "2026.09.05.2",
      description:
        "Add the generalized upsertOpportunity method and opportunityUpsert resource. globalArguments is unchanged, so this is a no-op attribute migration (existing instances upgrade cleanly with no field changes).",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.06.1",
      description:
        "Add the read surface: findPerson/findCompany/getOpportunity/listOpportunities plus getPersonById/getCompanyById, and the personRef/companyRef/opportunityRef/opportunityList snapshots. All additive and side-effect-free; globalArguments is unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.06.2",
      description:
        "Add ensureStageOption (confirm-gated, allowlisted SELECT-option provisioning) and the stageOption snapshot. globalArguments is unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
  ],
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
    "opportunityUpsert": {
      description:
        "Result of an upsertOpportunity run: the action taken and the resolved opportunity/company/contact ids",
      schema: OpportunityUpsertSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "personRef": {
      description:
        "Existence-check snapshot from findPerson/getPersonById (found + join keys, no bulk PII)",
      schema: PersonRefSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "companyRef": {
      description:
        "Existence-check snapshot from findCompany/getCompanyById (found + id/domain/name)",
      schema: CompanyRefSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "opportunityRef": {
      description:
        "Snapshot from getOpportunity: the reconcile-critical opportunity fields (id, leadId, name, stage, amount, ...)",
      schema: OpportunityRefSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "opportunityList": {
      description:
        "Snapshot from listOpportunities: a filtered, paginated set of opportunity views + truncation flag",
      schema: OpportunityListSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "stageOption": {
      description:
        "Result of an ensureStageOption run: the target picklist, the option, the action taken, and the full option set",
      schema: StageOptionSchema,
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
    ensureStageOption: {
      description:
        "Idempotently ensure a SELECT option exists on an allowlisted picklist field (default opportunity.stage), so an Opportunity can be set to a stage the workspace didn't ship with (e.g. CLOSED). Reads the field's FULL option set and appends the new option, preserving every existing option (id/label/color/position) verbatim — never a drop, reorder, or recolor. If the value already exists it is a no-op (action:present; a differing label/color is reported, never mutated). Confirm-gated (mutates workspace metadata); dryRun previews the planned option array without writing. SELECT-only; MULTI_SELECT and unknown targets are rejected. Snapshots a `stageOption` resource.",
      arguments: z.object({
        objectNameSingular: z
          .string()
          .default("opportunity")
          .describe(
            "Object owning the field (allowlisted; default opportunity)",
          ),
        fieldName: z
          .string()
          .default("stage")
          .describe("SELECT field name (allowlisted; default stage)"),
        value: z
          .string()
          .describe("Option token to ensure — UPPER_SNAKE (e.g. CLOSED)"),
        label: z
          .string()
          .optional()
          .describe("Display label; defaults to a title-cased value"),
        color: z
          .string()
          .default("gray")
          .describe("Option color from Twenty's palette; defaults gray"),
        position: z
          .number()
          .int()
          .optional()
          .describe("Sort position; defaults to append after the current max"),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to apply — mutates workspace metadata"),
        dryRun: z
          .boolean()
          .default(false)
          .describe("Preview the planned option array; write nothing"),
      }),
      execute: async (
        args: {
          objectNameSingular: string;
          fieldName: string;
          value: string;
          label?: string;
          color: string;
          position?: number;
          confirm: boolean;
          dryRun: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          // SO-4: reject any target not on the allowlist BEFORE any I/O.
          const target = `${args.objectNameSingular}.${args.fieldName}`;
          if (!STAGE_OPTION_ALLOWLIST.has(target)) {
            throw new Error(
              `Target '${target}' is not on the ensureStageOption allowlist (allowed: ${
                [...STAGE_OPTION_ALLOWLIST].join(", ")
              })`,
            );
          }
          const value = String(args.value ?? "").trim();
          if (!STAGE_OPTION_VALUE_RE.test(value)) {
            throw new Error(
              "Invalid option value: must be UPPER_SNAKE (A-Z, 0-9, _), no spaces",
            );
          }
          const color = String(args.color ?? "gray");
          if (!STAGE_OPTION_COLORS.has(color)) {
            throw new Error(
              `Invalid color '${color}' (allowed: ${
                [...STAGE_OPTION_COLORS].join(", ")
              })`,
            );
          }
          const label = args.label != null && String(args.label).trim()
            ? sanitizeText(args.label, 60)
            : titleCaseToken(value);
          // dryRun is allowed without confirm; a real write requires confirm.
          if (!args.confirm && !args.dryRun) {
            throw new Error(
              "Refusing to ensure a stage option without confirm:true (mutates workspace metadata). Use dryRun:true to preview.",
            );
          }

          // SO-1: mandatory full-shape read; HARD-stops on a lossy/absent option set.
          const field = await fetchSelectField(
            cfg,
            args.objectNameSingular,
            args.fieldName,
          );
          const existing = field.options.find((o) => o.value === value);

          let action: "present" | "created" | "planned-create";
          let mismatchNote: string | undefined;
          let resultOptions: SelectOption[];

          if (existing) {
            action = "present";
            resultOptions = field.options;
            if (existing.label !== label || existing.color !== color) {
              mismatchNote =
                `Option '${value}' already exists with label='${existing.label}' color='${existing.color}'; ` +
                `requested label='${label}' color='${color}' — left unchanged (no mutation).`;
            }
          } else {
            const maxPos = field.options.reduce(
              (m, o) => Math.max(m, o.position),
              -1,
            );
            const position = args.position ?? maxPos + 1;
            // A client-generated id: Twenty's metadata SELECT options carry ids;
            // supplying one keeps the append explicit. Existing ids pass through
            // untouched. (Live PATCH-body shape must be reconfirmed before a real
            // confirm run — see the item's build-time-verify note.)
            const newOpt: SelectOption = {
              id: crypto.randomUUID(),
              value,
              label,
              color,
              position,
            };
            resultOptions = [...field.options, newOpt];
            if (args.dryRun) {
              action = "planned-create";
            } else {
              // SO-3: re-read immediately before the write and abort if the option
              // set drifted (best-effort optimistic concurrency — no server ETag).
              const fresh = await fetchSelectField(
                cfg,
                args.objectNameSingular,
                args.fieldName,
              );
              if (!optionsEquivalent(fresh.options, field.options)) {
                throw new Error(
                  `Options for '${target}' changed between read and write (concurrent edit); aborting to avoid a lossy overwrite. Re-run.`,
                );
              }
              // SO-2: options-only PATCH — Twenty's metadata field PATCH is a
              // partial update, so sibling attributes (name/label/type/isNullable)
              // are preserved. We deliberately send ONLY options.
              await twentyRequest(
                cfg,
                "PATCH",
                `/rest/metadata/fields/${field.fieldId}`,
                { options: resultOptions },
              );
              action = "created";
            }
          }

          context.logger.info(
            "ensureStageOption {target} value={value}: {action}",
            { target, value, action },
          );
          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            object: args.objectNameSingular,
            field: args.fieldName,
            value,
            label,
            color,
            action,
            options: resultOptions.map((o) => ({
              value: o.value,
              label: o.label,
              color: o.color,
              position: o.position,
            })),
            retrievedAt: new Date().toISOString(),
          };
          if (mismatchNote) snap.mismatchNote = mismatchNote;
          const handle = await context.writeResource(
            "stageOption",
            `stageopt-${args.objectNameSingular}-${args.fieldName}-${value}`,
            snap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e));
        }
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
    findPerson: {
      description:
        "Look up a Person by primary email OR leadId (exactly one). Read-only existence check for reconcile/dedup: records a `personRef` on both hit (found:true + id) and miss (found:false), so callers can tell 'looked, not there' from 'never looked'. Throws on an ambiguous (>1) email match. No writes.",
      arguments: z
        .object({
          email: z.string().optional().describe(
            "Primary email — exactly one of email|leadId",
          ),
          leadId: z.string().optional().describe(
            "Opaque upstream lead id — exactly one of email|leadId",
          ),
        })
        .refine((a) => (a.email == null) !== (a.leadId == null), {
          message: "Provide exactly one of email or leadId",
        }),
      execute: async (
        args: { email?: string; leadId?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          let person: Record<string, unknown> | null = null;
          let byLeadId: string | undefined;
          if (args.email != null) {
            const email = validateEmail(args.email);
            if (!email) throw new Error("Invalid email");
            person = await findOnePersonByEmail(cfg, email);
          } else {
            const leadId = validateLeadId(args.leadId);
            if (!leadId) throw new Error("Invalid leadId");
            byLeadId = leadId;
            person = await findPersonByLeadId(cfg, leadId);
          }
          const found = person != null;
          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            found,
            retrievedAt: new Date().toISOString(),
          };
          let name: string;
          if (found && person) {
            const id = String(person.id ?? "");
            snap.id = id;
            if (person.leadId != null && person.leadId !== "") {
              snap.leadId = String(person.leadId);
            } else if (byLeadId) snap.leadId = byLeadId;
            if (person.companyId) snap.companyId = String(person.companyId);
            name = `person-${id}`;
          } else {
            if (byLeadId) snap.leadId = byLeadId;
            name = byLeadId ? `person-miss-${byLeadId}` : "person-miss";
          }
          const handle = await context.writeResource("personRef", name, snap);
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e));
        }
      },
    },
    getPersonById: {
      description:
        "Fetch a Person by UUID (GET /rest/people/{id}); records a `personRef` with found:false on a 404. Read-only — lets the reconcile report walk from an opportunity's pointOfContactId back to a contact.",
      arguments: z.object({
        id: z.string().describe("Person UUID"),
      }),
      execute: async (
        args: { id: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const id = validateUuid(args.id);
          if (!id) throw new Error("Invalid person id");
          const person = await getPersonById(cfg, id);
          const found = person != null;
          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            found,
            retrievedAt: new Date().toISOString(),
          };
          if (found && person) {
            snap.id = String(person.id ?? id);
            if (person.leadId != null && person.leadId !== "") {
              snap.leadId = String(person.leadId);
            }
            if (person.companyId) snap.companyId = String(person.companyId);
          }
          const handle = await context.writeResource(
            "personRef",
            found ? `person-${id}` : `person-miss-${id}`,
            snap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e));
        }
      },
    },
    findCompany: {
      description:
        "Look up a Company by domain OR exact name (exactly one). Records a `companyRef` on hit and miss. Throws on an ambiguous (>1) match; the name path returns found:false gracefully if the name field is not filterable on the instance. No writes.",
      arguments: z
        .object({
          domain: z.string().optional().describe(
            "Company domain — exactly one of domain|name",
          ),
          name: z.string().optional().describe(
            "Exact company name (must be filter-safe) — exactly one of domain|name",
          ),
        })
        .refine((a) => (a.domain == null) !== (a.name == null), {
          message: "Provide exactly one of domain or name",
        }),
      execute: async (
        args: { domain?: string; name?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          let company: Record<string, unknown> | null = null;
          let queriedDomain: string | undefined;
          let queriedName: string | undefined;
          if (args.domain != null) {
            const domain = validateDomain(args.domain);
            if (!domain) throw new Error("Invalid domain");
            queriedDomain = domain;
            company = await findOneCompanyByDomain(cfg, domain);
          } else {
            const name = String(args.name ?? "").trim();
            if (!isFilterSafe(name)) {
              throw new Error("Company name contains filter-unsafe characters");
            }
            queriedName = name;
            company = await findOneCompanyByName(cfg, name);
          }
          const found = company != null;
          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            found,
            retrievedAt: new Date().toISOString(),
          };
          let name: string;
          if (found && company) {
            const id = String(company.id ?? "");
            snap.id = id;
            if (company.name) snap.name = String(company.name);
            const dn = (company.domainName as { primaryLinkUrl?: unknown })
              ?.primaryLinkUrl;
            if (dn) snap.domain = String(dn);
            else if (queriedDomain) snap.domain = queriedDomain;
            name = `company-${id}`;
          } else {
            if (queriedDomain) snap.domain = queriedDomain;
            name = queriedDomain
              ? `company-miss-${queriedDomain}`
              : "company-miss";
          }
          void queriedName;
          const handle = await context.writeResource("companyRef", name, snap);
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e));
        }
      },
    },
    getCompanyById: {
      description:
        "Fetch a Company by UUID (GET /rest/companies/{id}); records a `companyRef` with found:false on a 404. Read-only — lets the reconcile report resolve an opportunity's companyId.",
      arguments: z.object({
        id: z.string().describe("Company UUID"),
      }),
      execute: async (
        args: { id: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const id = validateUuid(args.id);
          if (!id) throw new Error("Invalid company id");
          const company = await getCompanyById(cfg, id);
          const found = company != null;
          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            found,
            retrievedAt: new Date().toISOString(),
          };
          if (found && company) {
            snap.id = String(company.id ?? id);
            if (company.name) snap.name = String(company.name);
            const dn = (company.domainName as { primaryLinkUrl?: unknown })
              ?.primaryLinkUrl;
            if (dn) snap.domain = String(dn);
          }
          const handle = await context.writeResource(
            "companyRef",
            found ? `company-${id}` : `company-miss-${id}`,
            snap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e));
        }
      },
    },
    getOpportunity: {
      description:
        "Fetch one Opportunity by leadId OR id (exactly one). Records an `opportunityRef` snapshot carrying the reconcile-critical fields (id, leadId, name, stage, amount in whole units, currencyCode, closeDate, companyId, pointOfContactId); found:false + no fields on a miss. No writes.",
      arguments: z
        .object({
          leadId: z.string().optional().describe(
            "Opaque upstream lead id — exactly one of leadId|id",
          ),
          id: z.string().optional().describe(
            "Opportunity UUID — exactly one of leadId|id",
          ),
        })
        .refine((a) => (a.leadId == null) !== (a.id == null), {
          message: "Provide exactly one of leadId or id",
        }),
      execute: async (
        args: { leadId?: string; id?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          let opp: Record<string, unknown> | null = null;
          let byLeadId: string | undefined;
          if (args.leadId != null) {
            const leadId = validateLeadId(args.leadId);
            if (!leadId) throw new Error("Invalid leadId");
            byLeadId = leadId;
            opp = await findOpportunityByLeadId(cfg, leadId);
          } else {
            const id = validateUuid(args.id);
            if (!id) throw new Error("Invalid opportunity id");
            opp = await getOpportunityById(cfg, id);
          }
          const found = opp != null;
          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            found,
            retrievedAt: new Date().toISOString(),
          };
          let name: string;
          if (found && opp) {
            const view = mapOppView(opp);
            const id = view.id;
            snap.id = id;
            if (view.leadId) snap.leadId = view.leadId;
            else if (byLeadId) snap.leadId = byLeadId;
            if (view.name) snap.name = view.name;
            if (view.stage) snap.stage = view.stage;
            if (view.amount !== undefined) snap.amount = view.amount;
            if (view.currencyCode) snap.currencyCode = view.currencyCode;
            if (view.closeDate) snap.closeDate = view.closeDate;
            if (view.companyId) snap.companyId = view.companyId;
            if (opp.pointOfContactId) {
              snap.pointOfContactId = String(opp.pointOfContactId);
            }
            name = `opportunity-${id}`;
          } else {
            if (byLeadId) snap.leadId = byLeadId;
            name = byLeadId
              ? `opportunity-miss-${byLeadId}`
              : "opportunity-miss";
          }
          const handle = await context.writeResource(
            "opportunityRef",
            name,
            snap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e));
        }
      },
    },
    listOpportunities: {
      description:
        "Fan-out read (repo rule 6): list Opportunities filtered by companyId and/or stage (both optional; neither => all, capped). Composes filters with AND, pages through Twenty's cursor pagination up to `limit` (hard-capped at 500), dedups by id, and records an `opportunityList` snapshot of compact views + a `truncated` flag. No writes, no per-id loop.",
      arguments: z.object({
        companyId: z.string().optional().describe("Filter: company UUID"),
        stage: z.string().optional().describe(
          "Filter: opportunity stage (e.g. PROPOSAL)",
        ),
        limit: z
          .number()
          .int()
          .positive()
          .max(MAX_LIST_CAP)
          .default(60)
          .describe(`Max results to return (1..${MAX_LIST_CAP})`),
      }),
      execute: async (
        args: { companyId?: string; stage?: string; limit: number },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          let companyId: string | undefined;
          if (args.companyId != null) {
            const cid = validateUuid(args.companyId);
            if (!cid) throw new Error("Invalid companyId");
            companyId = cid;
          }
          let stage: string | undefined;
          if (args.stage != null) {
            const s = String(args.stage).trim();
            if (!isFilterSafe(s)) {
              throw new Error("stage contains filter-unsafe characters");
            }
            stage = s;
          }
          const { items, truncated } = await listOpportunitiesFiltered(cfg, {
            companyId,
            stage,
            limit: args.limit,
          });
          const views = items.map(mapOppView);
          const filter: Record<string, string> = {};
          if (companyId) filter.companyId = companyId;
          if (stage) filter.stage = stage;
          const handle = await context.writeResource(
            "opportunityList",
            `opps-${companyId ?? "all"}-${stage ?? "all"}`,
            {
              baseUrl: cfg.baseUrl,
              count: views.length,
              truncated,
              filter,
              items: views,
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e));
        }
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
    upsertOpportunity: {
      description:
        "Generalized, idempotent Opportunity upsert keyed on leadId — the create/update path with the full field set (name, amount, stage, closeDate, company, point of contact) that push_leads' bare createOpportunity omits. Finds any existing Opportunity by leadId: hit => PATCH the provided fields; miss => create. Optionally finds-or-creates and links a Company (by domain, else by exact name) and a point-of-contact Person (by email), and attaches a markdown Note. amount is given in whole currency units (50000 => $50,000) and stored as Twenty currency micros. confirm:true required for a real run; dryRun:true resolves + plans and writes nothing. Snapshots an `opportunityUpsert` resource.",
      arguments: z.object({
        leadId: z
          .string()
          .describe(
            "Stable idempotency key for this opportunity (upsert marker, e.g. 'jfw-aap-2.7-2026')",
          ),
        name: z.string().describe("Opportunity name"),
        amount: z
          .number()
          .nonnegative()
          .optional()
          .describe(
            "Deal value in whole currency units (e.g. 50000 = $50,000)",
          ),
        currencyCode: z
          .string()
          .optional()
          .describe(
            "ISO 4217 currency code for amount (defaults to USD on create; on an amount-only update the existing currency is preserved)",
          ),
        stage: z
          .string()
          .optional()
          .describe(
            "Opportunity stage (NEW, SCREENING, MEETING, PROPOSAL, CUSTOMER). Defaults to the model's opportunityStage.",
          ),
        closeDate: z
          .string()
          .default("")
          .describe("Expected/actual close date (YYYY-MM-DD or ISO datetime)"),
        companyName: z
          .string()
          .default("")
          .describe("Company to find-or-create and link"),
        companyDomain: z
          .string()
          .default("")
          .describe("Company domain, used to dedup/link the company"),
        pointOfContactName: z
          .string()
          .default("")
          .describe(
            "Point-of-contact full name (used only if the email is new)",
          ),
        pointOfContactEmail: z
          .string()
          .default("")
          .describe(
            "Point-of-contact email — the find-or-create key for the Person",
          ),
        isEmergency: z
          .boolean()
          .optional()
          .describe("Set the isEmergency marker on the opportunity"),
        noteBody: z
          .string()
          .default("")
          .describe("Optional markdown note attached to the opportunity"),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true for a real run (writes to Twenty)"),
        dryRun: z
          .boolean()
          .default(false)
          .describe("Resolve + plan, but write nothing"),
      }),
      execute: async (
        args: {
          leadId: string;
          name: string;
          amount?: number;
          currencyCode?: string;
          stage?: string;
          closeDate: string;
          companyName: string;
          companyDomain: string;
          pointOfContactName: string;
          pointOfContactEmail: string;
          isEmergency?: boolean;
          noteBody: string;
          confirm: boolean;
          dryRun: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        if (!args.dryRun && !args.confirm) {
          throw new Error(
            "Refusing to write without confirm:true (use dryRun:true to plan)",
          );
        }
        const leadId = validateLeadId(args.leadId);
        if (!leadId) {
          throw new Error(
            "Invalid leadId (allowed: A-Za-z0-9._:- up to 128 chars)",
          );
        }
        const name = sanitizeText(args.name, 200);
        if (!name) throw new Error("name is required");
        // Live Opportunity metadata: used to validate stage against the SELECT
        // enum and to learn the closeDate field type. Best-effort — if metadata
        // is unreadable, skip validation rather than block a write.
        let oppMeta: { stages: string[]; closeDateType: string | null } = {
          stages: [],
          closeDateType: null,
        };
        try {
          oppMeta = await fetchOpportunityMeta(cfg);
        } catch (_e) {
          context.logger.warning(
            "Opportunity metadata unreadable; skipping stage validation",
            {},
          );
        }

        // All lookups + writes are wrapped so a Twenty 4xx that echoes a
        // submitted value (email, company name) is redacted before it reaches
        // logs — matching the no-raw-PII guarantee elsewhere in this file.
        try {
          // Idempotency lookup FIRST — decides create vs update and lets an update
          // preserve fields (stage, currency) the caller did not set.
          const existingOpp = await findOpportunityByLeadId(cfg, leadId);

          // stage: apply the default only on CREATE; on update omit it unless the
          // caller set one, so a re-run never resets a manually advanced stage.
          const stageToWrite = args.stage ??
            (existingOpp ? undefined : cfg.opportunityStage);
          if (
            stageToWrite !== undefined && oppMeta.stages.length &&
            !oppMeta.stages.includes(stageToWrite)
          ) {
            throw new Error(
              `Invalid stage '${stageToWrite}'. Valid stages: ${
                oppMeta.stages.join(", ")
              }`,
            );
          }

          // amount: default USD only on create; on an amount-only update preserve
          // the record's existing currency rather than silently forcing USD.
          let amount:
            | { amountMicros: number; currencyCode: string }
            | undefined;
          if (args.amount !== undefined) {
            const existingCcy =
              ((existingOpp?.amount as Record<string, unknown> | undefined)
                ?.currencyCode) as string | undefined;
            const ccy = args.currencyCode ?? existingCcy ?? "USD";
            amount = toCurrency(args.amount, ccy);
          }

          // closeDate: bare date for a DATE field, anchored datetime for DATE_TIME
          // (avoids an off-by-one day west of UTC on DATE fields).
          let closeDate: string | undefined;
          if (args.closeDate) {
            const nd = normalizeCloseDate(args.closeDate);
            if (!nd) {
              throw new Error(`Unparseable closeDate: ${args.closeDate}`);
            }
            closeDate = oppMeta.closeDateType === "DATE" ? nd.slice(0, 10) : nd;
          }

          // Company (optional): dedup by domain, else by exact (filter-safe) name.
          // Create ONLY when a domain is supplied; a name-only miss is left
          // unlinked (recorded) rather than blind-created, to avoid duplicates.
          let companyId: string | undefined;
          let companyNote: string | undefined;
          const companyName = sanitizeText(args.companyName, 120);
          const companyDomain = validateDomain(args.companyDomain) ?? undefined;
          if (companyDomain || companyName) {
            let existingCo: Record<string, unknown> | null = null;
            if (companyDomain) {
              existingCo = await findOneCompanyByDomain(cfg, companyDomain);
            }
            if (!existingCo && companyName && isFilterSafe(companyName)) {
              existingCo = await findOneCompanyByName(cfg, companyName);
            }
            if (existingCo) {
              companyId = String(existingCo.id ?? "");
            } else if (companyDomain && !args.dryRun) {
              const co = await createCompany(cfg, {
                name: companyName || companyDomain,
                domain: companyDomain,
              });
              companyId = String(co.id ?? "");
            } else if (!companyDomain) {
              companyNote = companyName && !isFilterSafe(companyName)
                ? "company not linked: name has filter-unsafe characters and no domain to dedup by"
                : "company not linked: name-only with no domain match (not blind-created to avoid duplicates)";
            }
          }

          // Point of contact (optional): LINK-ONLY. Dedup by email; never create a
          // Person or stamp this lead's leadId onto one (that would poison the
          // leadId->person namespace push_leads relies on).
          let pointOfContactId: string | undefined;
          let pocSkipped: string | undefined;
          const pocEmail = validateEmail(args.pointOfContactEmail);
          if (pocEmail) {
            const existingPerson = await findOnePersonByEmail(cfg, pocEmail);
            if (existingPerson) {
              pointOfContactId = String(existingPerson.id ?? "");
            } else {
              pocSkipped =
                "no existing person for the given email (link-only; not created)";
            }
          } else if (args.pointOfContactName) {
            pocSkipped =
              "point-of-contact name supplied without a resolvable email; skipped";
          }

          // Opportunity: upsert on leadId, with a create->conflict->update fallback
          // for the check-then-act race (leadId is not a unique column in Twenty).
          const fields: OpportunityWriteFields = {
            name,
            ...(stageToWrite !== undefined ? { stage: stageToWrite } : {}),
            ...(amount ? { amount } : {}),
            ...(closeDate ? { closeDate } : {}),
            ...(pointOfContactId ? { pointOfContactId } : {}),
            ...(companyId ? { companyId } : {}),
            ...(args.isEmergency !== undefined
              ? { isEmergency: args.isEmergency }
              : {}),
          };
          let opportunityId = existingOpp ? String(existingOpp.id ?? "") : "";
          let action:
            | "created"
            | "updated"
            | "planned-create"
            | "planned-update";
          if (args.dryRun) {
            action = existingOpp ? "planned-update" : "planned-create";
          } else if (existingOpp) {
            await updateOpportunity(cfg, opportunityId, fields);
            action = "updated";
          } else {
            try {
              const created = await createOpportunityFull(cfg, leadId, fields);
              opportunityId = String(created.id ?? "");
              action = "created";
            } catch (e) {
              // A concurrent run may have created it between our lookup and POST.
              const raced = await findOpportunityByLeadId(cfg, leadId);
              if (raced) {
                opportunityId = String(raced.id ?? "");
                await updateOpportunity(cfg, opportunityId, fields);
                action = "updated";
              } else {
                throw e;
              }
            }
          }

          // Note (optional): strip tags/control chars THEN markdown-escape.
          let noteEnsured = false;
          const noteBody = sanitizeText(args.noteBody, 5000);
          if (noteBody && !args.dryRun && opportunityId) {
            const note = await ensureNoteForLead(cfg, {
              leadId,
              body: escapeMarkdown(noteBody),
              opportunityId,
              personId: pointOfContactId,
            });
            noteEnsured = Boolean(note.noteId);
          }

          // Report the stage in effect (written, or the preserved existing one).
          const reportedStage = stageToWrite ??
            String((existingOpp?.stage as string | undefined) ?? "");

          context.logger.info(
            "upsertOpportunity {leadId}: {action} (opp {opp}){dry}",
            {
              leadId,
              action,
              opp: opportunityId || "-",
              dry: args.dryRun ? " [dryRun]" : "",
            },
          );

          const handle = await context.writeResource(
            "opportunityUpsert",
            `opportunity-${leadId}`,
            {
              baseUrl: cfg.baseUrl,
              action,
              dryRun: args.dryRun,
              leadId,
              ...(opportunityId ? { opportunityId } : {}),
              name,
              stage: reportedStage,
              ...(args.amount !== undefined ? { amount: args.amount } : {}),
              ...(amount ? { currencyCode: amount.currencyCode } : {}),
              ...(closeDate ? { closeDate } : {}),
              ...(companyId ? { companyId } : {}),
              companyLinked: Boolean(companyId),
              ...(companyNote ? { companyNote } : {}),
              ...(pointOfContactId ? { pointOfContactId } : {}),
              ...(pocSkipped ? { pocSkipped } : {}),
              noteEnsured,
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e));
        }
      },
    },
  },
  checks: {
    "reachable": {
      description:
        "Verify the Twenty instance responds and the API token authenticates (authed GET /rest/people?limit=1) before a write.",
      labels: ["live"],
      appliesTo: [
        "ensureLeadFields",
        "push_leads",
        "upsertOpportunity",
        "ensureStageOption",
      ],
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
