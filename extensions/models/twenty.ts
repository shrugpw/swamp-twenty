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
  leadSourceChannel: z
    .string()
    .default("")
    .describe(
      "Source Channel SELECT option (UPPER_SNAKE, e.g. DIRECT) stamped on Opportunities that push_leads CREATES, for analytics segmentation. Empty (default) = do not set the field — leave empty until the opportunity.sourceChannel SELECT is provisioned (ensureOpportunitySegmentation / ensureField), since writing an unprovisioned field fails the create. Contact-form leads are inbound-direct, so DIRECT is the natural value once the field exists.",
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

/**
 * Reduce an arbitrary domain-ish value to a bare host (AR-6): lowercase, strip a
 * `scheme://`, any userinfo, port, path/query/fragment, and trailing dots. Used
 * BOTH when building the companies domain filter and when flattening
 * `domainName.primaryLinkUrl` into a CompanyView, so the filter matches and the
 * snapshot is diff-stable regardless of how the URL is stored. Returns the bare
 * host (unvalidated shape — callers that need a strict domain still run
 * {@link validateDomain}), or null when nothing usable remains.
 */
export function normalizeDomainHost(raw: unknown): string | null {
  if (raw == null) return null;
  let s = String(raw).trim().toLowerCase();
  if (!s) return null;
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, ""); // strip scheme://
  s = s.replace(/^[^/@]*@/, ""); // strip userinfo
  s = s.replace(/[/?#].*$/, ""); // strip path/query/fragment
  s = s.replace(/:\d+$/, ""); // strip port
  s = s.replace(/\.+$/, ""); // strip trailing dot(s)
  return s || null;
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
 * becomes `+1XXXXXXXXXX` and `1XXXXXXXXXX` becomes `+1XXXXXXXXXX` (Springfield, IL
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
// The transport echoes the failing request path in its Error message (e.g.
// `Twenty GET /rest/people?filter=leadId[eq]:...&starting_after=... failed`),
// which embeds the raw leadId/name/domain filter values and the opaque cursor.
// Scrub those query values wholesale so an attacker-influenced filter value (or
// a cursor that positionally encodes a record) can never leak into durable data
// — the [eq] value alone may not match the email/digit shapes above (SR-2).
const FILTER_QUERY_RE = /([?&]filter=)[^&\s]*/gi;
const CURSOR_QUERY_RE = /([?&]starting_after=)[^&\s]*/gi;
// SR-2/CR-S-1: scrub the bearer token. The transport keeps it in the
// Authorization header (never echoed), but a future error path could surface it
// — so `Bearer <token>` is masked generically, and any exact `token` the caller
// passes is masked literally, so the secret can never leak into durable data.
const BEARER_RE = /Bearer\s+[A-Za-z0-9._~+/=-]+/gi;

/**
 * Redact secrets + PII from a captured error message and cap its length: the
 * bearer token (SR-2/CR-S-1), the sensitive `filter=` / `starting_after=` query
 * values (which embed raw leadId/name/domain + the opaque cursor), and
 * email/long-digit PII shapes. Keeps the per-lead audit and the list snapshots'
 * "no secret / no raw PII / no attacker-influenced input" guarantee even when
 * Twenty echoes the offending value (or the transport echoes the request URL)
 * back in a 4xx. Pass `token` (e.g. cfg.apiToken) to also mask exact literal
 * occurrences of the secret.
 */
export function redactError(
  raw: unknown,
  maxLen = 300,
  token?: string,
): string {
  let s = raw instanceof Error ? raw.message : String(raw ?? "");
  if (token && token.length >= 4) s = s.split(token).join("[redacted]");
  s = s
    .replace(BEARER_RE, "Bearer [redacted]")
    .replace(FILTER_QUERY_RE, "$1[redacted]")
    .replace(CURSOR_QUERY_RE, "$1[redacted]")
    .replace(EMAIL_IN_TEXT_RE, "[email]")
    .replace(LONG_DIGITS_RE, "[number]");
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
  details: z
    .array(z.object({ label: z.string(), value: z.string() }))
    .optional()
    .describe(
      "Structured label/value extras (Needs/Reason/Timing/Via) rendered as their own labeled lines in the Note. Kept OUT of the free-text message so they are not markdown-escaped into a run-on. Optional on input; the KV adapter populates it.",
    ),
}).passthrough();
type LeadRecord = z.infer<typeof LeadRecordSchema>;

/**
 * One entry of a `kv_export` snapshot from the @shrug/fastly-compute leads
 * store: `value` is the JSON lead record the Fastly contact worker wrote (utf8).
 * key/found/valueEncoding are carried through but unused by the adapter.
 */
const KvEntrySchema = z.object({
  key: z.string().optional(),
  found: z.boolean().optional(),
  value: z.string().default(""),
  valueEncoding: z.string().optional(),
}).passthrough();
type KvEntry = z.infer<typeof KvEntrySchema>;

/** A `contact_type` value coerced to the LeadRecord enum, or null if unknown. */
function coerceContactType(
  v: unknown,
): "individual" | "business" | "emergency" | null {
  const s = typeof v === "string" ? v.toLowerCase().trim() : "";
  return s === "individual" || s === "business" || s === "emergency" ? s : null;
}

/**
 * Adapt ONE raw KV lead record (as written by the Fastly contact worker) into
 * the flat LeadRecord `push_leads` validates. Pure + unit-testable. Bridges the
 * two on-the-wire shapes — shrugpw's and shrug.host's richer one — losing
 * nothing:
 *   - `org` becomes the company name when `company` is absent;
 *   - the `geo` OBJECT is flattened to a "city, region, country" string;
 *   - null/absent email & phone become "" (planLead re-validates the email);
 *   - `contact_type` is honored when a valid enum, else inferred — shrug.host
 *     leads (`source == "shrug.host-contact"`) default to `business` so the
 *     company-linking path runs;
 *   - shrug.host's structured extras (`needs`/`reason`/`timing`/`source`) are
 *     folded onto the message so they reach the per-lead Note (no first-class
 *     Twenty field for them yet).
 */
export function leadFromKvRecord(raw: Record<string, unknown>): LeadRecord {
  const str = (v: unknown): string => (typeof v === "string" ? v : "");
  const source = str(raw.source).trim();

  const geoObj = raw.geo && typeof raw.geo === "object"
    ? raw.geo as Record<string, unknown>
    : {};
  const geo = [str(geoObj.city), str(geoObj.region), str(geoObj.country)]
    .map((x) => x.trim())
    .filter(Boolean)
    .join(", ");

  const contact_type = coerceContactType(raw.contact_type) ??
    (source === "shrug.host-contact" ? "business" : "individual");

  const needs = Array.isArray(raw.needs)
    ? (raw.needs as unknown[]).map(str).map((x) => x.trim()).filter(Boolean)
    : [];
  // Structured extras stay as label/value pairs (NOT folded into message) so the
  // note builder can render them as bold-labeled lines instead of an escaped
  // run-on. Values are user text — sanitized in planLead, escaped at render.
  const details: { label: string; value: string }[] = [];
  if (needs.length) details.push({ label: "Needs", value: needs.join(", ") });
  if (str(raw.reason).trim()) {
    details.push({ label: "Reason", value: str(raw.reason).trim() });
  }
  if (str(raw.timing).trim()) {
    details.push({ label: "Timing", value: str(raw.timing).trim() });
  }
  if (source) details.push({ label: "Via", value: source });
  const message = str(raw.message).trim();

  return {
    id: str(raw.id),
    name: str(raw.name),
    email: str(raw.email),
    phone: str(raw.phone),
    message,
    contact_type,
    company: str(raw.company) || str(raw.org),
    received_at: str(raw.received_at),
    status: str(raw.status) || "new",
    geo,
    details,
  };
}

/**
 * Parse one `kv_export` entry into an adapted LeadRecord. Returns null when the
 * entry has no string value or the value is not JSON — the caller counts these
 * as unparseable (surfaced in the audit; never silently dropped).
 */
export function leadFromKvEntry(entry: KvEntry): LeadRecord | null {
  if (typeof entry.value !== "string" || entry.value.trim() === "") return null;
  let raw: unknown;
  try {
    raw = JSON.parse(entry.value);
  } catch {
    return null;
  }
  if (!raw || typeof raw !== "object") return null;
  return leadFromKvRecord(raw as Record<string, unknown>);
}

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
  /** Bold-labeled Note lines (Needs/Reason/Timing/Via); values sanitized. */
  details: { label: string; value: string }[];
  contactType: "individual" | "business" | "emergency";
  emergency: boolean;
  /** Company name to use IF a company is created (business + real domain only). */
  companyName: string;
  /** Corporate domain for the company, or null when none/blocked/consumer. */
  companyDomain: string | null;
}

export type PlannedLead = PlannedLeadValid | PlannedLeadInvalid;

/**
 * Build the markdown Note body for a lead: the escaped free-text message, then
 * each structured field (Needs/Reason/Timing/Via, plus Geo) as its own
 * bold-labeled line. Labels are trusted/static so they carry the markdown; only
 * user-supplied values are markdown-escaped (values arrive already sanitized).
 * Pure so the exact rendering is unit-testable. Returns "" when there's nothing
 * to say — the caller substitutes an `Inbound lead <id>` placeholder.
 */
export function buildLeadNoteBody(
  p: {
    message: string;
    geo: string;
    details: { label: string; value: string }[];
  },
): string {
  const lines = [...p.details];
  if (p.geo) lines.push({ label: "Geo", value: p.geo });
  const block = lines
    .map((d) => `**${d.label}:** ${escapeMarkdown(d.value)}`)
    .join("\n\n");
  return [escapeMarkdown(p.message), block]
    .filter((s) => s.trim() !== "")
    .join("\n\n")
    .trim();
}

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
    details: (lead.details ?? [])
      .map((d) => ({ label: d.label, value: sanitizeText(d.value, 500) }))
      .filter((d) => d.value !== ""),
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

// --- Curated contact writer helpers (TWENTY-PERSON-UPSERT) ------------------

/** Fields writable on a Person by upsertPerson (partial-update safe). */
interface PersonWriteFields {
  name?: { firstName: string; lastName: string };
  phone?: string;
  jobTitle?: string;
  city?: string;
  companyId?: string;
}

/** Assemble a REST body from only the fields that are set (partial-update safe). */
function buildPersonBody(f: PersonWriteFields): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  if (f.name !== undefined) body.name = f.name;
  if (f.phone) body.phones = { primaryPhoneNumber: f.phone };
  if (f.jobTitle !== undefined) body.jobTitle = f.jobTitle;
  if (f.city !== undefined) body.city = f.city;
  if (f.companyId) body.companyId = f.companyId;
  return body;
}

/** The Person field names actually being written (for the upsert snapshot). */
function personFieldsSet(f: PersonWriteFields): string[] {
  const s: string[] = [];
  if (f.name !== undefined) s.push("name");
  if (f.phone) s.push("phone");
  if (f.jobTitle !== undefined) s.push("jobTitle");
  if (f.city !== undefined) s.push("city");
  if (f.companyId) s.push("company");
  return s;
}

/**
 * Create a curated Person keyed on primaryEmail, WITHOUT stamping a leadId —
 * unlike {@link createPerson}, which requires one. Curated contacts must not
 * enter the leadId->person namespace push_leads relies on. Retries once without
 * the phone on a phone-shaped error so a bad number never blocks the contact.
 */
/** Result of a curated write: the record, and whether the phone was dropped on
 * a retry (so the caller's snapshot can report what was actually written). */
interface PersonWriteResult {
  record: Record<string, unknown>;
  phoneDropped: boolean;
}

async function createPersonCurated(
  cfg: TwentyCfg,
  email: string,
  f: PersonWriteFields,
): Promise<PersonWriteResult> {
  const body: Record<string, unknown> = {
    ...buildPersonBody(f),
    emails: { primaryEmail: email },
  };
  try {
    const json = await twentyRequest(cfg, "POST", "/rest/people", body);
    return { record: unwrapRecord(json, "createPerson"), phoneDropped: false };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (body.phones && /phone/i.test(msg)) {
      delete body.phones;
      const json = await twentyRequest(cfg, "POST", "/rest/people", body);
      return { record: unwrapRecord(json, "createPerson"), phoneDropped: true };
    }
    throw e;
  }
}

/** Patch an existing Person by id with only the provided fields (phone-retry). */
async function updatePerson(
  cfg: TwentyCfg,
  id: string,
  f: PersonWriteFields,
): Promise<PersonWriteResult> {
  const body = buildPersonBody(f);
  try {
    const json = await twentyRequest(cfg, "PATCH", `/rest/people/${id}`, body);
    return { record: unwrapRecord(json, "updatePerson"), phoneDropped: false };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (body.phones && /phone/i.test(msg)) {
      delete body.phones;
      const json = await twentyRequest(
        cfg,
        "PATCH",
        `/rest/people/${id}`,
        body,
      );
      return { record: unwrapRecord(json, "updatePerson"), phoneDropped: true };
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
  sourceChannel?: string;
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
  // Analytics segmentation (TWENTY-OPP-SEGMENTATION): stamp Source Channel on
  // CREATE only, and only when the instance is configured with a value (the
  // opportunity.sourceChannel SELECT must already be provisioned). An unset
  // config leaves the create body byte-identical to before this change.
  if (o.sourceChannel) body.sourceChannel = o.sourceChannel;
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
  lineOfBusiness?: string;
  sourceChannel?: string;
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
  if (f.lineOfBusiness !== undefined) body.lineOfBusiness = f.lineOfBusiness;
  if (f.sourceChannel !== undefined) body.sourceChannel = f.sourceChannel;
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
  // Custom/segmentation SELECT fields (flat option-value scalars in Twenty REST)
  // + the emergency marker — surfaced so a reconcile can read back what a write
  // set without dropping to the Twenty UI.
  lineOfBusiness?: string;
  sourceChannel?: string;
  isEmergency?: boolean;
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
  // Segmentation SELECTs are flat option-value strings; empty/unset => omit.
  if (rec.lineOfBusiness != null && rec.lineOfBusiness !== "") {
    v.lineOfBusiness = String(rec.lineOfBusiness);
  }
  if (rec.sourceChannel != null && rec.sourceChannel !== "") {
    v.sourceChannel = String(rec.sourceChannel);
  }
  // Surface isEmergency even when false (mirrors mapPersonView) so consumers can
  // reason about the flag without a second read.
  if (rec.isEmergency != null) v.isEmergency = Boolean(rec.isEmergency);
  return v;
}

// --- Bulk-list compact views (TWENTY-SNAPSHOT-READS) ------------------------
// Deliberately mirror the *Ref posture: only join keys + non-sensitive scalars,
// never bulk PII. No person name/email/phone/jobTitle, no company beyond
// name/domain, and NEVER a Note body.

/** Compact People-list view — mirrors personRef (no name/email/phone/jobTitle). */
export interface PersonView {
  id: string;
  leadId?: string;
  companyId?: string;
  isEmergency?: boolean;
  createdAt?: string;
}

/** Map a raw Person REST record to the compact {@link PersonView}. */
export function mapPersonView(rec: Record<string, unknown>): PersonView {
  const v: PersonView = { id: String(rec.id ?? "") };
  if (rec.leadId != null && rec.leadId !== "") v.leadId = String(rec.leadId);
  // AR-9: companyId is Twenty's flat relation FK scalar on the person record.
  if (rec.companyId != null && rec.companyId !== "") {
    v.companyId = String(rec.companyId);
  }
  // AR-5: surface isEmergency (even when false) so consumers can drop restricted
  // rows even on an includeEmergency:true read.
  if (rec.isEmergency != null) v.isEmergency = Boolean(rec.isEmergency);
  if (rec.createdAt) v.createdAt = String(rec.createdAt);
  return v;
}

/** Compact Company-list view — mirrors companyRef (id/name/domain). */
export interface CompanyView {
  id: string;
  name: string;
  domain?: string;
  createdAt?: string;
}

/** Map a raw Company REST record to the compact {@link CompanyView}. */
export function mapCompanyView(rec: Record<string, unknown>): CompanyView {
  const v: CompanyView = {
    id: String(rec.id ?? ""),
    name: String(rec.name ?? ""),
  };
  // AR-6: normalize domainName.primaryLinkUrl to a bare host on flatten so the
  // snapshot is diff-stable and matches companyRef's key regardless of storage.
  const dn = (rec.domainName as { primaryLinkUrl?: unknown } | null | undefined)
    ?.primaryLinkUrl;
  const host = normalizeDomainHost(dn);
  if (host) v.domain = host;
  if (rec.createdAt) v.createdAt = String(rec.createdAt);
  return v;
}

// SR-1 / CR-A-5: the only Note title safe to snapshot is the machine-generated
// `Inbound lead <leadId>` from ensureNoteForLead. The guard is ANCHORED end-to-
// end — exactly the prefix + a single non-space leadId token — and the token is
// re-validated with validateLeadId, so a title with a free-text tail (e.g.
// `Inbound lead L1 and my notes...`) or a non-leadId suffix is dropped.
const INBOUND_LEAD_TITLE_RE = /^Inbound lead (\S+)$/;

/**
 * Compact Note-list view — NEVER carries bodyV2/markdown. NOTE: no isEmergency
 * field: this extension does not provision isEmergency on Note (only on
 * Person/Opportunity — see REQUIRED_FIELDS / setEmergencyMarker), so a Note has
 * no such marker to surface or filter on.
 */
export interface NoteView {
  id: string;
  title?: string;
  leadId?: string;
  createdAt?: string;
  updatedAt?: string;
}

/** Map a raw Note REST record to the compact {@link NoteView} (no body). */
export function mapNoteView(rec: Record<string, unknown>): NoteView {
  const v: NoteView = { id: String(rec.id ?? "") };
  const title = rec.title != null ? String(rec.title) : "";
  const m = title.match(INBOUND_LEAD_TITLE_RE); // SR-1 / CR-A-5
  if (m && validateLeadId(m[1])) v.title = title;
  if (rec.leadId != null && rec.leadId !== "") v.leadId = String(rec.leadId);
  if (rec.createdAt) v.createdAt = String(rec.createdAt);
  if (rec.updatedAt) v.updatedAt = String(rec.updatedAt);
  return v;
}

/**
 * Deterministic canonical JSON: object keys sorted, `undefined`-valued keys
 * dropped (matching JSON.stringify's object behavior). Used to hash a list
 * method's (filter, cursor) into a stable, separator-free instance key so the
 * empty-filter snapshot can never collide with a literal filter value and no
 * user value can inject the `-` key separator (AR-7).
 */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  const obj = v as Record<string, unknown>;
  const parts: string[] = [];
  for (const k of Object.keys(obj).sort()) {
    if (obj[k] === undefined) continue;
    parts.push(`${JSON.stringify(k)}:${canonicalJson(obj[k])}`);
  }
  return `{${parts.join(",")}}`;
}

/** First 16 hex chars of the SHA-256 of the canonical JSON of `obj` (AR-7). */
export async function listInstanceHash(obj: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(canonicalJson(obj));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);
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

// Canonical unique composite order (AR-4/V2-3): createdAt alone is NOT unique,
// so the id tiebreaker keeps cursor paging gap-free and snapshots byte-stable.
// Sent literally (constant, no injection risk); Twenty parses the comma as the
// two-key separator. VERIFY-LIVE: acceptance of this composite order_by + the
// starting_after cursor's consistency with it (spec openQuestion V2-3).
const LIST_ORDER = "createdAt,id";

// NULL-safe non-emergency exclusion (V2-1/criterion 6): matches rows where
// isEmergency is false OR null/unset — push_leads only stamps the marker on
// emergencies, so the NULL/unset rows are the majority and a bare
// isEmergency[eq]:false would silently drop them (and falsely reconcile as
// 'complete'). Constant DSL (parens/commas are literal grammar, not values).
// VERIFY-LIVE: the exact OR / IS-NULL syntax + isEmergency defaultValue (V2-1).
const NON_EMERGENCY_CLAUSE = "or(isEmergency[eq]:false,isEmergency[is]:NULL)";

/** One list method's paged, deduped result (see {@link listFiltered}). */
export interface ListPage {
  items: Array<Record<string, unknown>>;
  /** True when the per-call cap was reached with more pages available. */
  truncated: boolean;
  /** True when Twenty still has pages beyond this call (drives workflow loop). */
  hasMore: boolean;
  /** endCursor of the LAST fully-fetched page, to pass back as startingAfter. */
  nextCursor?: string;
  /** Twenty's reported total for the filter (exposed for workflow-level sums). */
  totalCount?: number;
  /** True only when the cursor is untrustworthy (no-progress / cursor-repeat). */
  incomplete: boolean;
  stopReason:
    | "complete"
    | "cap-reached"
    | "no-progress"
    | "cursor-repeat"
    | "max-pages"
    | "count-mismatch"
    | "no-total"
    | "unsupported-filter-value";
}

/**
 * Fan-out read (repo rule 6): page through records of `plural` matching the
 * AND-composed `clauses` in ONE call — the single generic paginator behind
 * listOpportunities/listPeople/listCompanies/listNotes. Each clause is a
 * ready-to-send `field[eq]:<url-encoded-value>` (or a constant DSL group like
 * {@link NON_EMERGENCY_CLAUSE}) built + validated by the caller; they are
 * comma-joined into one `filter=` param. Sends an explicit immutable `order_by`
 * (AR-4) so paging is gap-free.
 *
 * WHOLE-PAGE capping (CR-A-1/CR-A-2): a page is always consumed in full — every
 * record is appended (deduped by id within the call) and the cursor advances to
 * that page's `endCursor` — so the cursor handed back is ALWAYS a fully-consumed
 * page boundary. The next call resumes strictly after it: zero duplication and
 * zero skipped rows, even when `cap < PAGE_SIZE`. Consequently `cap` (from
 * `limit`) is a SOFT per-call floor: a call may return up to `PAGE_SIZE - 1`
 * more rows than `cap`, rounded up to the page boundary.
 *
 * Completeness is end-of-cursor (CR-A-3), not per-call reconciliation: a single
 * call cannot know its cumulative offset, so `complete`/`incomplete=false` is
 * reported whenever the loop ended on `hasNextPage=false`; `cap-reached` (with a
 * valid `nextCursor`) and the `max-pages` backstop are continuable, NOT
 * incomplete. `incomplete=true` is reserved for an untrustworthy cursor
 * (`no-progress`, `cursor-repeat`). A single-call whole-set read (no
 * `startingAfter`, `hasMore=false`) is the ONLY place a count is reconciled
 * against `totalCount` — matching -> `complete`, mismatch -> `count-mismatch`,
 * absent -> `no-total`; cross-call cumulative reconciliation is the workflow's
 * job, using the `totalCount` this envelope exposes.
 */
export async function listFiltered(
  cfg: TwentyCfg,
  plural: string,
  clauses: string[],
  cap: number,
  order: string,
  startingAfter?: string,
): Promise<ListPage> {
  const filterQ = clauses.length ? `filter=${clauses.join(",")}&` : "";
  const orderQ = order ? `order_by=${order}&` : "";

  const seen = new Set<string>();
  const items: Array<Record<string, unknown>> = [];
  let cursor: string | undefined = startingAfter;
  let totalCount: number | undefined;
  let hasMore = false;
  let nextCursor: string | undefined;
  let stopReason: ListPage["stopReason"] | undefined;
  // Backstop on page count in case the instance never reports hasNextPage:false.
  const maxPages = Math.ceil(cap / PAGE_SIZE) + 2;
  for (let page = 0; page < maxPages; page++) {
    const pageCursor = cursor; // the starting_after used for THIS fetch
    const path = `/rest/${plural}?${filterQ}${orderQ}limit=${PAGE_SIZE}` +
      (pageCursor ? `&starting_after=${encodeURIComponent(pageCursor)}` : "");
    const json = await twentyRequest(cfg, "GET", path);
    if (totalCount === undefined) {
      const tc = (json as { totalCount?: unknown }).totalCount;
      if (typeof tc === "number") totalCount = tc;
    }
    const batch = unwrapList(json, plural);
    const pageInfo = (json as {
      pageInfo?: { hasNextPage?: boolean; endCursor?: string };
    }).pageInfo;
    // Consume the WHOLE page — never slice mid-page (CR-A-1/CR-A-2).
    let newInPage = 0;
    for (const rec of batch) {
      const id = String(rec.id ?? "");
      if (!id || seen.has(id)) continue;
      newInPage++;
      seen.add(id);
      items.push(rec);
    }
    const endCursor = pageInfo?.endCursor;
    // Clean end of data.
    if (!pageInfo?.hasNextPage) {
      stopReason = "complete";
      break;
    }
    // hasNextPage is true — guard an untrustworthy cursor before advancing.
    if (!endCursor) {
      stopReason = "no-progress";
      break;
    }
    if (endCursor === pageCursor) {
      stopReason = "cursor-repeat";
      break;
    }
    if (newInPage === 0) {
      stopReason = "no-progress";
      break;
    }
    // Advance to this fully-consumed page's boundary, THEN honor the soft cap.
    cursor = endCursor;
    if (items.length >= cap) {
      hasMore = true;
      nextCursor = endCursor; // endCursor of the last FULLY-fetched page
      stopReason = "cap-reached";
      break;
    }
  }
  if (stopReason === undefined) {
    // Max-pages backstop (CR-A-6): the cursor is a consumed page boundary, so
    // the workflow can still continue — don't strand it, and don't flag it.
    stopReason = "max-pages";
    hasMore = true;
    nextCursor = cursor;
  }

  let incomplete = false;
  if (stopReason === "complete" && startingAfter === undefined) {
    // Single-call whole-set read: the ONLY place a count reconciles (CR-A-3).
    if (totalCount === undefined) {
      stopReason = "no-total";
      incomplete = true;
    } else if (items.length !== totalCount) {
      stopReason = "count-mismatch";
      incomplete = true;
    }
  } else if (stopReason === "no-progress" || stopReason === "cursor-repeat") {
    incomplete = true; // untrustworthy cursor — cannot safely continue
  }
  return {
    items,
    truncated: stopReason === "cap-reached",
    hasMore,
    nextCursor,
    totalCount,
    incomplete,
    stopReason,
  };
}

/**
 * listOpportunities' paginator, kept behavior-identical: builds the same AND
 * clauses and returns only {items, truncated}, now single-sourced through
 * {@link listFiltered} (which also sends the immutable order_by — AR-4).
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
  const page = await listFiltered(
    cfg,
    "opportunities",
    clauses,
    cap,
    LIST_ORDER,
  );
  return { items: page.items, truncated: page.truncated };
}

/**
 * Read the Opportunity object's live metadata: the `stage` SELECT enum values,
 * the two segmentation SELECT enums (`lineOfBusiness`, `sourceChannel`), and the
 * `closeDate` field type (DATE vs DATE_TIME). Used to fail fast on an invalid
 * stage / segmentation token and to format closeDate correctly for the instance.
 */
async function fetchOpportunityMeta(
  cfg: TwentyCfg,
): Promise<{
  stages: string[];
  closeDateType: string | null;
  lineOfBusiness: string[];
  sourceChannel: string[];
}> {
  const objs = await fetchObjectsMeta(cfg);
  const opp = objs.find((o) => String(o.nameSingular ?? "") === "opportunity");
  const fields = (opp?.fields ?? []) as Array<Record<string, unknown>>;
  const list = Array.isArray(fields) ? fields : [];
  // Extract a SELECT field's option value tokens (value ?? label), the same way
  // stage validation has always read them — shared so stage and the two
  // segmentation fields cannot drift.
  const optionValues = (fieldName: string): string[] => {
    const f = list.find((x) => String(x.name ?? "") === fieldName);
    const opts = (f?.options ?? []) as Array<Record<string, unknown>>;
    return Array.isArray(opts)
      ? opts.map((o) => String(o.value ?? o.label ?? "")).filter(Boolean)
      : [];
  };
  const stages = optionValues("stage");
  const lineOfBusiness = optionValues("lineOfBusiness");
  const sourceChannel = optionValues("sourceChannel");
  const cdField = list.find((f) => String(f.name ?? "") === "closeDate");
  const closeDateType = cdField ? (String(cdField.type ?? "") || null) : null;
  return { stages, closeDateType, lineOfBusiness, sourceChannel };
}

// --- Generic record upsert: strict controls (TWENTY-RECORD-UPSERT) ----------
// v1 object allowlist. ONLY these CUSTOM objects may be written by the generic
// upsertRecord; any other object (standard OR unlisted custom) is rejected
// BEFORE any I/O. This in-code allowlist — NOT an isCustom metadata flag — is
// the real safety control (see fetchUpsertObjectMeta for why isCustom is not
// available on this API surface). Extend deliberately.
const UPSERT_OBJECT_ALLOWLIST = new Set<string>([
  "subscription",
  "channelPartner",
]);
// Scalar field TYPEs upsertRecord may write. Composites (CURRENCY / EMAILS /
// PHONES / FULL_NAME / LINKS / ADDRESS / RELATION / ACTOR / POSITION / …) are
// rejected pre-write with a clear error rather than a blind Twenty 400 —
// composite support is v2.
const UPSERT_SCALAR_TYPES = new Set<string>([
  "TEXT",
  "NUMBER",
  "BOOLEAN",
  "DATE_TIME",
  "SELECT",
  "UUID",
]);
// Immutable/system fields no caller may set as matchField OR in `fields`.
const UPSERT_RESERVED_FIELDS = new Set<string>([
  "id",
  "createdAt",
  "updatedAt",
  "deletedAt",
  "position",
]);
const UPSERT_MATCH_VALUE_CAP = 200;
const UPSERT_FIELD_TEXT_CAP = 500;

/**
 * Resolve the write-relevant metadata for ONE object by nameSingular: its REST
 * plural (read from metadata, never guessed) and a name→{type, SELECT-option
 * values} map for every field. upsertRecord uses this to resolve the plural,
 * cross-check that matchField and every `fields` key exist and are scalar, and
 * validate SELECT values against the LIVE enum before a write. Throws if the
 * object is absent from workspace metadata.
 *
 * NOTE (isCustom — live-verified 2026-09-16 against crm.shrug.pw, Twenty
 * v2.38.x): the `/rest/metadata/objects` rows carry NO `isCustom` flag. The row
 * keys are id / universalIdentifier / applicationId / nameSingular / namePlural
 * / label* / description / icon / isRemote / isActive / isSystem / isUI* /
 * isSearchable / … / fields — and `isSystem` is `false` for BOTH standard
 * (person, opportunity) AND custom (subscription, channelPartner) objects, so it
 * cannot distinguish custom from standard. Per the approved spec's resolution #6
 * the strict UPSERT_OBJECT_ALLOWLIST is the real control, so the isCustom
 * defense-in-depth assert is intentionally DROPPED (the flag is unavailable on
 * this API surface). Re-verify and reinstate a `== true` assert if a future
 * Twenty version exposes a reliable custom flag here.
 */
async function fetchUpsertObjectMeta(
  cfg: TwentyCfg,
  objectNameSingular: string,
): Promise<{
  plural: string;
  fields: Map<string, { type: string; options: string[] }>;
}> {
  const objs = await fetchObjectsMeta(cfg);
  const obj = objs.find(
    (o) => String(o.nameSingular ?? "") === objectNameSingular,
  );
  if (!obj) {
    throw new Error(
      `Object '${objectNameSingular}' not found in workspace metadata`,
    );
  }
  const plural = String(obj.namePlural ?? "");
  if (!plural) {
    throw new Error(
      `Object '${objectNameSingular}' has no namePlural in workspace metadata`,
    );
  }
  const fieldList = (obj.fields ?? []) as Array<Record<string, unknown>>;
  const fields = new Map<string, { type: string; options: string[] }>();
  for (const f of Array.isArray(fieldList) ? fieldList : []) {
    const name = String(f.name ?? "");
    if (!name) continue;
    const type = String(f.type ?? "");
    const opts = (f.options ?? []) as Array<Record<string, unknown>>;
    const options = Array.isArray(opts)
      ? opts.map((o) => String(o.value ?? o.label ?? "")).filter(Boolean)
      : [];
    fields.set(name, { type, options });
  }
  return { plural, fields };
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

/**
 * Derive a Twenty metadata `name` (camelCase identifier) from a human label the
 * SAME way Twenty's server-side `computeMetadataNameFromLabel` does: strip
 * diacritics, tokenize on non-alphanumerics AND camelCase/upper-run/digit
 * boundaries (lodash `camelCase` semantics), lowercase the first token and
 * upper-case-lead the rest. This mirrors the reverse-field name Twenty auto-mints
 * from `targetFieldLabel` when it creates a RELATION, so ensureRelation can
 * pre-check the target object for a name collision BEFORE the POST (the server
 * otherwise 400s FIELD_METADATA_RELATION_MALFORMED / name-taken). Examples:
 * "Opportunities" -> "opportunities", "Line Items" -> "lineItems",
 * "Purchase Orders 2" -> "purchaseOrders2".
 */
export function computeMetadataNameFromLabel(label: string): string {
  const stripped = String(label ?? "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, ""); // drop combining diacritics
  const words = stripped.match(
    /[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+/g,
  ) ?? [];
  if (words.length === 0) return "";
  return words
    .map((w, i) =>
      i === 0 ? w.toLowerCase() : w[0].toUpperCase() + w.slice(1).toLowerCase()
    )
    .join("");
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
  const objs = await fetchObjectsMeta(cfg);
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
      typeof color !== "string" || typeof position !== "number" ||
      typeof opt.id !== "string" || !opt.id
    ) {
      throw new Error(
        `Option #${i} on '${objectNameSingular}.${fieldName}' is missing id/value/label/color/position; refusing to rebuild a lossy options array`,
      );
    }
    // Preserve the existing option's id verbatim — omitting it on the full-array
    // PATCH would risk Twenty treating the entry as a new option (re-create /
    // duplicate), so a non-string/empty id hard-stops above rather than degrade.
    return { id: opt.id, value, label, color, position };
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

// --- Generalized field provisioning helpers (TWENTY-ENSURE-FIELD) ------------

// The field types ensureField provisions. SELECT is handled specially (carries
// an options array). MULTI_SELECT and RELATION are intentionally out of scope in
// v1 (RELATION is CRM-TASKS #4, a separate work item).
type EnsureFieldType = "TEXT" | "BOOLEAN" | "NUMBER" | "DATE_TIME" | "SELECT";
const ENSURE_FIELD_TYPES = new Set<EnsureFieldType>([
  "TEXT",
  "BOOLEAN",
  "NUMBER",
  "DATE_TIME",
  "SELECT",
]);

// A Twenty custom-field `name` is a camelCase identifier (letter-led, alnum).
// Gating the metadata POST on this means a typo/CEL slip can never post a garbage
// field name (mirrors ensureStageOption's value allowlisting discipline).
const FIELD_NAME_RE = /^[a-z][A-Za-z0-9]*$/;

/** A requested SELECT option before id assignment (label/color defaulted). */
interface RequestedOption {
  value: string;
  label?: string;
  color?: string;
}

/** A validated, id-less SELECT option with its position assigned. */
interface PlannedOption {
  value: string;
  label: string;
  color: string;
  position: number;
}

/** The declarative spec for one field ensureField provisions. */
interface FieldSpec {
  objectNameSingular: string;
  name: string;
  label: string;
  type: EnsureFieldType;
  options?: RequestedOption[]; // SELECT only
  description?: string;
}

/** Structured outcome of ensuring one field (before snapshot envelope fields). */
interface FieldEnsureOutcome {
  object: string;
  name: string;
  type: string;
  action:
    | "created"
    | "present"
    | "planned-create"
    | "options-appended"
    | "planned-append"
    | "options-reconciled"
    | "planned-reconcile";
  optionsAdded: string[];
  optionsUpdated: string[];
  optionsPresent: string[];
  mismatchNotes: string[];
  typeMismatch?: string;
  // For a SELECT: the resulting (or, on dryRun, planned) full option set WITH
  // colors — so a recolor/append is verifiable straight from this snapshot
  // without a second read or the Twenty UI. Undefined for non-SELECT fields.
  options?: Array<{
    value: string;
    label: string;
    color: string;
    position: number;
  }>;
}

/**
 * Validate + normalize one requested SELECT option into canonical shape at the
 * given position. PURE (no id, no I/O) so the planner is deterministic and
 * unit-testable; the impure caller mints the client uuid. Throws on an invalid
 * value/color using the SAME rules as ensureStageOption: value UPPER_SNAKE,
 * color from Twenty's palette, label defaulted to the title-cased token.
 */
export function normalizeRequestedOption(
  raw: RequestedOption,
  position: number,
): PlannedOption {
  const value = String(raw?.value ?? "").trim();
  if (!STAGE_OPTION_VALUE_RE.test(value)) {
    throw new Error(
      `Invalid SELECT option value '${value}': must be UPPER_SNAKE (A-Z, 0-9, _), letter-led`,
    );
  }
  const color = String(raw?.color ?? "gray");
  if (!STAGE_OPTION_COLORS.has(color)) {
    throw new Error(
      `Invalid SELECT option color '${color}' (allowed: ${
        [...STAGE_OPTION_COLORS].join(", ")
      })`,
    );
  }
  const label = raw?.label != null && String(raw.label).trim()
    ? sanitizeText(raw.label, 60)
    : titleCaseToken(value);
  return { value, label, color, position };
}

/**
 * PURE SELECT-option planner — the shared discipline ensureField relies on.
 * Genuinely-new options are appended after the current max position. A requested
 * option whose value already exists but differs in label/color is, by default
 * (`reconcile`), RECONCILED IN PLACE: its id and position are preserved and the
 * new label+color are applied — swamp is the source of truth for these
 * model-owned options, so a drift is corrected, not merely reported. (The old
 * append-only "never recolor" guard only mattered when a human might hand-edit
 * options in the Twenty UI; pass `reconcile:false` to restore it — the drift is
 * then REPORTED via `mismatches` and left unchanged.) An exact match is always a
 * no-op. New options carry no id (the impure caller mints one before the write).
 * Duplicate requested values are collapsed. Throws (via normalizeRequestedOption)
 * on any invalid requested option, so a partially-built plan never reaches a write.
 */
export function planSelectOptions(
  existing: SelectOption[],
  requested: RequestedOption[],
  opts: { reconcile?: boolean } = {},
): {
  merged: SelectOption[];
  added: PlannedOption[];
  updated: SelectOption[];
  present: string[];
  mismatches: string[];
} {
  const reconcile = opts.reconcile ?? true;
  const byValue = new Map(existing.map((o) => [o.value, o]));
  let maxPos = existing.reduce((m, o) => Math.max(m, o.position), -1);
  const added: PlannedOption[] = [];
  const updated: SelectOption[] = [];
  const present: string[] = [];
  const mismatches: string[] = [];
  const seen = new Set<string>();
  for (const req of requested) {
    const norm = normalizeRequestedOption(req, 0);
    if (seen.has(norm.value)) continue; // collapse duplicates within the request
    seen.add(norm.value);
    const hit = byValue.get(norm.value);
    if (hit) {
      present.push(norm.value);
      if (hit.label !== norm.label || hit.color !== norm.color) {
        if (reconcile) {
          updated.push({ ...hit, label: norm.label, color: norm.color });
        } else {
          mismatches.push(
            `Option '${norm.value}' exists with label='${hit.label}' color='${hit.color}'; ` +
              `requested label='${norm.label}' color='${norm.color}' — left unchanged (no mutation).`,
          );
        }
      }
      continue;
    }
    maxPos += 1;
    added.push({ ...norm, position: maxPos });
  }
  const updatedByValue = new Map(updated.map((o) => [o.value, o]));
  const merged: SelectOption[] = [
    ...existing.map((o) => updatedByValue.get(o.value) ?? o),
    ...added.map((o) => ({ ...o })),
  ];
  return { merged, added, updated, present, mismatches };
}

/**
 * Project a SELECT option set down to the palette shape
 * (value/label/color/position), dropping any id — used to record the verifiable
 * resulting-options snapshot so a recolor/append can be confirmed without a
 * second read or the Twenty UI.
 */
function paletteOf(
  opts: ReadonlyArray<
    { value: string; label: string; color: string; position: number }
  >,
): Array<{ value: string; label: string; color: string; position: number }> {
  return opts.map(({ value, label, color, position }) => ({
    value,
    label,
    color,
    position,
  }));
}

/**
 * GET /rest/metadata/objects → the FULL object metadata array, paginated.
 *
 * The metadata endpoint is a cursor connection like the record lists: it returns
 * at most one page (default first `PAGE_SIZE`) with a top-level
 * `pageInfo { hasNextPage, endCursor }`. A workspace with more objects than one
 * page would otherwise be silently truncated — so page through with
 * `starting_after` until `hasNextPage` is false, accumulating every page's
 * `.data` array (deduped by id). Guards mirror {@link listFiltered}: stop on a
 * missing/repeated cursor (untrustworthy) and a page-count backstop, and an
 * instance that reports no `pageInfo` simply runs one page — identical to the
 * prior single-GET behavior, so this is a strict superset (no regression).
 */
export async function fetchObjectsMeta(
  cfg: TwentyCfg,
): Promise<Array<Record<string, unknown>>> {
  const seen = new Set<string>();
  const objs: Array<Record<string, unknown>> = [];
  let cursor: string | undefined;
  // Standard Twenty exposes ~20 objects; a generous backstop guards a
  // never-terminating cursor without capping any realistic workspace.
  const maxPages = 50;
  for (let page = 0; page < maxPages; page++) {
    const pageCursor = cursor;
    const path = "/rest/metadata/objects?" +
      `limit=${PAGE_SIZE}` +
      (pageCursor ? `&starting_after=${encodeURIComponent(pageCursor)}` : "");
    const json = await twentyRequest(cfg, "GET", path);
    const batch = ((json as { data?: unknown }).data ?? []) as Array<
      Record<string, unknown>
    >;
    let newInPage = 0;
    for (const rec of Array.isArray(batch) ? batch : []) {
      const id = String(rec.id ?? "");
      // Metadata rows always carry an id; fall back to nameSingular so a rare
      // id-less row is still not dropped.
      const key = id || `name:${String(rec.nameSingular ?? "")}`;
      if (seen.has(key)) continue;
      newInPage++;
      seen.add(key);
      objs.push(rec);
    }
    const pageInfo = (json as {
      pageInfo?: { hasNextPage?: boolean; endCursor?: string };
    }).pageInfo;
    // No more pages (or an instance that doesn't paginate metadata) → done.
    if (!pageInfo?.hasNextPage) break;
    const endCursor = pageInfo.endCursor;
    // hasNextPage but an untrustworthy cursor (absent / repeated / no progress):
    // stop rather than loop forever — return what we have.
    if (!endCursor || endCursor === pageCursor || newInPage === 0) break;
    cursor = endCursor;
  }
  return objs;
}

/**
 * Idempotently ensure ONE field exists on an object via the metadata API — the
 * shared core behind both ensureField (single, throws) and ensureLeadFields
 * (fan-out, swallows per-field errors into a report). Non-destructive:
 *   - absent            → POST /rest/metadata/fields (create); SELECT carries
 *                         its full validated + client-id'd options array;
 *   - present, scalar   → no-op (a differing type is REPORTED, never mutated);
 *   - present, SELECT   → append-only plan; if new options, re-read + drift-check
 *                         (optimistic concurrency, no server ETag) then an
 *                         options-only PATCH; if none new, a no-op.
 * `dryRun` validates + plans and writes nothing. Throws on a validation error or
 * an absent object so the caller can decide whether to swallow or surface it.
 * `objectsSnapshot` (optional) lets a fan-out caller pass one GET result for
 * presence detection; the SELECT-append path always re-reads fresh for its
 * concurrency check regardless.
 */
async function ensureFieldOnce(
  cfg: TwentyCfg,
  spec: FieldSpec,
  dryRun: boolean,
  objectsSnapshot?: Array<Record<string, unknown>>,
  reconcile = true,
): Promise<FieldEnsureOutcome> {
  const name = String(spec.name ?? "").trim();
  if (!FIELD_NAME_RE.test(name)) {
    throw new Error(
      `Invalid field name '${name}': must be a camelCase identifier (letter-led, alphanumeric)`,
    );
  }
  if (!ENSURE_FIELD_TYPES.has(spec.type)) {
    throw new Error(
      `Unsupported field type '${spec.type}' (allowed: ${
        [...ENSURE_FIELD_TYPES].join(", ")
      })`,
    );
  }
  const isSelect = spec.type === "SELECT";
  const requested = spec.options ?? [];
  if (isSelect && requested.length === 0) {
    throw new Error(
      `SELECT field '${spec.objectNameSingular}.${name}' requires at least one option`,
    );
  }
  if (!isSelect && requested.length > 0) {
    throw new Error(
      `Field type '${spec.type}' does not take options (SELECT only)`,
    );
  }
  const label = spec.label != null && String(spec.label).trim()
    ? sanitizeText(spec.label, 120)
    : titleCaseToken(name);

  const objs = objectsSnapshot ?? (await fetchObjectsMeta(cfg));
  const obj = objs.find(
    (o) => String(o.nameSingular ?? "") === spec.objectNameSingular,
  );
  if (!obj) {
    throw new Error(
      `Object '${spec.objectNameSingular}' not found in workspace metadata`,
    );
  }
  const objectMetadataId = String(obj.id ?? "");
  const fields = (obj.fields ?? []) as Array<Record<string, unknown>>;
  const existingField = (Array.isArray(fields) ? fields : []).find(
    (f) => String(f.name ?? "") === name,
  );

  const out: FieldEnsureOutcome = {
    object: spec.objectNameSingular,
    name,
    type: spec.type,
    action: "present",
    optionsAdded: [],
    optionsUpdated: [],
    optionsPresent: [],
    mismatchNotes: [],
  };

  // CREATE path.
  if (!existingField) {
    if (!objectMetadataId) {
      throw new Error(
        `Object '${spec.objectNameSingular}' has no metadata id; cannot create '${name}'`,
      );
    }
    const body: Record<string, unknown> = {
      name,
      label,
      type: spec.type,
      objectMetadataId,
    };
    if (spec.description) {
      body.description = sanitizeText(spec.description, 500);
    }
    if (isSelect) {
      const plan = planSelectOptions([], requested); // every option is new
      const withIds = plan.added.map((o) => ({
        id: crypto.randomUUID(),
        ...o,
      }));
      out.optionsAdded = withIds.map((o) => o.value);
      body.options = withIds;
      out.options = paletteOf(withIds);
    }
    if (dryRun) {
      out.action = "planned-create";
      return out;
    }
    await twentyRequest(cfg, "POST", "/rest/metadata/fields", body);
    out.action = "created";
    return out;
  }

  // PRESENT path — never mutate a scalar; report a type drift.
  const existingType = String(existingField.type ?? "");
  if (existingType !== spec.type) {
    out.typeMismatch =
      `Field '${spec.objectNameSingular}.${name}' exists as type '${existingType}', ` +
      `requested '${spec.type}' — left unchanged (no mutation).`;
  }
  if (!isSelect || existingType !== "SELECT") {
    out.action = "present";
    return out;
  }

  // PRESENT SELECT — append new options + (by default) reconcile drifted ones,
  // reusing ensureStageOption's read/plan/PATCH discipline.
  const field = await fetchSelectField(cfg, spec.objectNameSingular, name);
  const plan = planSelectOptions(field.options, requested, { reconcile });
  out.optionsPresent = plan.present;
  out.optionsUpdated = plan.updated.map((o) => o.value);
  out.mismatchNotes = plan.mismatches;
  // The resulting palette (with colors) either way: unchanged live set on a
  // no-op, or the reconciled/appended plan.merged when there's a write.
  out.options = paletteOf(
    plan.added.length === 0 && plan.updated.length === 0
      ? field.options
      : plan.merged,
  );
  if (plan.added.length === 0 && plan.updated.length === 0) {
    out.action = "present";
    return out;
  }
  out.optionsAdded = plan.added.map((o) => o.value);
  const appending = plan.added.length > 0;
  if (dryRun) {
    out.action = appending ? "planned-append" : "planned-reconcile";
    return out;
  }
  // Optimistic concurrency: re-read immediately before the write and abort if the
  // option set drifted (best-effort — Twenty exposes no ETag).
  const fresh = await fetchSelectField(cfg, spec.objectNameSingular, name);
  if (!optionsEquivalent(fresh.options, field.options)) {
    throw new Error(
      `Options for '${spec.objectNameSingular}.${name}' changed between read and write (concurrent edit); aborting to avoid a lossy overwrite. Re-run.`,
    );
  }
  // plan.merged = existing options (ids + positions preserved, label/color
  // reconciled in place) followed by appended options (id-less — mint here).
  const merged: SelectOption[] = plan.merged.map((o) =>
    (o as { id?: string }).id ? o : { id: crypto.randomUUID(), ...o }
  );
  // options-only PATCH — Twenty's metadata field PATCH is a partial update, so
  // sibling attributes (name/label/type/isNullable) survive. We send ONLY options.
  await twentyRequest(cfg, "PATCH", `/rest/metadata/fields/${field.fieldId}`, {
    options: merged,
  });
  out.action = appending ? "options-appended" : "options-reconciled";
  return out;
}

/**
 * The two Opportunity segmentation SELECT fields (CRM-TASKS #5). Analytics only
 * — NOT a pipeline gate. `sourceChannel` is what push_leads stamps (see the
 * `leadSourceChannel` global). Provisioned via the shared append-only ensureField
 * path so a re-run is a clean no-op.
 */
export const OPPORTUNITY_SEGMENTATION_FIELDS: ReadonlyArray<FieldSpec> = [
  {
    objectNameSingular: "opportunity",
    name: "lineOfBusiness",
    label: "Line of Business",
    type: "SELECT",
    options: [
      { value: "CONSULTING", label: "Consulting", color: "blue" },
      { value: "HOSTING", label: "Hosting", color: "green" },
      { value: "GAMES", label: "Games", color: "purple" },
    ],
  },
  {
    objectNameSingular: "opportunity",
    name: "sourceChannel",
    label: "Source Channel",
    type: "SELECT",
    options: [
      { value: "DIRECT", label: "Direct", color: "sky" },
      { value: "REFERRAL", label: "Referral", color: "turquoise" },
      {
        value: "CONSULTING_HANDOFF",
        label: "Consulting hand-off",
        color: "purple",
      },
    ],
  },
];

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
    kvParsed: z.number().optional().describe(
      "Leads adapted from kvEntries this run",
    ),
    kvUnparseable: z.number().optional().describe(
      "kvEntries dropped as non-JSON / empty (never silently ignored)",
    ),
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
  lineOfBusiness: z
    .string()
    .optional()
    .describe("Line of Business segmentation token written, if set"),
  sourceChannel: z
    .string()
    .optional()
    .describe("Source Channel segmentation token written, if set"),
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

// --- Generic record upsert snapshot (TWENTY-RECORD-UPSERT) ------------------
// The outcome of an upsertRecord run: the action taken, the resolved object
// identity + plural, the natural-key field, and the create/patch payload shape.
// The raw natural-key matchValue is NEVER persisted: it is stored only as a hash
// (matchValueHash), and inside creationPayload the matchField entry is likewise
// the hash placeholder `[hashed:<hash>]`, not the raw value — so an
// attacker-influenced natural key cannot leak into this durable
// (lifetime:infinite) resource. The other scalar VALUES in writtenFields /
// creationPayload are recorded as submitted (in-scope by spec, matching
// upsertOpportunity's posture of persisting submitted — never Twenty-response —
// values). No raw Twenty response body is persisted.
const RecordUpsertedSchema = z.object({
  baseUrl: z.string(),
  action: z.enum(["created", "updated", "planned-create", "planned-update"]),
  dryRun: z.boolean(),
  objectNameSingular: z.string(),
  plural: z.string(),
  matchField: z.string(),
  matchValueHash: z
    .string()
    .describe("Hash of the canonical natural-key value (never the raw value)"),
  recordId: z.string().optional(),
  writtenFields: z
    .record(z.string(), z.unknown())
    .describe(
      "Sanitized scalar fields sent in the create/patch (excludes matchField)",
    ),
  creationPayload: z
    .record(z.string(), z.unknown())
    .describe(
      "The create body SHAPE: writtenFields plus the matchField — whose value is the `[hashed:<hash>]` placeholder here, never the raw natural key (the real POST sends the canonical value)",
    ),
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
  lineOfBusiness: z.string().optional(),
  sourceChannel: z.string().optional(),
  isEmergency: z.boolean().optional(),
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
  lineOfBusiness: z.string().optional(),
  sourceChannel: z.string().optional(),
  isEmergency: z.boolean().optional(),
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

// --- Bulk-list snapshots (TWENTY-SNAPSHOT-READS) ----------------------------
// opportunityList-shaped PLUS continuation (AR-1) + honesty (AR-2) fields.

const ListStopReasonSchema = z.enum([
  "complete",
  "cap-reached",
  "no-progress",
  "cursor-repeat",
  "max-pages",
  "count-mismatch",
  "no-total",
  "unsupported-filter-value",
]);

const PersonViewSchema = z.object({
  id: z.string(),
  leadId: z.string().optional(),
  companyId: z.string().optional(),
  isEmergency: z.boolean().optional(),
  createdAt: z.string().optional(),
});

const CompanyViewSchema = z.object({
  id: z.string(),
  name: z.string(),
  domain: z.string().optional(),
  createdAt: z.string().optional(),
});

const NoteViewSchema = z.object({
  id: z.string(),
  title: z.string().optional(),
  leadId: z.string().optional(),
  createdAt: z.string().optional(),
  updatedAt: z.string().optional(),
});

const PeopleListSchema = z.object({
  baseUrl: z.string(),
  count: z.number().describe("Unique ids collected this call"),
  truncated: z
    .boolean()
    .describe("True only when the per-call cap was hit with more available"),
  hasMore: z
    .boolean()
    .describe("True when Twenty has more pages beyond this call (loop driver)"),
  nextCursor: z
    .string()
    .optional()
    .describe("Last endCursor to pass back as startingAfter; set iff hasMore"),
  totalCount: z
    .number()
    .optional()
    .describe("Twenty's reported total for the filter (for reconciliation)"),
  incomplete: z
    .boolean()
    .describe("True on any guard exit or a count that did not reconcile"),
  stopReason: ListStopReasonSchema,
  filter: z.object({
    companyId: z.string().optional(),
    leadId: z.string().optional(),
    includeEmergency: z.boolean().optional(),
  }),
  items: z.array(PersonViewSchema),
  retrievedAt: z.iso.datetime(),
});

const CompanyListSchema = z.object({
  baseUrl: z.string(),
  count: z.number().describe("Unique ids collected this call"),
  truncated: z
    .boolean()
    .describe("True only when the per-call cap was hit with more available"),
  hasMore: z
    .boolean()
    .describe("True when Twenty has more pages beyond this call (loop driver)"),
  nextCursor: z.string().optional(),
  totalCount: z.number().optional(),
  incomplete: z.boolean(),
  stopReason: ListStopReasonSchema,
  filter: z.object({
    domain: z.string().optional(),
    name: z.string().optional(),
  }),
  items: z.array(CompanyViewSchema),
  retrievedAt: z.iso.datetime(),
});

const NoteListSchema = z.object({
  baseUrl: z.string(),
  count: z.number().describe("Unique ids collected this call"),
  truncated: z
    .boolean()
    .describe("True only when the per-call cap was hit with more available"),
  hasMore: z
    .boolean()
    .describe("True when Twenty has more pages beyond this call (loop driver)"),
  nextCursor: z.string().optional(),
  totalCount: z.number().optional(),
  incomplete: z.boolean(),
  stopReason: ListStopReasonSchema,
  filter: z.object({
    leadId: z.string().optional(),
  }),
  items: z.array(NoteViewSchema),
  retrievedAt: z.iso.datetime(),
});

const NoteDeleteSchema = z.object({
  baseUrl: z.string(),
  leadId: z.string().nullable(),
  noteId: z.string().nullable(),
  resolvedVia: z.enum(["noteId", "leadId"]),
  found: z.boolean().describe("Whether a matching Note existed to act on"),
  dryRun: z.boolean(),
  deleted: z.boolean().describe("True only on a confirmed, non-dry delete"),
  at: z.iso.datetime(),
});

// --- SELECT-option snapshot (TWENTY-STAGE-OPTION) ---------------------------

const StageOptionSchema = z.object({
  baseUrl: z.string(),
  object: z.string(),
  field: z.string(),
  value: z.string(),
  label: z.string(),
  color: z.string(),
  action: z.enum([
    "present",
    "created",
    "planned-create",
    "updated",
    "planned-update",
  ]),
  mismatchNote: z
    .string()
    .optional()
    .describe(
      "Set when the value already exists with a different label/color AND reconcile:false (left unchanged)",
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

// --- Generalized field-provisioning snapshot (TWENTY-ENSURE-FIELD) ----------

const FieldEnsuredSchema = z.object({
  baseUrl: z.string(),
  object: z.string(),
  name: z.string(),
  type: z.string(),
  action: z.enum([
    "created",
    "present",
    "planned-create",
    "options-appended",
    "planned-append",
    "options-reconciled",
    "planned-reconcile",
  ]),
  dryRun: z.boolean(),
  optionsAdded: z
    .array(z.string())
    .describe("SELECT option values created/appended this run (or planned)"),
  optionsUpdated: z
    .array(z.string())
    .describe(
      "Existing SELECT option values reconciled in place (label/color updated) this run (or planned)",
    ),
  optionsPresent: z
    .array(z.string())
    .describe("SELECT option values that already existed"),
  mismatchNotes: z
    .array(z.string())
    .describe(
      "Non-mutating notes (reconcile:false only): an existing option whose label/color differed from the request",
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
    .optional()
    .describe(
      "SELECT only: the resulting (or planned, on dryRun) full option set WITH colors — lets a recolor/append be verified from this snapshot",
    ),
  typeMismatch: z
    .string()
    .optional()
    .describe(
      "Set when a field with this name exists as a DIFFERENT type (left unchanged)",
    ),
  retrievedAt: z.iso.datetime(),
});

// --- Custom-object provisioning snapshot (TWENTY-ENSURE-OBJECT) -------------
// The outcome of ensureObject: whether the custom OBJECT was created, already
// existed, or (on dryRun) would be created — plus its identity and the exact
// create payload, so a planned-create is verifiable straight from the snapshot
// without a second read or the Twenty UI. No PII (object metadata only).

const ObjectEnsuredSchema = z.object({
  baseUrl: z.string(),
  nameSingular: z.string(),
  namePlural: z.string(),
  labelSingular: z.string(),
  labelPlural: z.string(),
  action: z.enum(["created", "present", "planned-create"]),
  dryRun: z.boolean(),
  objectId: z
    .string()
    .optional()
    .describe(
      "The object's metadata id: the existing id when already present, or the newly minted id when created (absent on planned-create)",
    ),
  description: z.string().optional(),
  icon: z.string().optional().describe(
    "Twenty icon name, e.g. IconFileInvoice",
  ),
  payload: z
    .record(z.string(), z.unknown())
    .optional()
    .describe(
      "The create body sent (or, on planned-create, that WOULD be sent) to POST /rest/metadata/objects — absent when the object already existed",
    ),
  retrievedAt: z.iso.datetime(),
});

// --- Custom-relation provisioning snapshot (TWENTY-ENSURE-RELATION) ---------
// The outcome of ensureRelation: whether the RELATION field (created as a field
// via POST /rest/metadata/fields with a relationCreationPayload block) was
// created, already existed, or (on dryRun) would be created — plus both objects'
// identities, the derived reverse-field name Twenty auto-mints on the target,
// the server-read-back settings/relation detail, and the exact create payload.
// No PII (object/field metadata only).

const RelationEnsuredSchema = z.object({
  baseUrl: z.string(),
  action: z.enum(["created", "present", "planned-create", "type-mismatch"]),
  dryRun: z.boolean(),
  fromObjectNameSingular: z.string().describe("Source object (owns the field)"),
  toObjectNameSingular: z.string().describe(
    "Target object (relation points to)",
  ),
  name: z.string().describe("Source-side relation field name (camelCase)"),
  fromFieldName: z.string().describe(
    "Source-side relation field name (= instance-name key component)",
  ),
  label: z.string().describe("Source-side field label"),
  type: z
    .string()
    .describe("RELATION — or, on a type-mismatch, the existing field's type"),
  relationType: z
    .string()
    .describe("MANY_TO_ONE | ONE_TO_MANY (the source side)"),
  reverseFieldName: z
    .string()
    .describe(
      "Derived reverse-field name Twenty auto-mints on the target = computeMetadataNameFromLabel(targetFieldLabel)",
    ),
  targetFieldLabel: z.string(),
  targetFieldIcon: z.string().describe(
    "Tabler icon name for the reverse field",
  ),
  objectMetadataId: z
    .string()
    .optional()
    .describe("Source object metadata id"),
  targetObjectMetadataId: z
    .string()
    .optional()
    .describe("Target object metadata id (must pre-exist)"),
  fieldId: z
    .string()
    .optional()
    .describe("Source relation field id (read back after a create)"),
  onDelete: z
    .string()
    .optional()
    .describe(
      "Server-defaulted FK behavior (SET_NULL on the MANY_TO_ONE side)",
    ),
  joinColumnName: z
    .string()
    .optional()
    .describe("FK join column on the many side, e.g. `${name}Id`"),
  relation: z
    .object({
      targetObjectMetadata: z
        .object({
          id: z.string().optional(),
          nameSingular: z.string().optional(),
        })
        .optional(),
      sourceFieldMetadata: z
        .object({ id: z.string().optional(), name: z.string().optional() })
        .optional(),
      targetFieldMetadata: z
        .object({ id: z.string().optional(), name: z.string().optional() })
        .optional(),
    })
    .optional()
    .describe("Read-back relation detail from the field DTO after a create"),
  payload: z
    .record(z.string(), z.unknown())
    .optional()
    .describe(
      "The create body sent (or, on planned-create, that WOULD be sent) to POST /rest/metadata/fields including relationCreationPayload — absent when the relation already existed",
    ),
  typeMismatch: z
    .string()
    .optional()
    .describe(
      "Set when a field with this name exists as a DIFFERENT type (left unchanged)",
    ),
  targetMismatch: z
    .string()
    .optional()
    .describe(
      "Set when the field exists as a RELATION but points at a different target/relationType than requested (left unchanged)",
    ),
  retrievedAt: z.iso.datetime(),
});

// --- Curated contact snapshot (TWENTY-PERSON-UPSERT) ------------------------
// Carries NO raw PII (no email/name/phone) — only the id, which fields were
// set, and the company link — matching opportunityUpsert's posture.

const PersonUpsertSchema = z.object({
  baseUrl: z.string(),
  action: z.enum(["created", "updated", "planned-create", "planned-update"]),
  dryRun: z.boolean(),
  personId: z.string().optional(),
  fieldsSet: z
    .array(z.string())
    .describe(
      "Which Person fields the write set (name/phone/jobTitle/city/company)",
    ),
  companyId: z.string().optional(),
  companyLinked: z.boolean(),
  companyNote: z
    .string()
    .optional()
    .describe("Why a company was not linked (degraded path), if applicable"),
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
        sourceChannel: cfg.leadSourceChannel || undefined,
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
    const note = await ensureNoteForLead(cfg, {
      leadId: p.leadId,
      body: buildLeadNoteBody(p) || `Inbound lead ${p.leadId}`,
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
  version: "2026.09.15.2",
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
    {
      toVersion: "2026.09.06.3",
      description:
        "Add upsertPerson (idempotent-on-email curated contact writer, confirm-gated) and the personUpsert snapshot. globalArguments is unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.08.1",
      description:
        "Add the bulk read surface: listPeople/listCompanies/listNotes fan-out snapshot reads (+ peopleList/companyList/noteList resources) sharing one generic cursor paginator with listOpportunities (which now also sends the immutable order_by=createdAt,id). globalArguments is unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.10.1",
      description:
        'Add the generalized ensureField provisioning method (TEXT/BOOLEAN/NUMBER/DATE_TIME/SELECT, append-only on SELECT) with ensureLeadFields refactored to a thin wrapper over it; add the ensureOpportunitySegmentation fan-out (Line of Business + Source Channel) and the fieldEnsured resource; wire push_leads to stamp the new leadSourceChannel global on created Opportunities. globalArguments gains one OPTIONAL field, leadSourceChannel (default ""), so this is a no-op attribute migration — existing instances lazily acquire the empty default and behave identically until it is set.',
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.10.2",
      description:
        "Teach upsertOpportunity to write the two Opportunity segmentation SELECT fields: optional lineOfBusiness and sourceChannel tokens, validated against the live opportunity.lineOfBusiness/sourceChannel enums exactly like stage, written on both the create and update paths and omitted (never nulled) when unset. Additive method arguments + two optional opportunityUpsert snapshot fields only; globalArguments is unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.15.1",
      description:
        "Add the schema-provisioning methods ensureObject (idempotent create/ensure of a custom object, dryRun/confirm-gated) and ensureRelation (idempotent create/ensure of a RELATION field between two objects, single call provisions both sides), plus the computeMetadataNameFromLabel helper for reverse-name collision pre-check. Additive methods and resources only; globalArguments is unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.15.2",
      description:
        "Fix ensureObject recording objectId:null after a live create: the create POST response envelope (Twenty v2.38.x) does not match the best-effort id extraction, so objectId is now resolved deterministically by re-reading the authoritative objects list and matching nameSingular/namePlural (mirrors ensureRelation's created-path read-back). Behavior-only fix; no method/argument/resource shape changes, so this is a no-op attribute migration.",
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
    "recordUpserted": {
      description:
        "Result of an upsertRecord run: the action taken, the resolved custom object/plural, the natural-key field, the hashed match value, and the create/patch payload (no raw match value, no Twenty response body)",
      schema: RecordUpsertedSchema,
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
    "peopleList": {
      description:
        "Snapshot from listPeople: a filtered, paginated, deduped page of compact person views (join keys only, no bulk PII) + continuation/completeness fields",
      schema: PeopleListSchema,
      // SR-4: bulk snapshots get a finite TTL + tight GC — they do NOT inherit
      // the refs' infinite/100.
      lifetime: "3d",
      garbageCollection: 5,
    },
    "companyList": {
      description:
        "Snapshot from listCompanies: a filtered, paginated, deduped page of compact company views (id/name/domain) + continuation/completeness fields",
      schema: CompanyListSchema,
      lifetime: "3d",
      garbageCollection: 5,
    },
    "noteList": {
      description:
        "Snapshot from listNotes: a filtered, paginated, deduped page of compact note views (no body; title only on the machine 'Inbound lead ' pattern) + continuation/completeness fields",
      schema: NoteListSchema,
      lifetime: "3d",
      garbageCollection: 5,
    },
    "noteDelete": {
      description:
        "Result of a deleteNote run: the resolved target and whether it was deleted",
      schema: NoteDeleteSchema,
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
    "fieldEnsured": {
      description:
        "Result of an ensureField run: the field, the action taken (created/present/appended/planned), and any SELECT options added/present + non-mutating drift notes",
      schema: FieldEnsuredSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "personUpsert": {
      description:
        "Result of an upsertPerson run: the action taken, which fields were set, and the company link (no raw PII)",
      schema: PersonUpsertSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "objectEnsured": {
      description:
        "Result of an ensureObject run: the custom object's identity, the action taken (created/present/planned-create), and the create payload",
      schema: ObjectEnsuredSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "relationEnsured": {
      description:
        "Result of an ensureRelation run: both objects' identities, the source/reverse field names, the relation settings/relation read-back, the action taken (created/present/planned-create/type-mismatch), and the create payload",
      schema: RelationEnsuredSchema,
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
        const objs = await fetchObjectsMeta(cfg);
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
        // Thin wrapper over the shared ensureFieldOnce core (TWENTY-ENSURE-FIELD):
        // one metadata read, then ensure each required scalar field, mapping the
        // structured outcome back onto this method's created/present/failed shape.
        // A per-field throw (absent object, create 4xx) is captured, never fatal —
        // preserving ensureLeadFields' original resilience.
        const objs = await fetchObjectsMeta(cfg);
        const created: string[] = [];
        const alreadyPresent: string[] = [];
        const failed: Array<{ field: string; error: string }> = [];
        for (const rf of REQUIRED_FIELDS) {
          const key = `${rf.object}.${rf.name}`;
          try {
            const outcome = await ensureFieldOnce(
              cfg,
              {
                objectNameSingular: rf.object,
                name: rf.name,
                label: rf.label,
                type: rf.type as EnsureFieldType,
              },
              false,
              objs,
            );
            if (outcome.action === "created") created.push(key);
            else if (outcome.typeMismatch) {
              // A required marker field exists with the WRONG type — surface it
              // (non-destructive: never mutated) instead of masking it as present.
              failed.push({ field: key, error: outcome.typeMismatch });
            } else alreadyPresent.push(key);
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
        "Idempotently ensure a SELECT option exists on an allowlisted picklist field (default opportunity.stage), so an Opportunity can be set to a stage the workspace didn't ship with (e.g. CLOSED). Reads the field's FULL option set and appends the new option, preserving every OTHER existing option (id/label/color/position) verbatim — never a drop or reorder. If the value already exists with a differing label/color it is, by default (reconcile), updated IN PLACE (id/position preserved) since swamp owns the option; pass reconcile:false for strict append-only (the drift is reported, never applied). An exact match is a no-op. Confirm-gated (mutates workspace metadata); dryRun previews the planned option array without writing. SELECT-only; MULTI_SELECT and unknown targets are rejected. Snapshots a `stageOption` resource.",
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
        reconcile: z
          .boolean()
          .default(true)
          .describe(
            "When the option already exists with a different label/color, update it in place (swamp is the source of truth). Set false for strict append-only (drift reported, never applied).",
          ),
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
          reconcile: boolean;
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

          let action:
            | "present"
            | "created"
            | "planned-create"
            | "updated"
            | "planned-update";
          let mismatchNote: string | undefined;
          let resultOptions: SelectOption[];

          if (existing) {
            const drift = existing.label !== label || existing.color !== color;
            if (drift && args.reconcile) {
              // Reconcile in place: preserve id/position, apply requested
              // label+color. swamp is the source of truth for this option.
              resultOptions = field.options.map((o) =>
                o.value === value ? { ...o, label, color } : o
              );
              if (args.dryRun) {
                action = "planned-update";
              } else {
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
                await twentyRequest(
                  cfg,
                  "PATCH",
                  `/rest/metadata/fields/${field.fieldId}`,
                  { options: resultOptions },
                );
                action = "updated";
              }
            } else {
              action = "present";
              resultOptions = field.options;
              if (drift) {
                mismatchNote =
                  `Option '${value}' already exists with label='${existing.label}' color='${existing.color}'; ` +
                  `requested label='${label}' color='${color}' — left unchanged (no mutation).`;
              }
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
        "Fetch one Opportunity by leadId OR id (exactly one). Records an `opportunityRef` snapshot carrying the reconcile-critical fields (id, leadId, name, stage, amount in whole units, currencyCode, closeDate, companyId, pointOfContactId) plus the segmentation SELECTs (lineOfBusiness, sourceChannel) and isEmergency when set — so a written custom-field value is read-back verifiable; found:false + no fields on a miss. No writes.",
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
            if (view.lineOfBusiness) snap.lineOfBusiness = view.lineOfBusiness;
            if (view.sourceChannel) snap.sourceChannel = view.sourceChannel;
            if (view.isEmergency !== undefined) {
              snap.isEmergency = view.isEmergency;
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
        "Fan-out read (repo rule 6): list Opportunities filtered by companyId and/or stage (both optional; neither => all, capped). Composes filters with AND, pages through Twenty's cursor pagination up to `limit` (hard-capped at 500), dedups by id, and records an `opportunityList` snapshot of compact views (id/leadId/name/stage/amount/currency/closeDate/companyId + segmentation lineOfBusiness/sourceChannel + isEmergency when set) + a `truncated` flag. No writes, no per-id loop.",
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
          .describe(
            `Soft results floor (1..${MAX_LIST_CAP}) rounded UP to a page boundary — may return up to PAGE_SIZE-1 more`,
          ),
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
    listPeople: {
      description:
        "Fan-out read (repo rule 6): list People, optionally filtered by companyId and/or leadId (both optional; neither => all, capped-and-continued). Emergency-restricted rows are EXCLUDED by default via a NULL-safe clause (AR-5+SR-3). Composes filters with AND, sends order_by=createdAt,id, pages Twenty's cursor pagination up to a per-call cap (500), dedups by id, and records a `peopleList` page snapshot (join keys only — NO name/email/phone/jobTitle) with continuation + completeness fields. No writes, no per-id loop.",
      arguments: z.object({
        companyId: z.string().optional().describe(
          "Filter: company UUID (Twenty's flat relation FK)",
        ),
        leadId: z.string().optional().describe(
          "Filter: immutable lead marker (TEXT custom field)",
        ),
        includeEmergency: z.boolean().default(false).describe(
          "When false (default) excludes emergency-restricted rows NULL-safely (false OR unset); true opts them in",
        ),
        startingAfter: z.string().optional().describe(
          "Continuation cursor: a prior call's nextCursor, to resume paging past the per-call cap",
        ),
        limit: z
          .number()
          .int()
          .positive()
          .max(MAX_LIST_CAP)
          .default(60)
          .describe(
            `Soft per-call floor (1..${MAX_LIST_CAP}) rounded UP to a page boundary — the call stops after the first full page at/over this many rows, so it may return up to PAGE_SIZE-1 more. A safety floor, not a snapshot ceiling: loop on hasMore/nextCursor to collect the rest`,
          ),
      }),
      execute: async (
        args: {
          companyId?: string;
          leadId?: string;
          includeEmergency: boolean;
          startingAfter?: string;
          limit: number;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const cap = Math.min(
            Math.max(1, Math.floor(args.limit)),
            MAX_LIST_CAP,
          );
          const includeEmergency = args.includeEmergency;
          const startingAfter = args.startingAfter
            ? String(args.startingAfter)
            : undefined;

          let companyId: string | undefined;
          if (args.companyId != null) {
            const cid = validateUuid(args.companyId);
            if (!cid) throw new Error("Invalid companyId");
            companyId = cid;
          }
          // BOUNDED-REJECT (V2-2): a reserved-char leadId is never sent as a
          // corrupted clause — the call short-circuits with a distinct stopReason.
          let leadId: string | undefined;
          let leadIdAttempt: string | undefined;
          let rejected = false;
          if (args.leadId != null) {
            const s = String(args.leadId).trim();
            if (s.length) {
              leadIdAttempt = s;
              if (isFilterSafe(s)) leadId = s;
              else rejected = true;
            }
          }

          const filter: {
            companyId?: string;
            leadId?: string;
            includeEmergency?: boolean;
          } = { includeEmergency };
          if (companyId) filter.companyId = companyId;
          if (leadId) filter.leadId = leadId;

          const h = await listInstanceHash({
            f: { companyId, leadId: leadId ?? leadIdAttempt, includeEmergency },
            after: startingAfter ?? null,
          });
          const instanceName = `people-${h}`;
          const retrievedAt = new Date().toISOString();

          if (rejected) {
            const handle = await context.writeResource(
              "peopleList",
              instanceName,
              {
                baseUrl: cfg.baseUrl,
                count: 0,
                truncated: false,
                hasMore: false,
                incomplete: true,
                stopReason: "unsupported-filter-value",
                filter,
                items: [],
                retrievedAt,
              },
            );
            return { dataHandles: [handle] };
          }

          const clauses: string[] = [];
          if (!includeEmergency) clauses.push(NON_EMERGENCY_CLAUSE);
          if (companyId) {
            clauses.push(`companyId[eq]:${encodeURIComponent(companyId)}`);
          }
          if (leadId) clauses.push(`leadId[eq]:${encodeURIComponent(leadId)}`);

          const page = await listFiltered(
            cfg,
            "people",
            clauses,
            cap,
            LIST_ORDER,
            startingAfter,
          );
          const items = page.items.map(mapPersonView);
          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            count: items.length,
            truncated: page.truncated,
            hasMore: page.hasMore,
            incomplete: page.incomplete,
            stopReason: page.stopReason,
            filter,
            items,
            retrievedAt,
          };
          if (page.nextCursor !== undefined) snap.nextCursor = page.nextCursor;
          if (page.totalCount !== undefined) snap.totalCount = page.totalCount;
          const handle = await context.writeResource(
            "peopleList",
            instanceName,
            snap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    listCompanies: {
      description:
        "Fan-out read (repo rule 6): list Companies, optionally filtered by domain (domainName.primaryLinkUrl) and/or name (both optional; neither => all, capped-and-continued). Composes filters with AND, sends order_by=createdAt,id, pages up to a per-call cap (500), dedups by id, and records a `companyList` page snapshot (id/name/domain) with continuation + completeness fields. No writes, no per-id loop.",
      arguments: z.object({
        domain: z.string().optional().describe(
          "Filter: corporate domain (normalized to a bare host, e.g. acme.com)",
        ),
        name: z.string().optional().describe(
          "Filter: exact company name (filter-safe; reserved chars bounded-reject)",
        ),
        startingAfter: z.string().optional().describe(
          "Continuation cursor: a prior call's nextCursor",
        ),
        limit: z
          .number()
          .int()
          .positive()
          .max(MAX_LIST_CAP)
          .default(60)
          .describe(
            `Soft per-call floor (1..${MAX_LIST_CAP}) rounded UP to a page boundary — the call stops after the first full page at/over this many rows, so it may return up to PAGE_SIZE-1 more. A safety floor, not a snapshot ceiling: loop on hasMore/nextCursor to collect the rest`,
          ),
      }),
      execute: async (
        args: {
          domain?: string;
          name?: string;
          startingAfter?: string;
          limit: number;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const cap = Math.min(
            Math.max(1, Math.floor(args.limit)),
            MAX_LIST_CAP,
          );
          const startingAfter = args.startingAfter
            ? String(args.startingAfter)
            : undefined;

          let domain: string | undefined;
          if (args.domain != null) {
            // AR-6: normalize to a bare host BEFORE validating/filtering.
            const host = normalizeDomainHost(args.domain);
            const validated = host ? validateDomain(host) : null;
            if (!validated || !isFilterSafe(validated)) {
              throw new Error("Invalid domain");
            }
            domain = validated;
          }
          // BOUNDED-REJECT (V2-2): a reserved-char name (e.g. "Acme, Inc.") is
          // never sent as a corrupted clause.
          let name: string | undefined;
          let nameAttempt: string | undefined;
          let rejected = false;
          if (args.name != null) {
            const s = String(args.name).trim();
            if (s.length) {
              nameAttempt = s;
              if (isFilterSafe(s)) name = s;
              else rejected = true;
            }
          }

          const filter: { domain?: string; name?: string } = {};
          if (domain) filter.domain = domain;
          if (name) filter.name = name;

          const h = await listInstanceHash({
            f: { domain, name: name ?? nameAttempt },
            after: startingAfter ?? null,
          });
          const instanceName = `companies-${h}`;
          const retrievedAt = new Date().toISOString();

          if (rejected) {
            const handle = await context.writeResource(
              "companyList",
              instanceName,
              {
                baseUrl: cfg.baseUrl,
                count: 0,
                truncated: false,
                hasMore: false,
                incomplete: true,
                stopReason: "unsupported-filter-value",
                filter,
                items: [],
                retrievedAt,
              },
            );
            return { dataHandles: [handle] };
          }

          const clauses: string[] = [];
          if (domain) {
            clauses.push(
              `domainName.primaryLinkUrl[eq]:${encodeURIComponent(domain)}`,
            );
          }
          if (name) clauses.push(`name[eq]:${encodeURIComponent(name)}`);

          const page = await listFiltered(
            cfg,
            "companies",
            clauses,
            cap,
            LIST_ORDER,
            startingAfter,
          );
          const items = page.items.map(mapCompanyView);
          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            count: items.length,
            truncated: page.truncated,
            hasMore: page.hasMore,
            incomplete: page.incomplete,
            stopReason: page.stopReason,
            filter,
            items,
            retrievedAt,
          };
          if (page.nextCursor !== undefined) snap.nextCursor = page.nextCursor;
          if (page.totalCount !== undefined) snap.totalCount = page.totalCount;
          const handle = await context.writeResource(
            "companyList",
            instanceName,
            snap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    listNotes: {
      description:
        "Fan-out read (repo rule 6): list Notes, optionally filtered by leadId (optional; absent => ALL notes, capped-and-continued). Sends order_by=createdAt,id, pages up to a per-call cap (500), dedups by id, and records a `noteList` page snapshot with continuation + completeness fields. Note body (bodyV2.markdown) is NEVER included; title is emitted ONLY on the machine 'Inbound lead ' pattern (SR-1). No emergency filtering: this extension does not provision isEmergency on Note (only Person/Opportunity), so there is no marker to exclude on. No writes, no per-id loop.",
      arguments: z.object({
        leadId: z.string().optional().describe(
          "Filter: immutable lead marker (TEXT custom field on Note)",
        ),
        startingAfter: z.string().optional().describe(
          "Continuation cursor: a prior call's nextCursor",
        ),
        limit: z
          .number()
          .int()
          .positive()
          .max(MAX_LIST_CAP)
          .default(60)
          .describe(
            `Soft per-call floor (1..${MAX_LIST_CAP}) rounded UP to a page boundary — the call stops after the first full page at/over this many rows, so it may return up to PAGE_SIZE-1 more. A safety floor, not a snapshot ceiling: loop on hasMore/nextCursor to collect the rest`,
          ),
      }),
      execute: async (
        args: {
          leadId?: string;
          startingAfter?: string;
          limit: number;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const cap = Math.min(
            Math.max(1, Math.floor(args.limit)),
            MAX_LIST_CAP,
          );
          const startingAfter = args.startingAfter
            ? String(args.startingAfter)
            : undefined;

          let leadId: string | undefined;
          let leadIdAttempt: string | undefined;
          let rejected = false;
          if (args.leadId != null) {
            const s = String(args.leadId).trim();
            if (s.length) {
              leadIdAttempt = s;
              if (isFilterSafe(s)) leadId = s;
              else rejected = true;
            }
          }

          const filter: { leadId?: string } = {};
          if (leadId) filter.leadId = leadId;

          const h = await listInstanceHash({
            f: { leadId: leadId ?? leadIdAttempt },
            after: startingAfter ?? null,
          });
          const instanceName = `notes-${h}`;
          const retrievedAt = new Date().toISOString();

          if (rejected) {
            const handle = await context.writeResource(
              "noteList",
              instanceName,
              {
                baseUrl: cfg.baseUrl,
                count: 0,
                truncated: false,
                hasMore: false,
                incomplete: true,
                stopReason: "unsupported-filter-value",
                filter,
                items: [],
                retrievedAt,
              },
            );
            return { dataHandles: [handle] };
          }

          const clauses: string[] = [];
          if (leadId) clauses.push(`leadId[eq]:${encodeURIComponent(leadId)}`);

          const page = await listFiltered(
            cfg,
            "notes",
            clauses,
            cap,
            LIST_ORDER,
            startingAfter,
          );
          const items = page.items.map(mapNoteView);
          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            count: items.length,
            truncated: page.truncated,
            hasMore: page.hasMore,
            incomplete: page.incomplete,
            stopReason: page.stopReason,
            filter,
            items,
            retrievedAt,
          };
          if (page.nextCursor !== undefined) snap.nextCursor = page.nextCursor;
          if (page.totalCount !== undefined) snap.totalCount = page.totalCount;
          const handle = await context.writeResource(
            "noteList",
            instanceName,
            snap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    deleteNote: {
      description:
        "Delete the Note carrying a given leadId (resolved via the leadId filter), or an explicit noteId. Confirm-gated; dryRun resolves the target and plans without deleting. Idempotent — a missing Note is reported (found:false), not an error. Primary use: regenerate a lead Note after a format change (delete, then re-run push_leads, which recreates it). Records a noteDelete resource.",
      arguments: z.object({
        leadId: z
          .string()
          .optional()
          .describe("Lead marker whose Note to delete (resolved by leadId)."),
        noteId: z
          .string()
          .optional()
          .describe("Explicit Note id to delete; skips the leadId lookup."),
        dryRun: z
          .boolean()
          .default(false)
          .describe("Resolve the target and plan without deleting."),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true for a real delete."),
      }),
      execute: async (
        args: {
          leadId?: string;
          noteId?: string;
          dryRun: boolean;
          confirm: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const explicitId = args.noteId ? String(args.noteId).trim() : "";
          const lead = args.leadId ? String(args.leadId).trim() : "";
          if (!explicitId && !lead) {
            throw new Error("deleteNote requires leadId or noteId");
          }
          const resolvedVia: "noteId" | "leadId" = explicitId
            ? "noteId"
            : "leadId";
          let noteId = explicitId;
          if (!noteId) {
            if (!isFilterSafe(lead)) {
              throw new Error("deleteNote: unsupported leadId filter value");
            }
            const existing = await findNoteByLeadId(cfg, lead);
            noteId = existing ? String(existing.id ?? "") : "";
          }
          const found = Boolean(noteId);
          let deleted = false;
          if (found && !args.dryRun) {
            if (!args.confirm) {
              throw new Error(
                "Refusing to deleteNote without confirm:true (deletes a CRM note)",
              );
            }
            await twentyRequest(
              cfg,
              "DELETE",
              `/rest/notes/${encodeURIComponent(noteId)}`,
            );
            deleted = true;
          }
          const handle = await context.writeResource(
            "noteDelete",
            noteId || `lead-${lead || "none"}`,
            {
              baseUrl: cfg.baseUrl,
              leadId: lead || null,
              noteId: noteId || null,
              resolvedVia,
              found,
              dryRun: args.dryRun,
              deleted,
              at: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    push_leads: {
      description:
        "THE fan-out lead sink (repo rule 6). Ingest a batch of contact-form leads into Twenty in one execution: select status=='new', FIFO by received_at, capped at maxBatch. Per lead, isolated in try/catch: validate + sanitize every field FIRST (bad lead => failed, no writes); reuse but NEVER structurally mutate an existing Person; create/link a Company only for business leads on a real corporate domain; create exactly one Opportunity keyed on leadId (skip if it exists); ALWAYS ensure the per-lead message Note; and set the emergency alert flag + isEmergency marker INDEPENDENTLY of the opportunity skip. dryRun=true does lookups + a plan and writes nothing. confirm=true is required for a real run. Accepts leads either pre-shaped (`leads`) or as raw `kvEntries` from a `kv_export` snapshot, which it parses + adapts in-method (shrugpw and shrug.host shapes; org→company, geo object→string, needs/reason/timing/source folded onto the Note). Returns counts + per-lead results (no raw PII beyond leadId) in a `pushRun` resource.",
      arguments: z.object({
        leads: z
          .array(LeadRecordSchema)
          .default([])
          .describe(
            "Inbound leads already shaped to the flat lead record. Provide this and/or `kvEntries`.",
          ),
        kvEntries: z
          .array(KvEntrySchema)
          .default([])
          .describe(
            "Raw kv_export entries from the @shrug/fastly-compute leads store; each entry.value is a JSON lead record parsed + adapted in-method (handles both shrugpw's and shrug.host's shapes). Point this at the kv_export snapshot so the workflow stays thin.",
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
          kvEntries?: KvEntry[];
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
        // Fail fast on a misconfigured Source Channel: if set, it must be an
        // UPPER_SNAKE option token (a provisioned opportunity.sourceChannel
        // value) — otherwise every opportunity CREATE would 4xx. Empty disables.
        if (
          cfg.leadSourceChannel &&
          !STAGE_OPTION_VALUE_RE.test(cfg.leadSourceChannel)
        ) {
          throw new Error(
            "leadSourceChannel must be UPPER_SNAKE (A-Z, 0-9, _, letter-led) matching a provisioned opportunity.sourceChannel option, or empty to disable",
          );
        }
        // Adapt raw kv_export entries (if provided) and merge with any leads
        // passed pre-shaped. Unparseable entries are counted, never dropped silently.
        const fromKv: LeadRecord[] = [];
        let kvUnparseable = 0;
        for (const entry of args.kvEntries ?? []) {
          const lead = leadFromKvEntry(entry);
          if (lead) fromKv.push(lead);
          else kvUnparseable++;
        }
        const allLeads = [...(args.leads ?? []), ...fromKv];
        const { batch, cap, remaining, eligible } = selectBatch(
          allLeads,
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
            kvParsed: fromKv.length,
            kvUnparseable,
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
        "Generalized, idempotent Opportunity upsert keyed on leadId — the create/update path with the full field set (name, amount, stage, closeDate, company, point of contact, and the lineOfBusiness/sourceChannel segmentation SELECTs) that push_leads' bare createOpportunity omits. Finds any existing Opportunity by leadId: hit => PATCH the provided fields; miss => create. Optionally finds-or-creates and links a Company (by domain, else by exact name) and a point-of-contact Person (by email), and attaches a markdown Note. amount is given in whole currency units (50000 => $50,000) and stored as Twenty currency micros. confirm:true required for a real run; dryRun:true resolves + plans and writes nothing. Snapshots an `opportunityUpsert` resource.",
      arguments: z.object({
        leadId: z
          .string()
          .describe(
            "Stable idempotency key for this opportunity (upsert marker, e.g. 'acme-q1-renewal-2026')",
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
        lineOfBusiness: z
          .string()
          .optional()
          .describe(
            "Line of Business segmentation SELECT option token (UPPER_SNAKE: CONSULTING, HOSTING, GAMES). Validated against the live opportunity.lineOfBusiness enum exactly like stage. Omitted => left unchanged on both create and update (never nulled). Requires the field to be provisioned (ensureOpportunitySegmentation).",
          ),
        sourceChannel: z
          .string()
          .optional()
          .describe(
            "Source Channel segmentation SELECT option token (UPPER_SNAKE: DIRECT, REFERRAL, CONSULTING_HANDOFF). Validated against the live opportunity.sourceChannel enum exactly like stage. Omitted => left unchanged on both create and update (never nulled). Requires the field to be provisioned (ensureOpportunitySegmentation).",
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
          lineOfBusiness?: string;
          sourceChannel?: string;
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
        // Live Opportunity metadata: used to validate stage and the two
        // segmentation SELECTs against their enums and to learn the closeDate
        // field type. Best-effort — if metadata is unreadable, skip validation
        // rather than block a write.
        let oppMeta: {
          stages: string[];
          closeDateType: string | null;
          lineOfBusiness: string[];
          sourceChannel: string[];
        } = {
          stages: [],
          closeDateType: null,
          lineOfBusiness: [],
          sourceChannel: [],
        };
        try {
          oppMeta = await fetchOpportunityMeta(cfg);
        } catch (_e) {
          context.logger.warning(
            "Opportunity metadata unreadable; skipping stage/segmentation validation",
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

          // Segmentation SELECT fields (analytics): write only what the caller
          // set — an unset token is omitted from the body on BOTH create and
          // update, so a re-run never clears a value (never nulled). An empty
          // string (e.g. an unresolved CEL fallback) is coerced to unset so it
          // means "leave unchanged" rather than nulling the field or aborting
          // the whole upsert on the enum check. Validated against the live enum
          // exactly like stage; an invalid token fails fast here rather than as
          // a blind Twenty 4xx. Skipped (best-effort) when the field's options
          // are unreadable, matching stage's posture.
          const lineOfBusiness = args.lineOfBusiness || undefined;
          if (
            lineOfBusiness !== undefined && oppMeta.lineOfBusiness.length &&
            !oppMeta.lineOfBusiness.includes(lineOfBusiness)
          ) {
            throw new Error(
              `Invalid lineOfBusiness '${lineOfBusiness}'. Valid options: ${
                oppMeta.lineOfBusiness.join(", ")
              }`,
            );
          }
          const sourceChannel = args.sourceChannel || undefined;
          if (
            sourceChannel !== undefined && oppMeta.sourceChannel.length &&
            !oppMeta.sourceChannel.includes(sourceChannel)
          ) {
            throw new Error(
              `Invalid sourceChannel '${sourceChannel}'. Valid options: ${
                oppMeta.sourceChannel.join(", ")
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
            ...(lineOfBusiness !== undefined ? { lineOfBusiness } : {}),
            ...(sourceChannel !== undefined ? { sourceChannel } : {}),
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
              ...(lineOfBusiness !== undefined ? { lineOfBusiness } : {}),
              ...(sourceChannel !== undefined ? { sourceChannel } : {}),
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
    upsertRecord: {
      description:
        "Generic, idempotent create-or-update for a single record of an eligible CUSTOM object, keyed on a caller-chosen natural-key field. Object-agnostic sibling of upsertOpportunity, fail-closed throughout: objectNameSingular MUST be in a strict in-code allowlist (v1: subscription, channelPartner) — any other object errors before any I/O; matchField must be a camelCase, non-reserved, scalar field that exists on the object; every `fields` key must exist and be a scalar TYPE (TEXT/NUMBER/BOOLEAN/DATE_TIME/SELECT/UUID) — unknown keys and composite types (CURRENCY/RELATION/…) are rejected pre-write, and SELECT values are validated against the live enum. Finds by natural key (limit=2 → 0 create, 1 update, ≥2 refuse-ambiguous), with a create→conflict→update race fallback. PATCH sends only the caller's fields (matchField excluded → natural key preserved); matchField is stripped from `fields` entirely so it can never rewrite the key. String values are sanitized; the same canonical match value is used for BOTH the find filter and the stored create body. Idempotency is best-effort (Twenty has no unique constraint) — de-dupe a pre-existing ≥2 manually, then re-run; single-operator serialized use. confirm:true required for a real run; dryRun:true resolves + plans (planned-create/planned-update) and writes nothing. Snapshots a `recordUpserted` resource (match value stored hashed, never raw).",
      arguments: z.object({
        objectNameSingular: z
          .string()
          .describe(
            "Custom object to upsert (nameSingular). MUST be in the v1 allowlist: subscription, channelPartner.",
          ),
        matchField: z
          .string()
          .describe(
            "camelCase natural-key field to match on (must exist on the object and be a scalar type; not a reserved field)",
          ),
        matchValue: z
          .string()
          .describe(
            "Natural-key value. Canonicalized once (sanitized + filter-safety checked) and used identically for the find filter and the stored value.",
          ),
        fields: z
          .record(
            z.string(),
            z.union([z.string(), z.number(), z.boolean(), z.null()]),
          )
          .describe(
            "Scalar fields to write (create + update). Keys must exist on the object and be scalar; string values are sanitized; explicit null clears. matchField is stripped if present.",
          ),
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
          objectNameSingular: string;
          matchField: string;
          matchValue: string;
          fields: Record<string, string | number | boolean | null>;
          confirm: boolean;
          dryRun: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        // (Safety gate) evaluated FIRST — nothing resolved, no I/O.
        if (!args.dryRun && !args.confirm) {
          throw new Error(
            "Refusing to write without confirm:true (use dryRun:true to plan)",
          );
        }
        // Render a caller-supplied identifier safely inside a pre-I/O validation
        // error: strip control chars (ANSI escapes, newlines) and hard-cap the
        // length so a hostile objectNameSingular / matchField / fields key can't
        // inject terminal escapes or an unbounded blob into the durable
        // method-summary report. (The redactError/scrubSubmitted try/catch below
        // only wraps errors thrown AFTER this block.)
        const safeLabel = (s: unknown): string => sanitizeText(s, 80);
        // (Allowlist) reject any non-allowlisted object BEFORE any I/O. This is
        // the real control; there is no isCustom flag to lean on (see
        // fetchUpsertObjectMeta).
        const objectNameSingular = String(args.objectNameSingular ?? "").trim();
        if (!UPSERT_OBJECT_ALLOWLIST.has(objectNameSingular)) {
          throw new Error(
            `Object '${
              safeLabel(objectNameSingular)
            }' is not upsertable (allowed: ${
              [...UPSERT_OBJECT_ALLOWLIST].join(", ")
            })`,
          );
        }
        // (matchField) camelCase + not reserved, BEFORE any I/O.
        const matchField = String(args.matchField ?? "").trim();
        if (!FIELD_NAME_RE.test(matchField)) {
          throw new Error(
            `Invalid matchField '${
              safeLabel(matchField)
            }': must be a camelCase identifier (letter-led, alphanumeric)`,
          );
        }
        if (UPSERT_RESERVED_FIELDS.has(matchField)) {
          throw new Error(
            `matchField '${
              safeLabel(matchField)
            }' is reserved and cannot be a natural key`,
          );
        }
        // (matchValue) canonicalize ONCE. The IDENTICAL bytes are used for both
        // the GET filter and the stored create-body value, so a re-run finds
        // exactly what it wrote (no asymmetry dupes).
        const canonicalMatchValue = sanitizeText(
          args.matchValue,
          UPSERT_MATCH_VALUE_CAP,
        );
        if (!isFilterSafe(canonicalMatchValue)) {
          throw new Error(
            "matchValue is empty or contains filter-unsafe characters after sanitization",
          );
        }
        // (fields) strip matchField ENTIRELY (never let it rewrite the natural
        // key) + reject reserved/malformed keys, BEFORE any I/O. Existence,
        // scalar-type, and SELECT-option checks need metadata and run below.
        const rawFields = (args.fields ?? {}) as Record<
          string,
          string | number | boolean | null
        >;
        const cleaned: Record<string, string | number | boolean | null> = {};
        for (const [k, v] of Object.entries(rawFields)) {
          const key = String(k).trim();
          if (key === matchField) continue; // strip the natural key from fields
          if (!FIELD_NAME_RE.test(key)) {
            throw new Error(
              `Invalid field name '${
                safeLabel(key)
              }': must be a camelCase identifier (letter-led, alphanumeric)`,
            );
          }
          if (UPSERT_RESERVED_FIELDS.has(key)) {
            throw new Error(
              `Field '${safeLabel(key)}' is reserved and cannot be set`,
            );
          }
          cleaned[key] = v;
        }

        // Extend redactError's scrub to the caller's OWN submitted values (the
        // canonical match value + sanitized string field values), so a Twenty
        // 4xx that echoes a submitted value can never leak it into a thrown
        // error or durable data. We never persist a raw Twenty response body.
        const submittedStrings: string[] = [canonicalMatchValue];
        const scrubSubmitted = (msg: string): string => {
          let s = msg;
          for (const v of submittedStrings) {
            if (typeof v === "string" && v.length >= 3) {
              s = s.split(v).join("[redacted-value]");
            }
          }
          return s;
        };
        // Envelope-independent id extraction from a mutation response
        // (`{data:{create<Object>:{...}}}`): take the first record under `data`
        // rather than guess the op key (mirrors the ensureObject fix).
        const firstRecord = (json: unknown): Record<string, unknown> => {
          const d = (json as { data?: Record<string, unknown> })?.data ?? {};
          const v = Object.values(d)[0];
          return (v && typeof v === "object" ? v : {}) as Record<
            string,
            unknown
          >;
        };

        try {
          // (1) metadata: resolve plural + field type/option map. Object
          // presence is re-asserted here (belt-and-suspenders over the
          // allowlist). isCustom assert intentionally dropped.
          const meta = await fetchUpsertObjectMeta(cfg, objectNameSingular);
          const plural = meta.plural;

          // (matchField) must exist on the object AND be scalar.
          const mfMeta = meta.fields.get(matchField);
          if (!mfMeta) {
            throw new Error(
              `matchField '${matchField}' does not exist on object '${objectNameSingular}'`,
            );
          }
          if (!UPSERT_SCALAR_TYPES.has(mfMeta.type)) {
            throw new Error(
              `matchField '${matchField}' has non-scalar type '${mfMeta.type}' (allowed: ${
                [...UPSERT_SCALAR_TYPES].join(", ")
              })`,
            );
          }
          // (matchField VALUE) validate the natural-key value against the field
          // itself — the same enum path used for `fields` SELECT values — so a
          // SELECT/NUMBER key can't send a blind out-of-enum / non-numeric value
          // and eat an opaque Twenty 400. (canonicalMatchValue is a submitted
          // string, so it is scrubbed from any error by scrubSubmitted below;
          // the message deliberately omits the raw value.)
          if (mfMeta.type === "SELECT") {
            if (
              mfMeta.options.length &&
              !mfMeta.options.includes(canonicalMatchValue)
            ) {
              throw new Error(
                `Invalid value for SELECT matchField '${matchField}'. Valid options: ${
                  mfMeta.options.join(", ")
                }`,
              );
            }
          } else if (mfMeta.type === "NUMBER") {
            // matchValue always arrives as a string and is filtered/stored in
            // that canonical string form (stored == searched). A NUMBER natural
            // key must therefore parse as a finite number; reject pre-write
            // rather than send Twenty a value it will reject.
            if (!Number.isFinite(Number(canonicalMatchValue))) {
              throw new Error(
                `matchField '${matchField}' is NUMBER but matchValue is not a finite number`,
              );
            }
          }

          // (fields) existence (fail-closed) + scalar type + SELECT option
          // validation + string sanitization → the field set actually written.
          const writtenFields: Record<
            string,
            string | number | boolean | null
          > = {};
          for (const [key, val] of Object.entries(cleaned)) {
            const fMeta = meta.fields.get(key);
            if (!fMeta) {
              throw new Error(
                `Unknown field '${key}' on object '${objectNameSingular}' (fail-closed; refusing to write an unrecognized field)`,
              );
            }
            if (!UPSERT_SCALAR_TYPES.has(fMeta.type)) {
              throw new Error(
                `Field '${key}' has non-scalar type '${fMeta.type}' (allowed: ${
                  [...UPSERT_SCALAR_TYPES].join(", ")
                }); composite fields are not supported (v2)`,
              );
            }
            let out: string | number | boolean | null = val;
            if (typeof val === "string") {
              out = sanitizeText(val, UPSERT_FIELD_TEXT_CAP);
              submittedStrings.push(out);
            }
            if (fMeta.type === "SELECT" && out !== null) {
              const token = String(out);
              if (fMeta.options.length && !fMeta.options.includes(token)) {
                throw new Error(
                  `Invalid value '${token}' for SELECT field '${key}'. Valid options: ${
                    fMeta.options.join(", ")
                  }`,
                );
              }
            }
            writtenFields[key] = out;
          }

          // One hash of {object, matchField, canonical value} feeds BOTH the
          // snapshot instance name and the non-raw matchValueHash attribute
          // (single object arg — resolution #3). Computed here so the persisted
          // create payload can reference it instead of the raw value.
          const matchValueHash = await listInstanceHash({
            object: objectNameSingular,
            matchField,
            matchValue: canonicalMatchValue,
          });

          // The full create body actually sent to Twenty: matchField carries the
          // IDENTICAL canonical bytes used in the find filter.
          const creationPayload: Record<string, unknown> = {
            ...writtenFields,
            [matchField]: canonicalMatchValue,
          };
          // The form PERSISTED in the durable (lifetime:infinite) snapshot: the
          // raw natural-key value is replaced with its hash so the recorded
          // attributes honor the method's "matchValue stored hashed, never raw"
          // guarantee. (The other scalar VALUES in writtenFields are recorded
          // as-is — in-scope by spec; a caller putting PII in a non-identity
          // scalar field is out of this method's contract to protect.)
          const persistedCreationPayload: Record<string, unknown> = {
            ...writtenFields,
            [matchField]: `[hashed:${matchValueHash}]`,
          };

          // (2) find by natural key; limit=2 detects ambiguity.
          const findPath = `${
            buildFilterPath(`/rest/${plural}`, matchField, canonicalMatchValue)
          }&limit=2`;
          const existingList = unwrapList(
            await twentyRequest(cfg, "GET", findPath),
            plural,
          );
          if (existingList.length >= 2) {
            throw new Error(
              `Ambiguous natural key on '${objectNameSingular}.${matchField}': ${existingList.length} matching ${plural} — refusing to guess (de-dupe manually, then re-run)`,
            );
          }
          const existing = existingList[0] ?? null;
          let recordId = existing ? String(existing.id ?? "") : "";
          let action:
            | "created"
            | "updated"
            | "planned-create"
            | "planned-update";

          if (args.dryRun) {
            action = existing ? "planned-update" : "planned-create";
          } else if (existing) {
            // PATCH sends ONLY the caller's fields; matchField is EXCLUDED, so
            // the natural key is preserved and a re-run is a value-identical
            // no-op PATCH. An explicit null clears a field.
            await twentyRequest(
              cfg,
              "PATCH",
              `/rest/${plural}/${recordId}`,
              writtenFields,
            );
            action = "updated";
          } else {
            // create, with a check-then-act race fallback (Twenty has no unique
            // constraint on the natural key).
            let created = false;
            try {
              const rec = firstRecord(
                await twentyRequest(
                  cfg,
                  "POST",
                  `/rest/${plural}`,
                  creationPayload,
                ),
              );
              recordId = String(rec.id ?? "");
              action = "created";
              created = true;
            } catch (e) {
              // A concurrent run may have created it between our find and POST.
              const raced = unwrapList(
                await twentyRequest(cfg, "GET", findPath),
                plural,
              );
              if (raced.length === 1) {
                recordId = String(raced[0].id ?? "");
                await twentyRequest(
                  cfg,
                  "PATCH",
                  `/rest/${plural}/${recordId}`,
                  writtenFields,
                );
                action = "updated";
              } else if (raced.length === 0) {
                throw new Error(
                  `Create failed and the record is still not found by its natural key — unconfirmable: ${
                    scrubSubmitted(redactError(e, 300, cfg.apiToken))
                  }`,
                );
              } else {
                throw new Error(
                  `Create failed and the natural key is now ambiguous (${raced.length} matches) — refusing to guess`,
                );
              }
            }
            // The create response envelope carried no id (Twenty version drift):
            // resolve it authoritatively by re-reading the natural key. Done
            // OUTSIDE the race catch so an ambiguous (>=2) result is a hard
            // error — consistent with the primary find and the race catch —
            // rather than being swallowed or reported 'created' with no id.
            if (created && !recordId) {
              const after = unwrapList(
                await twentyRequest(cfg, "GET", findPath),
                plural,
              );
              if (after.length >= 2) {
                throw new Error(
                  `Create succeeded but the natural key now matches ${after.length} ${plural} — refusing to guess the created record's id (de-dupe manually)`,
                );
              }
              if (after.length === 1) recordId = String(after[0].id ?? "");
            }
          }

          context.logger.info(
            "upsertRecord {object}.{field}: {action} (id {id}){dry}",
            {
              object: objectNameSingular,
              field: matchField,
              action,
              id: recordId || "-",
              dry: args.dryRun ? " [dryRun]" : "",
            },
          );

          const handle = await context.writeResource(
            "recordUpserted",
            `record-${objectNameSingular}-${matchValueHash}`,
            {
              baseUrl: cfg.baseUrl,
              action,
              dryRun: args.dryRun,
              objectNameSingular,
              plural,
              matchField,
              matchValueHash,
              ...(recordId ? { recordId } : {}),
              writtenFields,
              creationPayload: persistedCreationPayload,
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(scrubSubmitted(redactError(e, 300, cfg.apiToken)));
        }
      },
    },
    upsertPerson: {
      description:
        "Idempotent, confirm-gated curated-contact writer keyed on primaryEmail. Find-or-create a Person and set name/phone/jobTitle/city and an optional company link: hit => PATCH only the provided fields (a re-run never clobbers an unset field, and a partial name never nulls the other subfield); miss => create. Unlike push_leads/createPerson this NEVER stamps a leadId (curated contacts stay out of the lead namespace). Company is deduped by domain then exact name and created only when a domain is supplied. amount of PII in the snapshot: none (id + which fields were set only). confirm:true required for a real run; dryRun:true resolves + plans and writes nothing. Snapshots a `personUpsert` resource.",
      arguments: z.object({
        email: z
          .string()
          .describe("Primary email — the find-or-create idempotency key"),
        firstName: z.string().optional().describe("First name"),
        lastName: z.string().optional().describe("Last name"),
        name: z
          .string()
          .optional()
          .describe(
            "Full name; split into first/last when firstName/lastName are omitted",
          ),
        phone: z.string().optional().describe(
          "Phone (normalized toward E.164)",
        ),
        jobTitle: z.string().optional().describe("Job title"),
        city: z.string().optional().describe("City"),
        companyDomain: z
          .string()
          .default("")
          .describe("Company domain — dedup/link (create only with a domain)"),
        companyName: z
          .string()
          .default("")
          .describe("Company name — dedup by exact name (best-effort)"),
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
          email: string;
          firstName?: string;
          lastName?: string;
          name?: string;
          phone?: string;
          jobTitle?: string;
          city?: string;
          companyDomain: string;
          companyName: string;
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
        const email = validateEmail(args.email);
        if (!email) throw new Error("Invalid email");

        // PU-5: the ENTIRE flow is wrapped so an ambiguous-email throw or any 4xx
        // that echoes a submitted value is redacted before it reaches logs.
        try {
          // Resolve the provided name parts. A single `name` splits into
          // first/last; explicit firstName/lastName win. `nameProvided` gates
          // whether an update touches the name at all (PU-2).
          let providedFirst: string | undefined;
          let providedLast: string | undefined;
          if (args.name != null && String(args.name).trim()) {
            const sp = splitName(args.name);
            providedFirst = sp.firstName;
            providedLast = sp.lastName;
          } else {
            if (args.firstName != null) {
              providedFirst = sanitizeText(args.firstName, 120);
            }
            if (args.lastName != null) {
              providedLast = sanitizeText(args.lastName, 120);
            }
          }
          const nameProvided = providedFirst !== undefined ||
            providedLast !== undefined;

          // Non-name fields, included only when actually provided + non-empty.
          const phone = args.phone != null ? normalizePhone(args.phone) : "";
          const jobTitle = args.jobTitle != null
            ? sanitizeText(args.jobTitle, 120)
            : undefined;
          const city = args.city != null
            ? sanitizeText(args.city, 120)
            : undefined;

          // Company (optional): dedup by domain, else exact filter-safe name.
          // Create ONLY when a domain is supplied; a name-only miss is left
          // unlinked (recorded), mirroring upsertOpportunity to avoid duplicates.
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

          // PU-2: build the name field. On create, use the provided parts (empty
          // where unset). On update, MERGE with the existing record so a partial
          // {firstName|lastName} never nulls the other subfield; omit name
          // entirely when the caller provided none.
          const nameFieldFor = (
            existing: Record<string, unknown> | null,
          ): { firstName: string; lastName: string } | undefined => {
            if (!existing) {
              return {
                firstName: providedFirst ?? "",
                lastName: providedLast ?? "",
              };
            }
            if (!nameProvided) return undefined;
            const en =
              (existing.name as { firstName?: unknown; lastName?: unknown }) ??
                {};
            // Merge, treating an EMPTY provided part as "not provided" so a
            // single-token `name` (splitName -> firstName:"") never nulls an
            // existing subfield (PU-2). Use `||`, not `??`, since the empty
            // string is exactly the case we must fall back to existing on.
            return {
              firstName: providedFirst || String(en.firstName ?? ""),
              lastName: providedLast || String(en.lastName ?? ""),
            };
          };

          const commonFields: PersonWriteFields = {
            ...(phone ? { phone } : {}),
            ...(jobTitle ? { jobTitle } : {}),
            ...(city ? { city } : {}),
            ...(companyId ? { companyId } : {}),
          };

          // Idempotency lookup — decides create vs update.
          const existingPerson = await findOnePersonByEmail(cfg, email);

          let personId = existingPerson ? String(existingPerson.id ?? "") : "";
          let action:
            | "created"
            | "updated"
            | "planned-create"
            | "planned-update";
          let writeFields: PersonWriteFields;
          // Track whether a bad phone was dropped on retry, so `fieldsSet` in the
          // snapshot reports what was actually written, not what was requested.
          let phoneDropped = false;

          if (existingPerson) {
            const nameField = nameFieldFor(existingPerson);
            writeFields = {
              ...commonFields,
              ...(nameField ? { name: nameField } : {}),
            };
            action = args.dryRun ? "planned-update" : "updated";
            if (!args.dryRun) {
              const res = await updatePerson(cfg, personId, writeFields);
              phoneDropped = res.phoneDropped;
            }
          } else {
            const nameField = nameFieldFor(null);
            writeFields = {
              ...commonFields,
              ...(nameField ? { name: nameField } : {}),
            };
            if (args.dryRun) {
              action = "planned-create";
            } else {
              try {
                const created = await createPersonCurated(
                  cfg,
                  email,
                  writeFields,
                );
                personId = String(created.record.id ?? "");
                phoneDropped = created.phoneDropped;
                action = "created";
              } catch (e) {
                // PU-1: a concurrent run may have created this email between our
                // lookup and POST — converge on it instead of duplicating.
                const raced = await findOnePersonByEmail(cfg, email);
                if (raced) {
                  personId = String(raced.id ?? "");
                  const mergedName = nameFieldFor(raced);
                  writeFields = {
                    ...commonFields,
                    ...(mergedName ? { name: mergedName } : {}),
                  };
                  const res = await updatePerson(cfg, personId, writeFields);
                  phoneDropped = res.phoneDropped;
                  action = "updated";
                } else {
                  throw e;
                }
              }
            }
          }
          // What was actually written: drop `phone` if the retry stripped it.
          const setFields = personFieldsSet(writeFields).filter(
            (k) => !(phoneDropped && k === "phone"),
          );

          context.logger.info(
            "upsertPerson: {action} (person {person}){dry}",
            {
              action,
              person: personId || "-",
              dry: args.dryRun ? " [dryRun]" : "",
            },
          );

          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            action,
            dryRun: args.dryRun,
            ...(personId ? { personId } : {}),
            fieldsSet: setFields,
            ...(companyId ? { companyId } : {}),
            companyLinked: Boolean(companyId),
            ...(companyNote ? { companyNote } : {}),
            retrievedAt: new Date().toISOString(),
          };
          const handle = await context.writeResource(
            "personUpsert",
            personId ? `person-upsert-${personId}` : "person-upsert-planned",
            snap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e));
        }
      },
    },
    ensureField: {
      description:
        "Idempotently provision ONE custom field on an object via POST /rest/metadata/fields — the generalized foundation ensureLeadFields is now a thin wrapper over. Supports TEXT / BOOLEAN / NUMBER / DATE_TIME / SELECT. Non-destructive to structure: an absent field is created; a present scalar field is a no-op (a differing type is reported, never mutated); a present SELECT gets NEW options APPENDED and, by default (reconcile), existing options whose label/color drifted RECONCILED in place (id/position preserved) — options are never dropped or reordered, reusing ensureStageOption's optimistic-concurrency discipline. Pass reconcile:false for strict append-only (drift reported, never applied). SELECT requires an options array; option values are UPPER_SNAKE, colors palette-validated, labels defaulted to the title-cased token. confirm:true is required for a real run; dryRun:true validates + plans (planned-create / planned-append / planned-reconcile) and writes nothing. Snapshots a `fieldEnsured` resource.",
      arguments: z.object({
        objectNameSingular: z
          .string()
          .describe("Object owning the field, e.g. opportunity / person"),
        name: z
          .string()
          .describe("Field name — a camelCase identifier, e.g. lineOfBusiness"),
        label: z
          .string()
          .optional()
          .describe("Display label; defaults to a title-cased name"),
        type: z
          .enum(["TEXT", "BOOLEAN", "NUMBER", "DATE_TIME", "SELECT"])
          .describe("Field type"),
        options: z
          .array(
            z.object({
              value: z
                .string()
                .describe("UPPER_SNAKE option token, e.g. HOSTING"),
              label: z.string().optional().describe("Display label"),
              color: z
                .string()
                .optional()
                .describe("Twenty palette color; defaults gray"),
            }),
          )
          .default([])
          .describe(
            "SELECT options (required for SELECT; ignored otherwise). Append-only: existing options are preserved.",
          ),
        description: z
          .string()
          .optional()
          .describe("Optional field description"),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to apply — mutates workspace metadata"),
        dryRun: z
          .boolean()
          .default(false)
          .describe("Preview the plan; write nothing"),
        reconcile: z
          .boolean()
          .default(true)
          .describe(
            "For a present SELECT, when an existing option's label/color differs from requested, update it in place (swamp is the source of truth). Set false for strict append-only (drift reported, never applied).",
          ),
      }),
      execute: async (
        args: {
          objectNameSingular: string;
          name: string;
          label?: string;
          type: EnsureFieldType;
          options: RequestedOption[];
          description?: string;
          confirm: boolean;
          dryRun: boolean;
          reconcile: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          if (!args.confirm && !args.dryRun) {
            throw new Error(
              "Refusing to ensure a field without confirm:true (mutates workspace metadata). Use dryRun:true to preview.",
            );
          }
          const planOnly = args.dryRun || !args.confirm;
          const spec: FieldSpec = {
            objectNameSingular: args.objectNameSingular,
            name: args.name,
            label: args.label ?? "",
            type: args.type,
            options: args.type === "SELECT" ? args.options : undefined,
            description: args.description,
          };
          const outcome = await ensureFieldOnce(
            cfg,
            spec,
            planOnly,
            undefined,
            args.reconcile,
          );
          context.logger.info(
            "ensureField {object}.{name} ({type}): {action}",
            {
              object: outcome.object,
              name: outcome.name,
              type: outcome.type,
              action: outcome.action,
            },
          );
          const handle = await context.writeResource(
            "fieldEnsured",
            `field-${outcome.object}-${outcome.name}`,
            {
              baseUrl: cfg.baseUrl,
              object: outcome.object,
              name: outcome.name,
              type: outcome.type,
              action: outcome.action,
              dryRun: planOnly,
              optionsAdded: outcome.optionsAdded,
              optionsUpdated: outcome.optionsUpdated,
              optionsPresent: outcome.optionsPresent,
              mismatchNotes: outcome.mismatchNotes,
              ...(outcome.options ? { options: outcome.options } : {}),
              ...(outcome.typeMismatch
                ? { typeMismatch: outcome.typeMismatch }
                : {}),
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e));
        }
      },
    },
    ensureOpportunitySegmentation: {
      description:
        "Fan-out (repo rule 6): idempotently provision the two Opportunity segmentation SELECT fields — Line of Business (Consulting / Hosting / Games) and Source Channel (Direct / Referral / Consulting hand-off) — through the shared append-only ensureField path in ONE execution (single GET, one lock). Analytics only, not a pipeline gate. Re-run is a clean no-op when the live options already match the spec; a field that exists with extra options keeps them, and by default (reconcile) an option whose label/color drifted from the spec is corrected in place (pass reconcile:false for strict append-only). confirm:true for a real run; dryRun:true previews. Snapshots one `fieldEnsured` resource per field.",
      arguments: z.object({
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to apply — mutates workspace metadata"),
        dryRun: z
          .boolean()
          .default(false)
          .describe("Preview the plan for both fields; write nothing"),
        reconcile: z
          .boolean()
          .default(true)
          .describe(
            "When an existing option's label/color differs from the spec, update it in place (the spec is the source of truth). Set false for strict append-only (drift reported, never applied).",
          ),
      }),
      execute: async (
        args: { confirm: boolean; dryRun: boolean; reconcile: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          if (!args.confirm && !args.dryRun) {
            throw new Error(
              "Refusing to provision segmentation fields without confirm:true (mutates workspace metadata). Use dryRun:true to preview.",
            );
          }
          const planOnly = args.dryRun || !args.confirm;
          // One metadata read shared across both fields (presence detection); the
          // SELECT-append path still re-reads fresh per field for its drift check.
          const objs = await fetchObjectsMeta(cfg);
          const handles: Array<{ name: string }> = [];
          for (const spec of OPPORTUNITY_SEGMENTATION_FIELDS) {
            const outcome = await ensureFieldOnce(
              cfg,
              spec,
              planOnly,
              objs,
              args.reconcile,
            );
            context.logger.info(
              "ensureOpportunitySegmentation {object}.{name}: {action}",
              {
                object: outcome.object,
                name: outcome.name,
                action: outcome.action,
              },
            );
            const handle = await context.writeResource(
              "fieldEnsured",
              `field-${outcome.object}-${outcome.name}`,
              {
                baseUrl: cfg.baseUrl,
                object: outcome.object,
                name: outcome.name,
                type: outcome.type,
                action: outcome.action,
                dryRun: planOnly,
                optionsAdded: outcome.optionsAdded,
                optionsUpdated: outcome.optionsUpdated,
                optionsPresent: outcome.optionsPresent,
                mismatchNotes: outcome.mismatchNotes,
                ...(outcome.options ? { options: outcome.options } : {}),
                ...(outcome.typeMismatch
                  ? { typeMismatch: outcome.typeMismatch }
                  : {}),
                retrievedAt: new Date().toISOString(),
              },
            );
            handles.push(handle);
          }
          return { dataHandles: handles };
        } catch (e) {
          throw new Error(redactError(e));
        }
      },
    },
    ensureObject: {
      description:
        "Idempotently provision ONE custom OBJECT (object metadata type) via POST /rest/metadata/objects — the schema-provisioning foundation relation/field work builds on. Non-destructive: an object whose nameSingular/namePlural already exists is a no-op (reported as `present`, never mutated); a missing object is created. nameSingular/namePlural are camelCase identifiers and must differ; labels default to the title-cased names. dryRun:true (the DEFAULT) validates + plans (planned-create) and writes nothing, returning the exact create payload it WOULD POST; a real create requires confirm:true AND dryRun:false. Snapshots an `objectEnsured` resource.",
      arguments: z.object({
        nameSingular: z
          .string()
          .describe(
            "Singular object name — a camelCase identifier, e.g. invoice / projectTask",
          ),
        namePlural: z
          .string()
          .describe(
            "Plural object name — a camelCase identifier, e.g. invoices / projectTasks (must differ from nameSingular)",
          ),
        labelSingular: z
          .string()
          .optional()
          .describe("Singular display label; defaults to a title-cased name"),
        labelPlural: z
          .string()
          .optional()
          .describe("Plural display label; defaults to a title-cased name"),
        description: z
          .string()
          .optional()
          .describe("Optional object description"),
        icon: z
          .string()
          .optional()
          .describe("Optional Twenty icon name, e.g. IconFileInvoice"),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to apply — mutates workspace metadata"),
        dryRun: z
          .boolean()
          .default(true)
          .describe(
            "Preview the plan; write nothing. Defaults true — a real create requires confirm:true AND dryRun:false.",
          ),
      }),
      execute: async (
        args: {
          nameSingular: string;
          namePlural: string;
          labelSingular?: string;
          labelPlural?: string;
          description?: string;
          icon?: string;
          confirm: boolean;
          dryRun: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          if (!args.confirm && !args.dryRun) {
            throw new Error(
              "Refusing to ensure an object without confirm:true (mutates workspace metadata). Use dryRun:true to preview.",
            );
          }
          const planOnly = args.dryRun || !args.confirm;

          // Validate the names as camelCase identifiers before any I/O — a typo or
          // CEL slip can never POST a garbage object name (mirrors ensureField).
          const nameSingular = String(args.nameSingular ?? "").trim();
          const namePlural = String(args.namePlural ?? "").trim();
          if (!FIELD_NAME_RE.test(nameSingular)) {
            throw new Error(
              `Invalid nameSingular '${nameSingular}': must be a camelCase identifier (letter-led, alphanumeric)`,
            );
          }
          if (!FIELD_NAME_RE.test(namePlural)) {
            throw new Error(
              `Invalid namePlural '${namePlural}': must be a camelCase identifier (letter-led, alphanumeric)`,
            );
          }
          if (nameSingular === namePlural) {
            throw new Error(
              `nameSingular and namePlural must differ (both '${nameSingular}')`,
            );
          }
          const labelSingular =
            args.labelSingular != null && String(args.labelSingular).trim()
              ? sanitizeText(args.labelSingular, 120)
              : titleCaseToken(nameSingular);
          const labelPlural =
            args.labelPlural != null && String(args.labelPlural).trim()
              ? sanitizeText(args.labelPlural, 120)
              : titleCaseToken(namePlural);
          const icon = args.icon != null && String(args.icon).trim()
            ? String(args.icon).trim()
            : undefined;

          // Read live objects; treat a match on EITHER name as already-present.
          const objs = await fetchObjectsMeta(cfg);
          const existing = objs.find(
            (o) =>
              String(o.nameSingular ?? "") === nameSingular ||
              String(o.namePlural ?? "") === namePlural,
          );

          const snapshot: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            nameSingular,
            namePlural,
            labelSingular,
            labelPlural,
            dryRun: planOnly,
            ...(args.description
              ? { description: sanitizeText(args.description, 500) }
              : {}),
            ...(icon ? { icon } : {}),
            retrievedAt: new Date().toISOString(),
          };

          if (existing) {
            // Already present — no-op create, never mutate the live object.
            const objectId = String(existing.id ?? "");
            snapshot.action = "present";
            if (objectId) snapshot.objectId = objectId;
            context.logger.info(
              "ensureObject {nameSingular}: present (no-op)",
              { nameSingular },
            );
            const handle = await context.writeResource(
              "objectEnsured",
              `object-${nameSingular}`,
              snapshot,
            );
            return { dataHandles: [handle] };
          }

          // CREATE path — build the metadata create body.
          const payload: Record<string, unknown> = {
            nameSingular,
            namePlural,
            labelSingular,
            labelPlural,
            ...(snapshot.description
              ? { description: snapshot.description }
              : {}),
            ...(icon ? { icon } : {}),
          };
          snapshot.payload = payload;

          if (planOnly) {
            snapshot.action = "planned-create";
            context.logger.info(
              "ensureObject {nameSingular}: planned-create (dryRun)",
              { nameSingular },
            );
            const handle = await context.writeResource(
              "objectEnsured",
              `object-${nameSingular}`,
              snapshot,
            );
            return { dataHandles: [handle] };
          }

          const resp = await twentyRequest(
            cfg,
            "POST",
            "/rest/metadata/objects",
            payload,
          );
          // Twenty's metadata create response shape varies; try the envelope as
          // a best-effort first pass (never fatal if absent — the create already
          // succeeded).
          const created = ((resp as { data?: unknown }).data ?? {}) as Record<
            string,
            unknown
          >;
          const nested = (created.createOneObject ?? created.createObject ??
            {}) as Record<string, unknown>;
          let newId = String(created.id ?? nested.id ?? "");
          // Envelope guesses miss the real v2.38.x response shape, so don't trust
          // them: re-read the authoritative objects list and resolve the new id
          // by matching nameSingular/namePlural (mirrors ensureRelation's
          // created-path read-back). This makes objectId deterministic
          // regardless of the POST response envelope.
          if (!newId) {
            const objs2 = await fetchObjectsMeta(cfg);
            const createdObj = objs2.find(
              (o) =>
                String(o.nameSingular ?? "") === nameSingular ||
                String(o.namePlural ?? "") === namePlural,
            );
            if (createdObj) newId = String(createdObj.id ?? "");
          }
          snapshot.action = "created";
          if (newId) snapshot.objectId = newId;
          context.logger.info(
            "ensureObject {nameSingular}: created",
            { nameSingular },
          );
          const handle = await context.writeResource(
            "objectEnsured",
            `object-${nameSingular}`,
            snapshot,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e));
        }
      },
    },
    ensureRelation: {
      description:
        "Idempotently provision ONE custom RELATION between two existing objects. In Twenty a relation IS a field: this POSTs to /rest/metadata/fields with type RELATION plus a relationCreationPayload block, and the ONE call auto-creates BOTH sides (the reverse field on the target is server-minted from targetFieldLabel — never posted here). relationType is MANY_TO_ONE or ONE_TO_MANY only (no first-class MANY_TO_MANY). Non-destructive: a source field whose name already exists as a RELATION is a no-op (`present`; a target/relationType drift is reported, never mutated); a name that exists as a DIFFERENT type is reported (`type-mismatch`), never mutated; a create hard-fails (pre-checked here) if the derived reverse-field name already exists on the target. Both object ids are resolved by nameSingular from one metadata read. dryRun:true (the DEFAULT) validates + plans (planned-create) and writes nothing, returning the exact create payload; a real create requires confirm:true AND dryRun:false. Snapshots a `relationEnsured` resource (re-read from the server after a create).",
      arguments: z.object({
        fromObjectNameSingular: z
          .string()
          .describe(
            "Source object owning the field (nameSingular, must already exist), e.g. opportunity",
          ),
        toObjectNameSingular: z
          .string()
          .describe(
            "Target object the relation points at (nameSingular, must already exist), e.g. invoice",
          ),
        relationType: z
          .enum(["MANY_TO_ONE", "ONE_TO_MANY"])
          .describe(
            "Source-side cardinality. Only MANY_TO_ONE / ONE_TO_MANY exist in Twenty v2.38.1 (MANY_TO_MANY is a separate MORPH/junction concern, out of scope).",
          ),
        fromFieldName: z
          .string()
          .describe(
            "Source-side field name — a camelCase identifier, e.g. invoice / opportunities",
          ),
        fromLabel: z
          .string()
          .optional()
          .describe(
            "Source-side display label; defaults to a title-cased name",
          ),
        targetFieldLabel: z
          .string()
          .describe(
            "Label of the auto-created REVERSE field on the target object (REQUIRED). Its camelCase name is derived via computeMetadataNameFromLabel and must not already exist on the target.",
          ),
        targetFieldIcon: z
          .string()
          .describe(
            "Tabler icon name for the reverse field (REQUIRED), e.g. IconListOpportunity",
          ),
        fromIcon: z
          .string()
          .optional()
          .describe("Optional Tabler icon name for the source-side field"),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to apply — mutates workspace metadata"),
        dryRun: z
          .boolean()
          .default(true)
          .describe(
            "Preview the plan; write nothing. Defaults true — a real create requires confirm:true AND dryRun:false.",
          ),
      }),
      execute: async (
        args: {
          fromObjectNameSingular: string;
          toObjectNameSingular: string;
          relationType: "MANY_TO_ONE" | "ONE_TO_MANY";
          fromFieldName: string;
          fromLabel?: string;
          targetFieldLabel: string;
          targetFieldIcon: string;
          fromIcon?: string;
          confirm: boolean;
          dryRun: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          if (!args.confirm && !args.dryRun) {
            throw new Error(
              "Refusing to ensure a relation without confirm:true (mutates workspace metadata). Use dryRun:true to preview.",
            );
          }
          const planOnly = args.dryRun || !args.confirm;

          // Validate names/labels before any I/O (a typo can never POST garbage).
          const fromObject = String(args.fromObjectNameSingular ?? "").trim();
          const toObject = String(args.toObjectNameSingular ?? "").trim();
          const fromFieldName = String(args.fromFieldName ?? "").trim();
          if (!FIELD_NAME_RE.test(fromFieldName)) {
            throw new Error(
              `Invalid fromFieldName '${fromFieldName}': must be a camelCase identifier (letter-led, alphanumeric)`,
            );
          }
          if (
            args.relationType !== "MANY_TO_ONE" &&
            args.relationType !== "ONE_TO_MANY"
          ) {
            throw new Error(
              `Unsupported relationType '${args.relationType}' (allowed: MANY_TO_ONE, ONE_TO_MANY)`,
            );
          }
          const targetFieldLabel = String(args.targetFieldLabel ?? "").trim();
          if (!targetFieldLabel) {
            throw new Error(
              "targetFieldLabel is required (drives the reverse field name)",
            );
          }
          const targetFieldIcon = String(args.targetFieldIcon ?? "").trim();
          if (!targetFieldIcon) {
            throw new Error("targetFieldIcon is required");
          }
          const reverseFieldName = computeMetadataNameFromLabel(
            targetFieldLabel,
          );
          if (!reverseFieldName) {
            throw new Error(
              `targetFieldLabel '${targetFieldLabel}' yields an empty reverse field name`,
            );
          }
          const fromLabel =
            args.fromLabel != null && String(args.fromLabel).trim()
              ? sanitizeText(args.fromLabel, 120)
              : titleCaseToken(fromFieldName);
          const fromIcon = args.fromIcon != null && String(args.fromIcon).trim()
            ? String(args.fromIcon).trim()
            : undefined;

          // Resolve BOTH object ids from one metadata read.
          const objs = await fetchObjectsMeta(cfg);
          const sourceObj = objs.find(
            (o) => String(o.nameSingular ?? "") === fromObject,
          );
          if (!sourceObj) {
            throw new Error(
              `Object '${fromObject}' not found in workspace metadata`,
            );
          }
          const targetObj = objs.find(
            (o) => String(o.nameSingular ?? "") === toObject,
          );
          if (!targetObj) {
            throw new Error(
              `Object '${toObject}' not found in workspace metadata`,
            );
          }
          const objectMetadataId = String(sourceObj.id ?? "");
          const targetObjectMetadataId = String(targetObj.id ?? "");
          if (!objectMetadataId || !targetObjectMetadataId) {
            throw new Error(
              "Source/target object is missing its metadata id; cannot create the relation",
            );
          }

          // Read-back shaper for a RELATION field DTO -> snapshot detail.
          const readback = (
            f: Record<string, unknown>,
          ): Record<string, unknown> => {
            const settings = (f.settings ?? {}) as Record<string, unknown>;
            const rel = (f.relation ?? {}) as Record<string, unknown>;
            const tgtObj = (rel.targetObjectMetadata ?? {}) as Record<
              string,
              unknown
            >;
            const srcF = (rel.sourceFieldMetadata ?? {}) as Record<
              string,
              unknown
            >;
            const tgtF = (rel.targetFieldMetadata ?? {}) as Record<
              string,
              unknown
            >;
            const out: Record<string, unknown> = {};
            if (f.id) out.fieldId = String(f.id);
            if (settings.relationType) {
              out.relationType = String(settings.relationType);
            }
            if (settings.onDelete) out.onDelete = String(settings.onDelete);
            if (settings.joinColumnName) {
              out.joinColumnName = String(settings.joinColumnName);
            }
            const relDetail: Record<string, unknown> = {};
            if (tgtObj.id || tgtObj.nameSingular) {
              relDetail.targetObjectMetadata = {
                ...(tgtObj.id ? { id: String(tgtObj.id) } : {}),
                ...(tgtObj.nameSingular
                  ? { nameSingular: String(tgtObj.nameSingular) }
                  : {}),
              };
            }
            if (srcF.id || srcF.name) {
              relDetail.sourceFieldMetadata = {
                ...(srcF.id ? { id: String(srcF.id) } : {}),
                ...(srcF.name ? { name: String(srcF.name) } : {}),
              };
            }
            if (tgtF.id || tgtF.name) {
              relDetail.targetFieldMetadata = {
                ...(tgtF.id ? { id: String(tgtF.id) } : {}),
                ...(tgtF.name ? { name: String(tgtF.name) } : {}),
              };
            }
            if (Object.keys(relDetail).length > 0) out.relation = relDetail;
            return out;
          };

          const snapshot: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            dryRun: planOnly,
            fromObjectNameSingular: fromObject,
            toObjectNameSingular: toObject,
            name: fromFieldName,
            fromFieldName: fromFieldName,
            label: fromLabel,
            type: "RELATION",
            relationType: args.relationType,
            reverseFieldName,
            targetFieldLabel,
            targetFieldIcon,
            objectMetadataId,
            targetObjectMetadataId,
            retrievedAt: new Date().toISOString(),
          };

          // Idempotency (source side): does fromFieldName already exist?
          const sourceFields = (sourceObj.fields ?? []) as Array<
            Record<string, unknown>
          >;
          const existingSource =
            (Array.isArray(sourceFields) ? sourceFields : [])
              .find((f) => String(f.name ?? "") === fromFieldName);
          if (existingSource) {
            const existingType = String(existingSource.type ?? "");
            if (existingType !== "RELATION") {
              // Present as a DIFFERENT type — reported, never mutated.
              snapshot.action = "type-mismatch";
              snapshot.type = existingType;
              snapshot.typeMismatch =
                `Field '${fromObject}.${fromFieldName}' exists as type '${existingType}', ` +
                `requested 'RELATION' — left unchanged (no mutation).`;
              context.logger.info(
                "ensureRelation {from}.{name}: type-mismatch ({existing})",
                {
                  from: fromObject,
                  name: fromFieldName,
                  existing: existingType,
                },
              );
              const handle = await context.writeResource(
                "relationEnsured",
                `relation-${fromObject}-${fromFieldName}`,
                snapshot,
              );
              return { dataHandles: [handle] };
            }
            // Present as a RELATION — no-op. Note a target/relationType drift.
            snapshot.action = "present";
            const rb = readback(existingSource);
            Object.assign(snapshot, rb);
            const rbRel = (rb.relation ?? {}) as Record<string, unknown>;
            const rbTgt = (rbRel.targetObjectMetadata ?? {}) as Record<
              string,
              unknown
            >;
            const pointsElsewhere = rbTgt.id != null &&
              String(rbTgt.id) !== targetObjectMetadataId;
            const cardinalityDrift = rb.relationType != null &&
              String(rb.relationType) !== args.relationType;
            if (pointsElsewhere || cardinalityDrift) {
              snapshot.targetMismatch =
                `Relation '${fromObject}.${fromFieldName}' exists as ` +
                `${rb.relationType ?? "?"} -> target ${
                  rbTgt.id ?? "?"
                }; requested ` +
                `${args.relationType} -> target ${targetObjectMetadataId} — left unchanged (no mutation).`;
            }
            context.logger.info(
              "ensureRelation {from}.{name}: present (no-op)",
              { from: fromObject, name: fromFieldName },
            );
            const handle = await context.writeResource(
              "relationEnsured",
              `relation-${fromObject}-${fromFieldName}`,
              snapshot,
            );
            return { dataHandles: [handle] };
          }

          // Reverse-name collision pre-check on the TARGET (create would 400).
          const targetFields = (targetObj.fields ?? []) as Array<
            Record<string, unknown>
          >;
          const reverseCollision =
            (Array.isArray(targetFields) ? targetFields : [])
              .some((f) => String(f.name ?? "") === reverseFieldName);
          if (reverseCollision) {
            throw new Error(
              `Reverse field name '${reverseFieldName}' (from targetFieldLabel '${targetFieldLabel}') ` +
                `already exists on target object '${toObject}' — a relation create would fail. ` +
                `Choose a different targetFieldLabel.`,
            );
          }

          // CREATE path — build the metadata field body + relationCreationPayload.
          const payload: Record<string, unknown> = {
            name: fromFieldName,
            label: fromLabel,
            type: "RELATION",
            objectMetadataId,
            ...(fromIcon ? { icon: fromIcon } : {}),
            relationCreationPayload: {
              type: args.relationType,
              targetObjectMetadataId,
              targetFieldLabel,
              targetFieldIcon,
            },
          };
          snapshot.payload = payload;

          if (planOnly) {
            snapshot.action = "planned-create";
            context.logger.info(
              "ensureRelation {from}.{name}: planned-create (dryRun)",
              { from: fromObject, name: fromFieldName },
            );
            const handle = await context.writeResource(
              "relationEnsured",
              `relation-${fromObject}-${fromFieldName}`,
              snapshot,
            );
            return { dataHandles: [handle] };
          }

          await twentyRequest(cfg, "POST", "/rest/metadata/fields", payload);
          // Don't trust the create response alone — re-read and locate the field.
          const objs2 = await fetchObjectsMeta(cfg);
          const sourceObj2 = objs2.find(
            (o) => String(o.nameSingular ?? "") === fromObject,
          );
          const sourceFields2 = (sourceObj2?.fields ?? []) as Array<
            Record<string, unknown>
          >;
          const created = (Array.isArray(sourceFields2) ? sourceFields2 : [])
            .find((f) => String(f.name ?? "") === fromFieldName);
          snapshot.action = "created";
          if (created) Object.assign(snapshot, readback(created));
          context.logger.info(
            "ensureRelation {from}.{name} -> {to}: created ({relType})",
            {
              from: fromObject,
              name: fromFieldName,
              to: toObject,
              relType: args.relationType,
            },
          );
          const handle = await context.writeResource(
            "relationEnsured",
            `relation-${fromObject}-${fromFieldName}`,
            snapshot,
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
        "upsertPerson",
        "ensureField",
        "ensureOpportunitySegmentation",
        "ensureObject",
        "ensureRelation",
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
