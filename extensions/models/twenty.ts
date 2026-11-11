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
  noteHashHmacKey: z
    .string()
    .default("")
    .meta({ sensitive: true })
    .describe(
      'OPTIONAL keyed-HMAC secret for note reconciliation (TWENTY-NOTE-RECONCILE). Resolve from a vault via CEL (e.g. vault.get("twenty", "note-hash-hmac-key")); NEVER hard-code. The repo-side notes-drift report reads the SAME vault key so both sides HMAC byte-identically (SEC-1, the sole ext<->report coupling). Empty (default) = note-hash surfacing still works (listNotes returns any already-stored hash — no key needed), but POPULATION is gated: population is ENABLED by provisioning the note.noteHash field, and when that field IS provisioned createNote/updateNote FAIL CLOSED on an empty key (refuse the write) rather than store a zero-confidentiality empty-keyed hash (SEC-5/ADV-10). SENSITIVE: logged length-only, never snapshotted, redacted in errors — same discipline as apiToken (SEC-6). push_leads/ensureNoteForLead never hash, so the lead sink is unaffected by this key.',
    ),
  // --- Email SEND subsystem (TWENTY-EMAIL send) -----------------------------
  // The API_KEY apiToken above is FORBIDDEN on runWorkflowVersion + myConnected-
  // Accounts (both need a workspace-member USER context). The send path mints a
  // fresh USER access token per run from these vaulted credentials (login ->
  // access token), uses it, and discards it (no refresh/rotation/write-back).
  sendUserEmail: z
    .string()
    .default("")
    .meta({ sensitive: true })
    .describe(
      'Email of the ONE workspace-member service user whose connected mailboxes own ALL brand identities. Resolve from a vault via CEL (e.g. vault.get("twenty", "send-user-email")); NEVER hard-code. Empty (default) = the send subsystem is unconfigured and sendEmail/listConnectedAccounts fail closed. SENSITIVE.',
    ),
  sendUserPassword: z
    .string()
    .default("")
    .meta({ sensitive: true })
    .describe(
      'Password of the send service user (sendUserEmail). Resolve from a vault via CEL (e.g. vault.get("twenty", "send-user-password")); NEVER hard-code, log, or snapshot. Used ONLY to mint a per-run USER access token; discarded immediately. SENSITIVE.',
    ),
  brandConnectedAccounts: z
    .record(z.string(), z.string())
    .default({})
    .describe(
      "Fail-closed identity map: brand DOMAIN (e.g. shrug.host) -> the connectedAccountId (UUID) of the mailbox that sends AS that brand. Load-validated at first send (validateBrandMap): every value MUST be a non-empty UUID with no duplicate ids; empty (default) = no brand can be resolved so every sendEmail refuses. At send time the chosen id is re-validated against the LIVE myConnectedAccounts list AND its account domain must equal the brand key (F3/F14) — this is what prevents the wrong-brand-fallback bug.",
    ),
  lineOfBusinessBrand: z
    .record(z.string(), z.string())
    .default({})
    .describe(
      "OPTIONAL default-brand map: Opportunity lineOfBusiness SELECT value (UPPER_SNAKE) -> brand domain (a key of brandConnectedAccounts). Consulted ONLY when fromBrand is ABSENT and the target is an Opportunity with a NON-EMPTY lineOfBusiness (F5); every other target requires an explicit fromBrand. An explicit-but-unmapped fromBrand is a hard refuse and NEVER consults this default (F4). Empty (default) = no default, fromBrand always required (F16-safe).",
    ),
  sendWorkflowName: z
    .string()
    .default("Send Email")
    .describe(
      "Name of the Twenty native 'Send Email' workflow whose ACTIVE/published version sendEmail invokes. Resolved to lastPublishedVersionId at send time (F12 — never pin a version id). The workflow's send-email step MUST author connectedAccountId/to/subject/body as trigger-payload variable references (see design doc); that authoring is a Twenty-side dependency, not built here.",
    ),
  twentyOrigin: z
    .string()
    .default("")
    .describe(
      "Origin passed to the login/token mutations when minting the USER access token. Empty (default) = fall back to baseUrl (the default workspace on twenty-local). Set explicitly for a multi-workspace host.",
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

/**
 * Blank out GraphQL string literals (`"..."` and block `"""..."""`) and `#` line
 * comments, replacing each span with a single space, so a subsequent STRUCTURAL
 * scan cannot be fooled by a `}`, a `#`, or the words `mutation`/`subscription`
 * appearing INSIDE a string or comment. NOT a full GraphQL lexer — it only
 * neutralizes the spans that must not be scanned. (GraphQL has no C-style block
 * comments; only `#` line comments and triple-quoted block strings.)
 */
export function stripGraphQLStringsAndComments(query: string): string {
  let out = "";
  let i = 0;
  const n = query.length;
  while (i < n) {
    const c = query[i];
    if (c === '"' && query[i + 1] === '"' && query[i + 2] === '"') {
      i += 3;
      while (
        i < n &&
        !(query[i] === '"' && query[i + 1] === '"' && query[i + 2] === '"')
      ) i++;
      i += 3;
      out += " ";
      continue;
    }
    if (c === '"') {
      i++;
      while (i < n && query[i] !== '"') {
        if (query[i] === "\\") i++; // skip the char after a backslash escape
        i++;
      }
      i++;
      out += " ";
      continue;
    }
    if (c === "#") {
      while (i < n && query[i] !== "\n") i++;
      out += " ";
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

/**
 * True iff `query` contains NO top-level `mutation`/`subscription` operation —
 * i.e. it is a read-only document. Strips strings/comments first, then scans at
 * brace depth 0: the first identifier of each operation (document start, or just
 * after a top-level `}`) is the operation type; a bare `{...}` selection is an
 * anonymous query. Commas are treated as insignificant (GraphQL ignores them),
 * so a comma-separated multi-op cannot slip a mutation past. This is
 * DEFENSE-IN-DEPTH: the real guarantee is that {@link twentyGraphQL}'s `query` is
 * ALWAYS an in-code constant literal (never caller-supplied); this guard is NOT a
 * safe boundary for untrusted query text.
 */
export function isReadOnlyGraphQL(query: string): boolean {
  const stripped = stripGraphQLStringsAndComments(query).replace(/^﻿/, "");
  let depth = 0;
  let atOpStart = true; // document start or just after a top-level `}`
  const re = /[{}]|[A-Za-z_][A-Za-z0-9_]*/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(stripped)) !== null) {
    const tok = m[0];
    if (tok === "{") {
      depth++;
      atOpStart = false;
      continue;
    }
    if (tok === "}") {
      depth--;
      if (depth <= 0) {
        depth = 0;
        atOpStart = true;
      }
      continue;
    }
    if (depth === 0 && atOpStart) {
      const low = tok.toLowerCase();
      if (low === "mutation" || low === "subscription") return false;
      atOpStart = false; // first identifier consumed (query/field/op name)
    }
  }
  return true;
}

/**
 * Minimal Twenty **Core GraphQL** client over fetch (TWENTY-DASHBOARDS). POSTs
 * `{query, variables}` to `/graphql` with the vaulted bearer token — the SAME
 * workspace API key as the REST surface (only native-dashboard *authoring* needs
 * a user token, which this model does not do). Throws (caller-redacts) on a
 * non-2xx HTTP status OR when the GraphQL response carries `errors`, so any
 * failure is uniform and a caller can fall back to REST.
 *
 * **READ-ONLY, in-code-literal-only:** `query` MUST be a compile-time constant
 * literal built inside this module — NEVER a caller-supplied string. That
 * invariant (not the guard below) is the real safety boundary; a
 * `stripGraphQLStringsAndComments`-based {@link isReadOnlyGraphQL} check is
 * applied as defense-in-depth to reject any top-level mutation/subscription
 * (incl. comma-separated multi-op and `#`/`"""`-obfuscated docs), but it is NOT
 * hardened for untrusted input. Returns the `data` object.
 */
export async function twentyGraphQL(
  cfg: TwentyCfg,
  query: string,
  variables?: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  // Read-only guard (defense-in-depth; see docstring — the real guarantee is the
  // in-code-literal-only invariant): reject a top-level mutation/subscription.
  if (!isReadOnlyGraphQL(query)) {
    throw new Error(
      "twentyGraphQL refuses a non-query operation (read-only transport)",
    );
  }
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const resp = await fetch(`${base}/graphql`, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${cfg.apiToken}`,
      "Accept": "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(variables ? { query, variables } : { query }),
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(
      `Twenty GraphQL failed: ${resp.status} ${resp.statusText} — ${
        text.slice(0, 300)
      }`,
    );
  }
  const json = (text ? JSON.parse(text) : {}) as {
    data?: Record<string, unknown>;
    errors?: Array<{ message?: string }>;
  };
  if (json.errors && json.errors.length > 0) {
    const msg = json.errors.map((e) => e?.message ?? "").join("; ");
    throw new Error(`Twenty GraphQL errors: ${msg.slice(0, 300)}`);
  }
  return json.data ?? {};
}

/**
 * Raw authed GET that never throws — returns the status + parsed body so a probe
 * can CLASSIFY the outcome (2xx reachable / 404 endpoint-absent / 401-403
 * forbidden / 4xx other), which twentyRequest's throw-on-non-2xx can't express.
 * Used by listViews (TWENTY-VIEW-MGMT) to resolve which view endpoint is live and
 * whether the token's role can even see views. Read-only.
 */
export async function rawGet(
  cfg: TwentyCfg,
  path: string,
): Promise<{ status: number; ok: boolean; body: unknown }> {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const resp = await fetch(`${base}${path}`, {
    headers: {
      "Authorization": `Bearer ${cfg.apiToken}`,
      "Accept": "application/json",
    },
  });
  const text = await resp.text();
  let body: unknown = null;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text.slice(0, 200);
  }
  return { status: resp.status, ok: resp.ok, body };
}

/** Classify a probe status into a coarse reachability verdict. */
export function classifyProbe(
  status: number,
): "ok" | "absent" | "forbidden" | "error" {
  if (status >= 200 && status < 300) return "ok";
  if (status === 404) return "absent";
  if (status === 401 || status === 403) return "forbidden";
  return "error";
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

/**
 * Canonical COMPANY host for domain dedup (TWENTY-COMPANY-UPSERT, ADV-1).
 * {@link normalizeDomainHost} reduces a domain-ish value to a bare host but
 * deliberately does NOT strip a leading `www.` — so `acme.com` and
 * `https://www.acme.com` normalize to DIFFERENT hosts (`acme.com` vs
 * `www.acme.com`) and a blind compare false-negatives (and would duplicate).
 * This strips a single leading `www.` AFTER normalizeDomainHost so BOTH match
 * sides reduce to the same registrable-host form. A bare `www.<tld>` (nothing
 * left after the strip) is treated as unusable (null). Not PSL-aware — a full
 * registrable-domain reduction (e.g. collapsing `shop.acme.co.uk` -> `acme.co.uk`)
 * needs the public-suffix list; the leading-`www.` strip covers the dominant
 * real-world stored-URL variant (scheme + `www.`) this dedup exists to close.
 */
export function canonicalCompanyHost(raw: unknown): string | null {
  const host = normalizeDomainHost(raw);
  if (!host) return null;
  const stripped = host.replace(/^www\./, "");
  return stripped || null;
}

/**
 * Canonical COMPANY name for dedup/compare (TWENTY-COMPANY-UPSERT): lowercase,
 * collapse internal whitespace to single spaces, trim. Used to compare an input
 * name against a stored name for exact-canonical equality (case/whitespace
 * insensitive) so a name match — or a domain-hit's name-conflict check — is not
 * foiled by trivial spacing/case drift. Empty string when nothing usable.
 */
export function canonicalCompanyName(raw: unknown): string {
  if (raw == null) return "";
  return String(raw).replace(/\s+/g, " ").trim().toLowerCase();
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
 * occurrences of the secret. Pass `moreSecrets` (TE-1) to mask ADDITIONAL literal
 * secrets — the send path passes cfg.sendUserPassword and the minted user token
 * so neither can survive into a captured send-path error/report.
 */
export function redactError(
  raw: unknown,
  maxLen = 300,
  token?: string,
  moreSecrets?: Array<string | undefined | null>,
): string {
  let s = raw instanceof Error ? raw.message : String(raw ?? "");
  // Scrub each explicitly-provided secret down to length >= 2. These are values
  // the caller has deliberately named as must-not-leak (apiToken, send password,
  // minted user token, submitted email, submitted person name tokens). The >= 2
  // floor (rather than >= 4) exists so a SHORT real name echoed in a Twenty 4xx
  // — "Ed", "Li", "Eli", "Ann" are all real submitted names — is still redacted
  // out of the durable audit; only 1-char tokens are skipped (too generic to
  // scrub without wrecking the message). The generic bearer/filter/email/digit
  // scrubbers below are unaffected. Minor cosmetic over-redaction of an
  // incidental 2-char substring is the accepted trade for not leaking PII.
  for (const sec of [token, ...(moreSecrets ?? [])]) {
    if (sec && sec.length >= 2) s = s.split(sec).join("[redacted]");
  }
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
  client_ip: z
    .string()
    .optional()
    .describe(
      "Submitter source IP from the contact worker, carried through solely for the spam-classifier IP-rotation velocity signal (classifyLead). Never written to Twenty; never surfaced in the audit (reasons are coded, not raw IPs).",
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
  // Carry the source IP through for classifyLead's IP-rotation velocity signal
  // only (the adapter otherwise drops it). Accept either wire spelling.
  const clientIp = (str(raw.client_ip) || str(raw.clientIp)).trim();

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
    ...(clientIp ? { client_ip: clientIp } : {}),
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

// --- Lead spam classification (shadow mode) ---------------------------------

/**
 * Per-lead spam verdict from {@link classifyLead}. `reasons` are PII-FREE coded
 * tokens (never raw email/name/message/IP text) so they are safe to surface in
 * the push_leads audit, which carries no raw PII beyond the opaque leadId.
 */
export interface SpamVerdict {
  leadId: string;
  score: number;
  reasons: string[];
  flagged: boolean;
}

/**
 * Score at/above which a lead is flagged. SHADOW MODE: flagged leads are
 * reported (score + reasons) but still synced - nothing is quarantined. Tuned
 * (design/lead-spam-filter.md section 6) so a single signal class is never
 * enough alone: windowed repeat-email velocity (+3) needs one corroborator, and
 * a solicitation phrase (+2) plus a free-mail domain (+1) still falls short -
 * which protects a legitimate repeat submitter and a plain free-mail inquiry
 * while the Robertjisib set clears easily (velocity 3 + localpart 2 + rotation 2).
 */
export const SPAM_SCORE_THRESHOLD = 4;

/** Window for the cross-lead velocity signals (design section 2: "within a
 * short window"). A burst clusters; a loyal customer contacting months apart
 * does not accumulate velocity. */
const SPAM_VELOCITY_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

// High-precision solicitation phrases ONLY. Deliberately EXCLUDES dual-use B2B
// vocabulary (cooperation / collaborate / bare "seo" / "marketing services" /
// "rank your") that a legitimate freelancer inquiry would use - those produced
// a threshold-boundary false positive from a plain gmail lead (review H3).
const SPAM_SOLICITATION_RE =
  /\b(know your price|your prices?|back ?link|link building|guest post|crypto|bitcoin|forex|binary option|investment opportunity|loan offer)\b/i;
const SPAM_REFERRAL_RE =
  /\b(sent me|referred (by|me)|recommend(ed)? (by|me|us)|found you (via|through|on)|came from|heard about you|fediverse|mastodon|word of mouth)\b/i;

/** Count letter<->digit class transitions across a string's alnum runs. */
function alnumClassTransitions(s: string): number {
  let transitions = 0;
  let prev: "a" | "d" | null = null;
  for (const ch of s.toLowerCase()) {
    let cls: "a" | "d" | null = null;
    if (ch >= "a" && ch <= "z") cls = "a";
    else if (ch >= "0" && ch <= "9") cls = "d";
    else {
      prev = null; // a separator breaks the run
      continue;
    }
    if (prev !== null && cls !== prev) transitions++;
    prev = cls;
  }
  return transitions;
}

/**
 * True when an email localpart looks machine-generated, e.g. "gregoryj8tl2g":
 * long, mixes letters and digits, and flips between the two several times.
 * "neil", "weatherman", "john.doe", "jsmith2024" do NOT trip it.
 */
export function localpartLooksMachine(email: string): boolean {
  const at = email.indexOf("@");
  const lp = (at === -1 ? email : email.slice(0, at)).toLowerCase();
  if (lp.length < 8) return false;
  if (!/[a-z]/.test(lp) || !/\d/.test(lp)) return false;
  return alnumClassTransitions(lp) >= 3;
}

/** Normalized key for name-identity velocity: trimmed, lower-cased, internal
 * whitespace collapsed. Empty when the name is blank (so a nameless lead never
 * clusters with another nameless lead). */
function normalizeNameKey(name: string | null | undefined): string {
  return (name ?? "").trim().toLowerCase().replace(/\s+/g, " ");
}

/**
 * True when a NAME field is a single machine-handle token rather than a human
 * name: no whitespace, >=12 chars, carries an embedded >=4-digit run, and its
 * letters are all-caps or vowel-starved (< 0.3 vowel ratio). Catches the
 * "NARYTHY911194NEYRTHYT" gibberish-handle campaign. A real name is multi-word
 * (has whitespace) or short, so "Neil Hanlon", "WEATHER MAN", "Robertjisib",
 * and "jsmith2024" do NOT trip it.
 */
export function nameLooksGibberish(name: string): boolean {
  const n = (name ?? "").trim();
  if (/\s/.test(n)) return false; // multi-word => not this single-token pattern
  if (n.length < 12) return false;
  if (!/\d{4,}/.test(n)) return false; // embedded long digit run
  const letters = n.replace(/[^A-Za-z]/g, "");
  if (letters.length < 8) return false;
  const allCaps = n === n.toUpperCase();
  const vowels = (letters.match(/[aeiou]/gi) ?? []).length;
  return allCaps || vowels / letters.length < 0.3;
}

/**
 * Fraction of a string's letters that belong to a clearly NON-LATIN script
 * (Cyrillic/Greek/CJK/Arabic/...). Latin-with-diacritics (Vietnamese, Czech,
 * Turkish) is Latin script and does NOT count - so a legitimate diacritic-dense
 * Latin message is not mistaken for a foreign-script spam body (review L1).
 */
function nonLatinScriptRatio(s: string): number {
  let letters = 0;
  let nonLatin = 0;
  for (const ch of s) {
    if (/\p{L}/u.test(ch)) {
      letters++;
      if (!/\p{Script=Latin}/u.test(ch)) nonLatin++;
    }
  }
  return letters === 0 ? 0 : nonLatin / letters;
}

/**
 * True when a raw phone is present but is the design's mis-prefixed
 * domestic-trunk case: a bare 11-digit number starting with 8, NOT entered
 * internationally (no leading '+' or '00'). Such a number's real dialable form
 * is +7..., so normalizePhone's best-effort "+8..." is bogus. A number entered
 * as E.164 (+84 Vietnam, +81 Japan, ...) is trusted on STRUCTURE alone and is
 * never flagged for its shape (review M2). Low-weight, never load-bearing.
 */
export function phoneLooksBogus(rawPhone: string): boolean {
  const raw = String(rawPhone).trim();
  const digits = raw.replace(/\D/g, "");
  if (digits.length < 7) return false; // absent / too short -> not a signal
  const enteredIntl = raw.startsWith("+") || digits.startsWith("00");
  // Bare 11-digit trunk-8 number not entered internationally -> mis-prefixed
  // domestic trunk (its real form is +7...). Exclude leading digit pairs that
  // ARE real zone-8 country codes (81 JP, 82 KR, 84 VN, 86 CN), which collide
  // at this length when pasted without a '+' (review M2 cycle 2).
  if (!enteredIntl && /^8\d{10}$/.test(digits) && !/^8[1246]/.test(digits)) {
    return true;
  }
  const norm = normalizePhone(rawPhone);
  if (/^\+1[2-9]\d{9}$/.test(norm)) return false; // clean NANP
  return !/^\+[1-9]\d{7,14}$/.test(norm); // only structurally invalid E.164
}

/**
 * Score a corpus of leads for spam. SHADOW MODE: pure, no I/O, no quarantine -
 * it only annotates. Velocity signals (repeat email, IP rotation) are computed
 * across the WHOLE corpus but WINDOWED to leads near each other in time
 * (design: "within a short window"), so pass the full set, not just the
 * processed page. Returns a verdict per lead keyed by the validated leadId.
 *
 * The strong signals are deliberately LANGUAGE-INDEPENDENT: the Robertjisib set
 * is one solicitation template in six languages, so English-phrase matching
 * alone misses five of six - windowed repeat-email velocity, machine-generated
 * localpart and IP rotation catch all six. Surface aesthetics (all-caps body,
 * quirky domain, null contact_type) do NOT contribute: a real fediverse
 * referral (WEATHER MAN) trips all three. A referral mention discounts the
 * score, but only absent hard bot-farm evidence (velocity/rotation) so the
 * discount cannot be weaponized to smuggle a burst through. A known-customer
 * domain hard-passes. Self-contained so it can be lifted to a standalone
 * classifier (design options B/C) without a rewrite.
 *
 * Accepted residual risks for the SHADOW phase (documented, not silently
 * inherited; revisit before ENFORCE / weight retuning):
 *   - Slow-drip evasion: a spammer pacing submissions >1 window apart never
 *     accumulates velocity; the per-lead signals (localpart/phone/solicitation)
 *     are the only backstop then. This is the deliberate cost of windowing out
 *     the loyal-customer false positive.
 *   - Windowing is pairwise (relative to each lead's own timestamp), not
 *     transitive, so members of a burst spaced near the window edge can score
 *     unevenly. Harmless at the current margin; matters only if weights change.
 *   - A null/unparseable received_at clusters with all other null-timestamp
 *     leads for the same email with no time bound (biases toward over-flagging,
 *     not toward an evasion), so the signal's precision depends on upstream
 *     timestamp quality.
 */
export function classifyLead(
  corpus: LeadRecord[],
  opts: {
    threshold?: number;
    freemailDomains?: readonly string[];
    knownDomains?: readonly string[];
  } = {},
): Map<string, SpamVerdict> {
  const threshold = opts.threshold ?? SPAM_SCORE_THRESHOLD;
  // Lowercase the freemail list so a mixed-case operator entry still matches
  // (isBlockedDomain compares a lowercased domain against the list verbatim;
  // review INFO-7, now that the list is operator-facing via opts).
  const freemail = (opts.freemailDomains ?? DEFAULT_EMAIL_DOMAIN_BLOCKLIST).map(
    (
      d,
    ) => d.toLowerCase(),
  );
  const known = new Set((opts.knownDomains ?? []).map((d) => d.toLowerCase()));

  // Velocity index: per normalized email, every occurrence's timestamp + IP.
  // Signals are WINDOWED below (design: "within a short window") so a burst
  // clusters but a loyal customer contacting months apart does not accumulate
  // velocity (review H2).
  const byEmail = new Map<string, { t: number | null; ip: string }[]>();
  for (const l of corpus) {
    const email = validateEmail(l.email);
    if (!email) continue;
    const parsed = Date.parse(l.received_at ?? "");
    const t = Number.isNaN(parsed) ? null : parsed;
    const ip = (l.client_ip ?? "").trim();
    let arr = byEmail.get(email);
    if (!arr) {
      arr = [];
      byEmail.set(email, arr);
    }
    arr.push({ t, ip });
  }

  // Name-identity index (design section 2: "same email/NAME"): per normalized
  // name, every occurrence's timestamp + email. The spam tell is one persona
  // reused across DISTINCT burner emails (the Robertjisib wave rotates the gmail
  // address each time, defeating email velocity); counting distinct emails in a
  // window - not raw repeats - is what keeps a single human resubmitting from
  // one address (same name, one email) from clustering with themselves.
  const byName = new Map<string, { t: number | null; email: string }[]>();
  for (const l of corpus) {
    const nameKey = normalizeNameKey(l.name);
    if (!nameKey) continue;
    const email = validateEmail(l.email);
    if (!email) continue; // a nameless/emailless lead can't corroborate identity
    const parsed = Date.parse(l.received_at ?? "");
    const t = Number.isNaN(parsed) ? null : parsed;
    let arr = byName.get(nameKey);
    if (!arr) {
      arr = [];
      byName.set(nameKey, arr);
    }
    arr.push({ t, email });
  }

  const out = new Map<string, SpamVerdict>();
  for (const l of corpus) {
    const leadId = validateLeadId(l.id);
    if (!leadId) continue;
    const reasons: string[] = [];
    let score = 0;
    const email = validateEmail(l.email);
    const dom = email ? domainOfEmail(email) : null;

    // Known-customer hard-pass (design section 2): a returning customer must
    // never be quarantined, regardless of score. Empty by default; the IN
    // clients / Twenty People join that POPULATES this is the ENFORCE-phase
    // task (design section 5.2) - it must be wired before spamFilter=true.
    if (dom && known.has(dom)) {
      out.set(leadId, {
        leadId,
        score: 0,
        reasons: ["known-customer-hardpass"],
        flagged: false,
      });
      continue;
    }

    // Windowed velocity (cross-lead).
    let windowCount = 1;
    let windowIps = 0;
    if (email) {
      const parsed = Date.parse(l.received_at ?? "");
      const t0 = Number.isNaN(parsed) ? null : parsed;
      const peers = byEmail.get(email)!;
      const near = peers.filter((p) =>
        (t0 === null || p.t === null)
          ? (t0 === null && p.t === null)
          : Math.abs(p.t - t0) <= SPAM_VELOCITY_WINDOW_MS
      );
      windowCount = near.length;
      windowIps = new Set(near.map((p) => p.ip).filter(Boolean)).size;
      if (windowCount >= 3) {
        score += 3;
        reasons.push(`identity-repeat:${windowCount}`);
      } else if (windowCount === 2) {
        score += 1;
        reasons.push("identity-repeat:2");
      }
      if (windowIps >= 2) {
        score += 2;
        reasons.push(`ip-rotation:${windowIps}`);
      }
    }

    // Name-identity velocity: one persona reused across DISTINCT emails in the
    // window is a bot rotating burner addresses (the Robertjisib wave), which
    // email velocity can't see. Counting distinct emails - not raw name repeats
    // - means a single human resubmitting from one address never clusters, and a
    // months-apart loyal customer stays a singleton (both windowed, review H2).
    // Weighted like email velocity (+1 for a pair, +3 for a burst) so it can
    // never flag on its own - it only corroborates (dup/H2/H3 FP guards).
    const nameKey = normalizeNameKey(l.name);
    if (nameKey && email) {
      const parsed = Date.parse(l.received_at ?? "");
      const t0 = Number.isNaN(parsed) ? null : parsed;
      const near = byName.get(nameKey)!.filter((p) =>
        (t0 === null || p.t === null)
          ? (t0 === null && p.t === null)
          : Math.abs(p.t - t0) <= SPAM_VELOCITY_WINDOW_MS
      );
      const distinctEmails = new Set(near.map((p) => p.email)).size;
      if (distinctEmails >= 3) {
        score += 3;
        reasons.push(`name-repeat:${distinctEmails}`);
      } else if (distinctEmails === 2) {
        score += 1;
        reasons.push("name-repeat:2");
      }
    }

    // Per-lead signals.
    if (email && localpartLooksMachine(email)) {
      score += 2;
      reasons.push("localpart-machine-generated");
    }
    if (nameLooksGibberish(l.name ?? "")) {
      score += 2;
      reasons.push("name-gibberish");
    }
    if (phoneLooksBogus(l.phone ?? "")) {
      score += 1;
      reasons.push("phone-unnormalizable");
    }
    const msg = l.message ?? "";
    const solicitation = SPAM_SOLICITATION_RE.test(msg);
    if (solicitation) {
      score += 2;
      reasons.push("solicitation-template");
    }
    // The nonlatin signal is a MISMATCH signal (ASCII name vs foreign-script
    // body), so it requires a non-empty ASCII name (review L3).
    const name = (l.name ?? "").trim();
    const nameIsAscii = name !== "" &&
      [...name].every((c) => (c.codePointAt(0) ?? 0) < 128);
    if (nameIsAscii && nonLatinScriptRatio(msg) >= 0.5) {
      score += 2;
      reasons.push("nonlatin-body-ascii-name");
    }
    if (solicitation && dom && isBlockedDomain(dom, freemail)) {
      score += 1;
      reasons.push("freemail-plus-solicitation");
    }

    // Ham discount: a referral mention is a HAM signal (the WEATHER MAN guard),
    // but it may only RESCUE a borderline lead - it can never cancel a score
    // that the spam signals have ALREADY driven to the flag threshold. So the
    // discount applies only when the pre-discount score is below threshold.
    // This blocks the evasion where a spammer appends "a friend sent me" to an
    // otherwise clearly-spam lead (single-shot OR a velocity burst) to zero it
    // out, while still discounting a genuine one-off referral whose score was
    // never going to flag (reviews H1 cycle 1 + cycle 2).
    if (SPAM_REFERRAL_RE.test(msg)) {
      if (score < threshold) {
        score -= 5;
        reasons.push("referral-mention-discount");
      } else {
        reasons.push("referral-mention-ignored-corroborated");
      }
    }

    if (score < 0) score = 0;
    out.set(leadId, { leadId, score, reasons, flagged: score >= threshold });
  }
  return out;
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

/**
 * Strict leadId->opportunity resolution for the SEND path (EMAIL-TE-4): THROWS on
 * an ambiguous (>1) match instead of silently taking [0]. A duplicate leadId must
 * never let the send pick one opportunity and drive the wrong-brand LoB default —
 * a duplicate is an operator/data error, so fail loud. Read methods keep the
 * tolerant {@link findOpportunityByLeadId} first-match.
 */
async function findOpportunityByLeadIdStrict(
  cfg: TwentyCfg,
  leadId: string,
): Promise<Record<string, unknown> | null> {
  const list = unwrapList(
    await twentyRequest(
      cfg,
      "GET",
      buildFilterPath("/rest/opportunities", "leadId", leadId),
    ),
    "opportunities",
  );
  if (list.length > 1) {
    throw new Error(
      `Ambiguous leadId '${leadId}': ${list.length} opportunities match (send refused)`,
    );
  }
  return list[0] ?? null;
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
  // channelPartner relation FK (TWENTY-OPP-CHANNEL) — set directly, like companyId.
  channelPartnerId?: string;
  isEmergency?: boolean;
  lineOfBusiness?: string;
  sourceChannel?: string;
  // Provider-pipeline typed args (TWENTY-OPP-FIELDS).
  asn?: string;
  qualStatus?: string;
  // Offering segmentation SELECT (TWENTY-OPP-OFFERING).
  offering?: string;
  // Generic scalar escape hatch: already validated (existence + scalar type +
  // SELECT enum + reserved-key rejection) by the caller; spread verbatim into
  // the REST body on both create and update. Collisions with typed args are
  // rejected pre-write, so no key here can shadow one.
  customFields?: Record<string, string | number | boolean>;
}

/** Assemble a REST body from only the fields that are set (partial-update safe). */
export function buildOpportunityBody(
  f: OpportunityWriteFields,
): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  if (f.name !== undefined) body.name = f.name;
  if (f.stage !== undefined) body.stage = f.stage;
  if (f.amount !== undefined) body.amount = f.amount;
  if (f.closeDate !== undefined) body.closeDate = f.closeDate;
  if (f.pointOfContactId) body.pointOfContactId = f.pointOfContactId;
  if (f.companyId) body.companyId = f.companyId;
  if (f.channelPartnerId) body.channelPartnerId = f.channelPartnerId;
  if (f.isEmergency !== undefined) body.isEmergency = f.isEmergency;
  if (f.lineOfBusiness !== undefined) body.lineOfBusiness = f.lineOfBusiness;
  if (f.sourceChannel !== undefined) body.sourceChannel = f.sourceChannel;
  if (f.asn !== undefined) body.asn = f.asn;
  if (f.qualStatus !== undefined) body.qualStatus = f.qualStatus;
  if (f.offering !== undefined) body.offering = f.offering;
  if (f.customFields) {
    // Defense-in-depth: never let a customFields key emit a RESERVED field into
    // the body on ANY path, even though execute() already rejects reserved keys
    // pre-write. createOpportunityFull re-pins the real leadId over the body on
    // create; this guard is the equivalent belt-and-suspenders for the UPDATE
    // (PATCH) path — which sends buildOpportunityBody directly — so the
    // immutable leadId marker (and every typed-arg field) can never be
    // overwritten via the escape hatch, matching upsertRecord's matchField strip.
    for (const [k, v] of Object.entries(f.customFields)) {
      if (OPP_CUSTOMFIELDS_RESERVED.has(k)) continue;
      body[k] = v;
    }
  }
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

/**
 * Find exactly one channelPartner by its `name` natural key (TWENTY-OPP-CHANNEL).
 * Link-only resolver for upsertOpportunity's channelPartnerName arg — mirrors
 * {@link findOneCompanyByName}: throws on an ambiguous (>1) match, returns null
 * on no match or a non-filterable instance.
 */
async function findOneChannelPartnerByName(
  cfg: TwentyCfg,
  name: string,
): Promise<Record<string, unknown> | null> {
  try {
    const list = unwrapList(
      await twentyRequest(
        cfg,
        "GET",
        buildFilterPath("/rest/channelPartners", "name", name),
      ),
      "channelPartners",
    );
    if (list.length > 1) {
      throw new Error(
        `Ambiguous channelPartner name '${name}': ${list.length} matches`,
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

/**
 * Parse a micros value that a GraphQL aggregate may serialize as a JS number OR
 * a BIGINT string (CR-A-L3). Returns null for anything non-integer, so a caller
 * degrades to "no server sum" rather than trusting a bad value.
 */
export function parseMicros(v: unknown): number | null {
  if (typeof v === "number") return Number.isFinite(v) ? v : null;
  if (typeof v === "string" && /^-?\d+$/.test(v)) return Number(v);
  return null;
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
  // channelPartner relation FK (TWENTY-OPP-CHANNEL) — flat id, like companyId.
  channelPartnerId?: string;
  // Custom/segmentation SELECT fields (flat option-value scalars in Twenty REST)
  // + the emergency marker — surfaced so a reconcile can read back what a write
  // set without dropping to the Twenty UI.
  lineOfBusiness?: string;
  sourceChannel?: string;
  // Provider-pipeline custom fields (TWENTY-OPP-FIELDS): asn (TEXT) + qualStatus
  // (SELECT) — surfaced so an upsertOpportunity write is read-back verifiable.
  asn?: string;
  qualStatus?: string;
  // Offering segmentation SELECT (TWENTY-OPP-OFFERING).
  offering?: string;
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
  if (rec.channelPartnerId) {
    v.channelPartnerId = String(rec.channelPartnerId);
  }
  // Segmentation SELECTs are flat option-value strings; empty/unset => omit.
  if (rec.lineOfBusiness != null && rec.lineOfBusiness !== "") {
    v.lineOfBusiness = String(rec.lineOfBusiness);
  }
  if (rec.sourceChannel != null && rec.sourceChannel !== "") {
    v.sourceChannel = String(rec.sourceChannel);
  }
  // Provider-pipeline custom fields; empty/unset => omit (mirrors segmentation).
  if (rec.asn != null && rec.asn !== "") v.asn = String(rec.asn);
  if (rec.qualStatus != null && rec.qualStatus !== "") {
    v.qualStatus = String(rec.qualStatus);
  }
  if (rec.offering != null && rec.offering !== "") {
    v.offering = String(rec.offering);
  }
  // Surface isEmergency even when false (mirrors mapPersonView) so consumers can
  // reason about the flag without a second read.
  if (rec.isEmergency != null) v.isEmergency = Boolean(rec.isEmergency);
  return v;
}

// --- Pipeline analytics aggregation (TWENTY-DASHBOARDS) ---------------------
// Pure, PII-free aggregation over OppViews for the CRM dashboard. Reads ONLY the
// allowlisted scalar/enum fields already on OppView — never name/companyId/
// contacts. Group-bys use OBSERVED values (not a hardcoded enum list), so a
// legacy/added stage or LOB option is counted, never silently dropped (AD10).

/** Open (in-flight) pipeline stages — the Sales-pipeline board (positive set). */
export const OPEN_STAGES: readonly string[] = [
  "NEW",
  "SCREENING",
  "MEETING",
  "PROPOSAL",
];
/** Won stages: CUSTOMER (won-active) + CLOSED_WON (won-terminal), ontology §2.2. */
export const WON_STAGES: readonly string[] = ["CUSTOMER", "CLOSED_WON"];
/** Lost stage(s). */
export const LOST_STAGES: readonly string[] = ["CLOSED_LOST"];

const UNSET_LOB = "UNSET";
const UNATTRIBUTED = "UNATTRIBUTED";
const UNKNOWN_CURRENCY = "UNKNOWN";

/** Per-currency money accumulator (whole units; never cross-currency summed). */
interface AmountEntry {
  currency: string;
  amount: number;
}
interface StageBucket {
  stage: string;
  count: number;
  amounts: AmountEntry[];
}
interface LobBucket {
  lineOfBusiness: string;
  count: number;
  amounts: AmountEntry[];
}
interface ChannelBucket {
  sourceChannel: string;
  count: number;
}

/** The PII-free CRM dashboard metric set. */
export interface OppAggregates {
  totalOpps: number;
  emergencyExcluded: number;
  currencies: string[];
  byStage: StageBucket[];
  byLineOfBusiness: LobBucket[];
  bySourceChannel: ChannelBucket[];
  openPipeline: { count: number; amounts: AmountEntry[] };
  winLoss: { won: number; lost: number; winRate: number | null };
  activeCustomers: number;
}

/** Add a view's whole-unit amount into a per-currency accumulator. */
function addAmount(acc: Record<string, number>, view: OppView): void {
  if (view.amount === undefined) return;
  const cur = view.currencyCode || UNKNOWN_CURRENCY;
  acc[cur] = (acc[cur] ?? 0) + view.amount;
}

/** Freeze a per-currency accumulator into a sorted AmountEntry[]. */
function toAmounts(acc: Record<string, number>): AmountEntry[] {
  return Object.entries(acc)
    .map(([currency, amount]) => ({ currency, amount }))
    .sort((a, b) => a.currency.localeCompare(b.currency));
}

/**
 * Aggregate a set of OppViews into the PII-free dashboard metric set. Excludes
 * isEmergency opps by default (SE4 — never disclose emergency volume in an
 * aggregate a non-restricted viewer might see); pass includeEmergency to count
 * them. Findings folded: win = CUSTOMER+CLOSED_WON, lost = CLOSED_LOST, winRate
 * null on 0/0 (AD1); legacy CLOSED (or any stage) gets its own observed bucket,
 * never dropped (AD2/AD10); null sourceChannel -> UNATTRIBUTED (AD3);
 * per-currency sums, no whole-run fail-closed on mixed currency (AD11).
 */
export function aggregateOppViews(
  views: readonly OppView[],
  opts: { includeEmergency?: boolean } = {},
): OppAggregates {
  const stage = new Map<
    string,
    { count: number; amt: Record<string, number> }
  >();
  const lob = new Map<string, { count: number; amt: Record<string, number> }>();
  const chan = new Map<string, number>();
  const openAmt: Record<string, number> = {};
  const currencies = new Set<string>();
  let openCount = 0;
  let won = 0;
  let lost = 0;
  let activeCustomers = 0;
  let total = 0;
  let emergencyExcluded = 0;

  for (const v of views) {
    if (v.isEmergency && !opts.includeEmergency) {
      emergencyExcluded++;
      continue;
    }
    total++;
    if (v.currencyCode) currencies.add(v.currencyCode);
    else if (v.amount !== undefined) currencies.add(UNKNOWN_CURRENCY); // A-L4

    const sKey = v.stage || "UNSET";
    const sb = stage.get(sKey) ?? { count: 0, amt: {} };
    sb.count++;
    addAmount(sb.amt, v);
    stage.set(sKey, sb);

    const lKey = v.lineOfBusiness || UNSET_LOB;
    const lb = lob.get(lKey) ?? { count: 0, amt: {} };
    lb.count++;
    addAmount(lb.amt, v);
    lob.set(lKey, lb);

    const cKey = v.sourceChannel || UNATTRIBUTED;
    chan.set(cKey, (chan.get(cKey) ?? 0) + 1);

    if (OPEN_STAGES.includes(v.stage)) {
      openCount++;
      addAmount(openAmt, v);
    }
    if (WON_STAGES.includes(v.stage)) won++;
    if (LOST_STAGES.includes(v.stage)) lost++;
    if (v.stage === "CUSTOMER") activeCustomers++;
  }

  const winRate = (won + lost) > 0 ? won / (won + lost) : null;
  const byCount = <T extends { count: number }>(a: T, b: T) =>
    b.count - a.count;

  return {
    totalOpps: total,
    emergencyExcluded,
    currencies: [...currencies].sort(),
    byStage: [...stage.entries()]
      .map(([stage, b]) => ({
        stage,
        count: b.count,
        amounts: toAmounts(b.amt),
      }))
      .sort(byCount),
    byLineOfBusiness: [...lob.entries()]
      .map(([lineOfBusiness, b]) => ({
        lineOfBusiness,
        count: b.count,
        amounts: toAmounts(b.amt),
      }))
      .sort(byCount),
    bySourceChannel: [...chan.entries()]
      .map(([sourceChannel, count]) => ({ sourceChannel, count }))
      .sort(byCount),
    openPipeline: { count: openCount, amounts: toAmounts(openAmt) },
    winLoss: { won, lost, winRate },
    activeCustomers,
  };
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
  noteHash?: string;
  createdAt?: string;
  updatedAt?: string;
}

/**
 * Map a raw Note REST record to the compact {@link NoteView} (no body). Surfaces
 * `noteHash` — the stored KEYED HMAC of title+body (TWENTY-NOTE-RECONCILE) — when
 * present, still body-FREE: it is the reconciler's single read surface
 * (leadId + noteHash per note, never a body). The hash is a keyed HMAC (SEC-1),
 * so surfacing it is not an oracle; omitted when the note.noteHash field is
 * unprovisioned or empty (legacy notes read as "hash-unknown" on the report side,
 * ADV-6). Surfacing needs no HMAC key (returns the already-stored value, OQ3).
 */
export function mapNoteView(rec: Record<string, unknown>): NoteView {
  const v: NoteView = { id: String(rec.id ?? "") };
  const title = rec.title != null ? String(rec.title) : "";
  const m = title.match(INBOUND_LEAD_TITLE_RE); // SR-1 / CR-A-5
  if (m && validateLeadId(m[1])) v.title = title;
  if (rec.leadId != null && rec.leadId !== "") v.leadId = String(rec.leadId);
  if (rec.noteHash != null && rec.noteHash !== "") {
    v.noteHash = String(rec.noteHash);
  }
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
 * Canonical serialization of a Note's {title, body} for hashing (TWENTY-NOTE-
 * RECONCILE, OQ2/ADV-3). Pinned ONCE here and MUST be mirrored BYTE-IDENTICALLY
 * by the repo-side notes-drift report — this canonical form + the keyed-HMAC in
 * {@link hashNote} are the sole ext<->report coupling, and a shared fixture
 * vector under a NON-PRODUCTION test key is the regression guard (SEC-8: never
 * commit a real-key vector). Deterministic sorted-key JSON via canonicalJson;
 * title and body are serialized VERBATIM (NO newline normalization — note bodies
 * are stored verbatim markdown, so normalizing here would diverge the stored
 * hash from the byte content). Covering title+body folds title drift into the
 * hash so the reconciler never needs the SR-1-guarded title surfaced (ADV-3).
 */
export function canonicalNote(title: string, body: string): string {
  return canonicalJson({ title, body });
}

/**
 * Keyed HMAC-SHA256 (lowercase hex) over {@link canonicalNote} using the vault-
 * held note-hash key (TWENTY-NOTE-RECONCILE). SEC-1/SEC-2: a KEYED HMAC, NOT a
 * plain digest — so the value stored on note.noteHash and surfaced body-free on
 * listNotes is not a brute-force/confirmation oracle for low-entropy templated
 * lead-note bodies. ADV-3: covers TITLE+BODY. SEC-5 FAIL CLOSED: refuses an
 * empty key rather than hashing with an empty (public) key, which would silently
 * collapse the SEC-1/SEC-2 confidentiality. The same fail-closed guard binds the
 * repo-side report's mirrored hashNote (SEC-7).
 */
export async function hashNote(
  key: string,
  title: string,
  body: string,
): Promise<string> {
  if (!key) {
    throw new Error(
      "hashNote: refusing to compute a note hash with an empty HMAC key " +
        "(SEC-5 fail-closed) — an empty key is zero-confidentiality",
    );
  }
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    new TextEncoder().encode(canonicalNote(title, body)),
  );
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
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

// --- Email/thread read helpers (TWENTY-EMAIL) -------------------------------
//
// Twenty's message tables are channel-neutral: messageThread, message
// (subject/text/receivedAt/createdAt, receivedAt NULLABLE), messageParticipant
// (join keys personId/workspaceMemberId, NEVER a company link — company is
// transitive via person), messageThreadTarget (MORPH_RELATION with distinct
// join columns targetPersonId/targetCompanyId/targetOpportunityId), and
// messageChannelMessageAssociation (direction INCOMING|OUTGOING, joined by
// messageId; the association.message link is NULLABLE). connectedAccount and
// messageChannel are NOT REST-visible, so direction is sourced from the
// association (F8), never a connectedAccount handle comparison.
//
// PII discipline (F6/F7, mirrors mapNoteView/personRef): these helpers surface
// JOIN KEYS + non-sensitive scalars ONLY — never a raw handle/displayName, a
// subject text, or a message text/body. Subject/body are represented as
// presence + length. Participants resolve to personId/workspaceMemberId.

type MessageDirection = "INCOMING" | "OUTGOING" | "unknown";

/** A participant reduced to join keys only (NO handle/displayName — F6). */
interface ThreadParticipantKey {
  personId?: string;
  workspaceMemberId?: string;
  /** from/to/cc/bcc — a Twenty enum, not PII; kept to distinguish sender. */
  role?: string;
}

/** A body-free per-message view (subject/body as presence+length — F6). */
interface MessageView {
  id: string;
  direction: MessageDirection;
  subjectPresent: boolean;
  subjectLength: number;
  bodyLength: number;
  participants: ThreadParticipantKey[];
  receivedAt?: string;
  createdAt?: string;
}

// The REST plural for the direction-carrying association object.
const MSG_ASSOC_PLURAL = "messageChannelMessageAssociations";

/**
 * The message's effective chronology timestamp: receivedAt when present, else
 * the non-null createdAt fallback (F15 — receivedAt is NULLABLE for unsynced /
 * outbound rows). ISO-8601 strings sort lexicographically, so callers order by
 * this coalesced value client-side rather than trusting a nullable-column sort.
 * Returns "" only when a row somehow carries neither timestamp.
 */
export function messageTs(m: Record<string, unknown>): string {
  const r = m.receivedAt;
  if (r != null && String(r) !== "") return String(r);
  const c = m.createdAt;
  if (c != null && String(c) !== "") return String(c);
  return "";
}

/**
 * The genuinely-last message of a set by coalesced {@link messageTs} (F15),
 * with the id as a stable tiebreaker. Null-safe: a null-receivedAt row whose
 * createdAt is later correctly wins over an earlier receivedAt row. Returns
 * null for an empty set.
 */
export function pickLastMessage(
  items: Array<Record<string, unknown>>,
): Record<string, unknown> | null {
  let best: Record<string, unknown> | null = null;
  let bestTs = "";
  let bestId = "";
  for (const m of items) {
    const ts = messageTs(m);
    const id = String(m.id ?? "");
    if (best === null || ts > bestTs || (ts === bestTs && id > bestId)) {
      best = m;
      bestTs = ts;
      bestId = id;
    }
  }
  return best;
}

/**
 * Derive a thread's follow-up state from its last message. Direction is
 * AUTHORITATIVE (from the association, F8) — an unknown direction yields
 * 'unknown' rather than a guess (a wrong guess could imply an errant outbound).
 * OUTGOING last => we are waiting on them: 'sent-unanswered' while fresh,
 * 'dormant' once older than dormantDays. INCOMING last => 'awaiting-us'. No
 * messages => 'empty'. Pure (no I/O) so the state machine is unit-testable.
 */
export function deriveThreadState(
  lastDirection: MessageDirection,
  ageDays: number | null,
  dormantDays: number,
  messageCount: number,
): "awaiting-us" | "sent-unanswered" | "dormant" | "empty" | "unknown" {
  if (messageCount <= 0) return "empty";
  if (lastDirection === "unknown") return "unknown";
  if (lastDirection === "INCOMING") return "awaiting-us";
  // OUTGOING: we sent last.
  if (ageDays != null && ageDays > dormantDays) return "dormant";
  return "sent-unanswered";
}

/**
 * Direction for a message from messageChannelMessageAssociation.direction,
 * joined by messageId (F8). Returns 'unknown' when no association exists or the
 * association carries no direction (the association.message link is nullable) —
 * NEVER a guess. messageId is a server-derived UUID; guarded with isFilterSafe
 * before any filter interpolation (F11) as defense-in-depth.
 */
async function fetchMessageDirection(
  cfg: TwentyCfg,
  messageId: string,
): Promise<MessageDirection> {
  if (!isFilterSafe(messageId)) return "unknown";
  const json = await twentyRequest(
    cfg,
    "GET",
    buildFilterPath(`/rest/${MSG_ASSOC_PLURAL}`, "messageId", messageId),
  );
  const assoc = unwrapList(json, MSG_ASSOC_PLURAL)[0];
  const d = assoc?.direction;
  if (d === "INCOMING" || d === "OUTGOING") return d;
  return "unknown";
}

/**
 * A message's participants reduced to join keys (F6): personId /
 * workspaceMemberId (+ the non-PII role enum). NEVER the raw handle or
 * displayName. There is no company link on messageParticipant (company is
 * transitive via person). messageId guarded with isFilterSafe (F11).
 */
async function fetchMessageParticipantKeys(
  cfg: TwentyCfg,
  messageId: string,
): Promise<ThreadParticipantKey[]> {
  if (!isFilterSafe(messageId)) return [];
  const json = await twentyRequest(
    cfg,
    "GET",
    buildFilterPath("/rest/messageParticipants", "messageId", messageId),
  );
  const list = unwrapList(json, "messageParticipants");
  const out: ThreadParticipantKey[] = [];
  for (const p of list) {
    const key: ThreadParticipantKey = {};
    if (p.personId != null && p.personId !== "") {
      key.personId = String(p.personId);
    }
    if (p.workspaceMemberId != null && p.workspaceMemberId !== "") {
      key.workspaceMemberId = String(p.workspaceMemberId);
    }
    if (p.role != null && p.role !== "") key.role = String(p.role);
    // Never emit handle/displayName (F6). A role-only external participant is
    // kept so the message's shape is visible, but carries no identifying data.
    if (key.personId || key.workspaceMemberId || key.role) out.push(key);
  }
  return out;
}

/** Page a thread's messages (filter=messageThreadId). Gap-free createdAt,id
 * order for the cursor; chronology (receivedAt-coalesced) is applied
 * client-side (F15). threadId must be validated + filter-safe by the caller. */
async function fetchThreadMessagesPage(
  cfg: TwentyCfg,
  threadId: string,
  cap: number,
  startingAfter?: string,
): Promise<ListPage> {
  return await listFiltered(
    cfg,
    "messages",
    [`messageThreadId[eq]:${encodeURIComponent(threadId)}`],
    cap,
    LIST_ORDER,
    startingAfter,
  );
}

// Recent-first message order for LAST-MESSAGE / STATUS derivation (EMAIL-ORD-1).
// receivedAt is the primary chronology but NULLABLE (unsynced/outbound rows), so
// DescNullsLast keeps null-receivedAt rows from sorting to the front; createdAt +
// id give a gap-free descending tiebreak. Fetching newest-first means the HEAD
// page holds the true last message even when a thread exceeds the per-call cap —
// a plain ascending read (LIST_ORDER) returned the OLDEST N and inverted the
// derived direction/status. Constant DSL (bracket-modifier order_by; commas are
// the literal key separator, no injection risk).
// Lead with the NON-NULL createdAt (ORD-1-R): receivedAt is nullable (a
// just-sent OUTBOUND reply commonly has receivedAt=null), and a
// receivedAt-led DescNullsLast would bury that true-newest message past the
// cap, re-inverting the threadStatus verdict. A createdAt-led head holds the
// true last message EXCEPT when receivedAt and createdAt diverge across the cap
// boundary (future-dated/clock-skewed or late-backfilled rows where
// receivedAt > createdAt) — pickLastMessage orders by the coalesced
// (receivedAt ?? createdAt) value, so that rare case can still pick a
// head-page neighbour; every such read is capped and therefore flagged
// truncated=true (a lower-confidence verdict), never presented as authoritative.
// A fuller fix needs server-side ordering on the coalesced value (no single
// Twenty column) or a full-thread read. Mirrors THREAD_RECENT_ORDER.
const MSG_RECENT_ORDER =
  "createdAt[DescNullsLast],receivedAt[DescNullsLast],id[DescNullsLast]";

/** Page a thread's messages NEWEST-first for last-message/status derivation
 * (EMAIL-ORD-1). The head page holds the true last even past the cap; callers
 * pick it with {@link pickLastMessage} and MUST surface page.truncated/hasMore so
 * a capped read never presents as authoritative. getThread keeps the ascending
 * {@link fetchThreadMessagesPage} for its full oldest->newest listing. threadId
 * must be validated + filter-safe by the caller. */
async function fetchThreadRecentMessagesPage(
  cfg: TwentyCfg,
  threadId: string,
  cap: number,
  startingAfter?: string,
): Promise<ListPage> {
  return await listFiltered(
    cfg,
    "messages",
    [`messageThreadId[eq]:${encodeURIComponent(threadId)}`],
    cap,
    MSG_RECENT_ORDER,
    startingAfter,
  );
}

/**
 * Enrich raw message records into body-free {@link MessageView}s, resolving
 * direction (association) and participant join keys per message. Returns the
 * raw record + coalesced ts alongside each view so callers can order
 * client-side (F15) without re-reading.
 */
async function enrichThreadMessages(
  cfg: TwentyCfg,
  rawItems: Array<Record<string, unknown>>,
): Promise<
  Array<{ raw: Record<string, unknown>; view: MessageView; ts: string }>
> {
  const out: Array<
    { raw: Record<string, unknown>; view: MessageView; ts: string }
  > = [];
  for (const m of rawItems) {
    const id = validateUuid(m.id);
    const direction = id ? await fetchMessageDirection(cfg, id) : "unknown";
    const participants = id ? await fetchMessageParticipantKeys(cfg, id) : [];
    const subject = m.subject != null ? String(m.subject) : "";
    const text = m.text != null ? String(m.text) : "";
    const view: MessageView = {
      id: String(m.id ?? ""),
      direction,
      subjectPresent: subject.length > 0,
      subjectLength: subject.length,
      bodyLength: text.length,
      participants,
    };
    if (m.receivedAt != null && String(m.receivedAt) !== "") {
      view.receivedAt = String(m.receivedAt);
    }
    if (m.createdAt != null && String(m.createdAt) !== "") {
      view.createdAt = String(m.createdAt);
    }
    out.push({ raw: m, view, ts: messageTs(m) });
  }
  return out;
}

// Recent-first order for a workspace-wide thread scan (createdAt is non-null,
// so DescNullsLast == plain descending; id tiebreaker keeps the cursor
// gap-free). Bracket-modifier order_by form per the Phase-0 findings.
const THREAD_RECENT_ORDER = "createdAt[DescNullsLast],id[DescNullsLast]";

type ThreadTargetKind =
  | "opportunity"
  | "person"
  | "company"
  | "leadId"
  | "workspace";

/** A resolved messageThreadTarget filter selection (F18). */
interface ResolvedThreadTarget {
  kind: ThreadTargetKind;
  id?: string;
  resolvedKind?: "opportunity" | "person" | "company";
  resolvedId?: string;
  field?: "targetOpportunityId" | "targetPersonId" | "targetCompanyId";
  found: boolean;
}

interface ThreadTargetArgs {
  opportunityId?: string;
  personId?: string;
  companyId?: string;
  leadId?: string;
}

/**
 * Resolve the caller's target into the correct polymorphic messageThreadTarget
 * filter field + a VALIDATED UUID (F18/F11): opportunity->targetOpportunityId,
 * person->targetPersonId, company->targetCompanyId. At most one target may be
 * given (else throw). A leadId is resolved to its opportunity first, then its
 * person (mirrors findOpportunityByLeadId/findPersonByLeadId); found:false when
 * neither exists. No target => a recent workspace-wide scan. Every resolvedId
 * is UUID-validated here so it can never interpolate an unvalidated id into a
 * filter, and an opportunity id can never filter a person field.
 */
async function resolveThreadTarget(
  cfg: TwentyCfg,
  args: ThreadTargetArgs,
  // EMAIL-TE-4: the send path passes strictLeadId to REFUSE an ambiguous
  // leadId->opportunity match; read methods leave it off (tolerant first-match).
  opts?: { strictLeadId?: boolean },
): Promise<ResolvedThreadTarget> {
  const has = (v: unknown) => v != null && String(v).trim() !== "";
  const provided: ThreadTargetKind[] = [];
  if (has(args.opportunityId)) provided.push("opportunity");
  if (has(args.personId)) provided.push("person");
  if (has(args.companyId)) provided.push("company");
  if (has(args.leadId)) provided.push("leadId");
  if (provided.length > 1) {
    throw new Error(
      "Provide at most one of opportunityId|personId|companyId|leadId",
    );
  }
  if (provided.length === 0) return { kind: "workspace", found: true };

  const which = provided[0];
  if (which === "opportunity" || which === "person" || which === "company") {
    const raw = which === "opportunity"
      ? args.opportunityId
      : which === "person"
      ? args.personId
      : args.companyId;
    const id = validateUuid(raw);
    if (!id) throw new Error(`Invalid ${which}Id (must be a UUID)`);
    const field = which === "opportunity"
      ? "targetOpportunityId"
      : which === "person"
      ? "targetPersonId"
      : "targetCompanyId";
    return {
      kind: which,
      id,
      resolvedKind: which,
      resolvedId: id,
      field,
      found: true,
    };
  }

  // leadId: resolve to the opportunity first, else the person.
  const leadId = validateLeadId(args.leadId);
  if (!leadId) throw new Error("Invalid leadId");
  const opp = opts?.strictLeadId
    ? await findOpportunityByLeadIdStrict(cfg, leadId)
    : await findOpportunityByLeadId(cfg, leadId);
  const oppId = opp ? validateUuid(opp.id) : null;
  if (oppId) {
    return {
      kind: "leadId",
      id: leadId,
      resolvedKind: "opportunity",
      resolvedId: oppId,
      field: "targetOpportunityId",
      found: true,
    };
  }
  const person = await findPersonByLeadId(cfg, leadId);
  const personId = person ? validateUuid(person.id) : null;
  if (personId) {
    return {
      kind: "leadId",
      id: leadId,
      resolvedKind: "person",
      resolvedId: personId,
      field: "targetPersonId",
      found: true,
    };
  }
  return { kind: "leadId", id: leadId, found: false };
}

/**
 * Resolve the set of thread ids for a target (F18): a filtered
 * messageThreadTarget scan per the correct join column, or a recent
 * workspace-wide messageThread scan when there is no target. Thread ids are
 * UUID-validated before use. Returns the ListPage so the caller surfaces the
 * paging/completeness envelope.
 */
async function fetchThreadIdsForTarget(
  cfg: TwentyCfg,
  resolved: ResolvedThreadTarget,
  cap: number,
  startingAfter?: string,
): Promise<{ ids: string[]; page: ListPage }> {
  const seen = new Set<string>();
  const ids: string[] = [];
  if (resolved.kind === "workspace") {
    const page = await listFiltered(
      cfg,
      "messageThreads",
      [],
      cap,
      THREAD_RECENT_ORDER,
      startingAfter,
    );
    for (const t of page.items) {
      const tid = validateUuid(t.id);
      if (tid && !seen.has(tid)) {
        seen.add(tid);
        ids.push(tid);
      }
    }
    return { ids, page };
  }
  const field = resolved.field;
  const rid = resolved.resolvedId;
  if (!field || !rid || !isFilterSafe(rid)) {
    throw new Error("Unresolvable or unsafe thread target");
  }
  const page = await listFiltered(
    cfg,
    "messageThreadTargets",
    [`${field}[eq]:${encodeURIComponent(rid)}`],
    cap,
    LIST_ORDER,
    startingAfter,
  );
  for (const t of page.items) {
    const tid = validateUuid(t.messageThreadId);
    if (tid && !seen.has(tid)) {
      seen.add(tid);
      ids.push(tid);
    }
  }
  return { ids, page };
}

// GraphQL field selection for an Opportunity row — the allowlisted analytics
// fields only (never name/contacts). `amount` is Twenty's CURRENCY composite,
// selected as its {amountMicros, currencyCode} subfields so mapOppView's
// extractAmount consumes the GraphQL node exactly like a REST record.
const OPP_AGG_NODE_FIELDS =
  "id stage amount { amountMicros currencyCode } lineOfBusiness sourceChannel isEmergency";

/**
 * GraphQL-primary acquisition (TWENTY-DASHBOARDS): page the full Opportunity set
 * over the Core GraphQL `opportunities` connection (Relay `first`/`after`),
 * selecting only the allowlisted analytics fields. Also returns the connection's
 * server-side `totalCount` + `sumAmountAmountMicros` (all-currency micros sum) so
 * the caller can cross-check its in-extension aggregation. Node shape matches a
 * REST opportunity record for the fields we read, so callers map with mapOppView.
 * Throws (caller-redacts) on any GraphQL failure so acquisition can fall back to
 * REST. Verified live on v2.38.1 (sumAmountAmountMicros == in-extension sum).
 *
 * `truncated` is honest: it is true whenever the loop stops while the server
 * still reports more pages — a page-count backstop OR a broken/repeat cursor
 * (never a false "complete", CR-A-H1). Rows are deduped by id across page
 * boundaries (CR-A-M1). Pages until hasNextPage is false (a full aggregate up to
 * the ~MAX_AGG_PAGES*60 backstop), not an artificial record cap (CR-A-M2).
 */
export async function acquireOppRowsGraphQL(cfg: TwentyCfg): Promise<{
  rows: Array<Record<string, unknown>>;
  truncated: boolean;
  serverTotalCount: number | null;
  serverSumMicros: number | null;
}> {
  const rows: Array<Record<string, unknown>> = [];
  const seen = new Set<string>();
  let after: string | null = null;
  let serverTotalCount: number | null = null;
  let serverSumMicros: number | null = null;
  let pages = 0;
  const PAGE = 60; // Twenty caps a page at 60.
  const MAX_AGG_PAGES = 200; // backstop: ~12k opps before we bail as truncated.
  const query =
    `query($first:Int,$after:String){ opportunities(first:$first, after:$after){ totalCount sumAmountAmountMicros edges { node { ${OPP_AGG_NODE_FIELDS} } } pageInfo { hasNextPage endCursor } } }`;
  for (;;) {
    const data = await twentyGraphQL(cfg, query, { first: PAGE, after });
    const conn = data.opportunities as {
      totalCount?: number;
      sumAmountAmountMicros?: number | string;
      edges?: Array<{ node?: Record<string, unknown> }>;
      pageInfo?: { hasNextPage?: boolean; endCursor?: string };
    } | undefined;
    if (!conn) throw new Error("GraphQL opportunities returned no connection");
    if (typeof conn.totalCount === "number") serverTotalCount = conn.totalCount;
    // amountMicros can serialize as a BIGINT string; accept both (CR-A-L3).
    const sm = parseMicros(conn.sumAmountAmountMicros);
    if (sm !== null) serverSumMicros = sm;
    for (const e of conn.edges ?? []) {
      const node = e?.node;
      if (!node) continue;
      const id = typeof node.id === "string" ? node.id : "";
      if (id) {
        if (seen.has(id)) continue; // cross-page overlap dedup (CR-A-M1)
        seen.add(id);
      }
      rows.push(node);
    }
    pages++;
    const more = Boolean(conn.pageInfo?.hasNextPage);
    if (!more) {
      return { rows, truncated: false, serverTotalCount, serverSumMicros };
    }
    // The server says there is more. If the cursor is unusable (absent/repeat)
    // or we hit the page backstop, stop but report truncated=true — never a
    // silent partial claiming completeness (CR-A-H1).
    const next = conn.pageInfo?.endCursor;
    if (!next || next === after || pages >= MAX_AGG_PAGES) {
      return { rows, truncated: true, serverTotalCount, serverSumMicros };
    }
    after = next;
  }
}

/**
 * Read the Opportunity object's live metadata: the `stage` SELECT enum values,
 * the segmentation SELECT enums (`lineOfBusiness`, `sourceChannel`, `offering`),
 * the `qualStatus` enum, and the `closeDate` field type (DATE vs DATE_TIME). Used
 * to fail fast on an invalid stage / segmentation token and to format closeDate
 * correctly for the instance.
 */
async function fetchOpportunityMeta(
  cfg: TwentyCfg,
): Promise<{
  stages: string[];
  closeDateType: string | null;
  lineOfBusiness: string[];
  sourceChannel: string[];
  qualStatus: string[];
  offering: string[];
  // Full name → {type, SELECT-option values} map for EVERY opportunity field
  // (TWENTY-OPP-FIELDS F3): the ungated field-map that qualStatus AND every
  // customFields key are validated through. NOT restricted by
  // UPSERT_OBJECT_ALLOWLIST (that allowlist governs upsertRecord's arbitrary
  // objects; opportunity is a first-class typed target here).
  fields: Map<string, { type: string; options: string[] }>;
}> {
  const objs = await fetchObjectsMeta(cfg);
  const opp = objs.find((o) => String(o.nameSingular ?? "") === "opportunity");
  const fieldList = (opp?.fields ?? []) as Array<Record<string, unknown>>;
  const list = Array.isArray(fieldList) ? fieldList : [];
  // Extract a SELECT field's option value tokens (value ?? label), the same way
  // stage validation has always read them — shared so stage and the
  // segmentation/qualification fields cannot drift.
  const optionValues = (fieldName: string): string[] => {
    const f = list.find((x) => String(x.name ?? "") === fieldName);
    const opts = (f?.options ?? []) as Array<Record<string, unknown>>;
    return Array.isArray(opts)
      ? opts.map((o) => String(o.value ?? o.label ?? "")).filter(Boolean)
      : [];
  };
  // name → {type, options} for every field, built from the SAME metadata read
  // (no extra API call) — the field-map customFields/qualStatus validate against.
  const fields = new Map<string, { type: string; options: string[] }>();
  for (const f of list) {
    const name = String(f.name ?? "");
    if (!name) continue;
    const opts = (f.options ?? []) as Array<Record<string, unknown>>;
    const options = Array.isArray(opts)
      ? opts.map((o) => String(o.value ?? o.label ?? "")).filter(Boolean)
      : [];
    fields.set(name, { type: String(f.type ?? ""), options });
  }
  const stages = optionValues("stage");
  const lineOfBusiness = optionValues("lineOfBusiness");
  const sourceChannel = optionValues("sourceChannel");
  const qualStatus = optionValues("qualStatus");
  const offering = optionValues("offering");
  const cdField = list.find((f) => String(f.name ?? "") === "closeDate");
  const closeDateType = cdField ? (String(cdField.type ?? "") || null) : null;
  return {
    stages,
    closeDateType,
    lineOfBusiness,
    sourceChannel,
    qualStatus,
    offering,
    fields,
  };
}

// --- Email SEND subsystem (TWENTY-EMAIL send) -------------------------------
//
// Sending is Twenty's native "Send Email" workflow action, invoked via the
// runWorkflowVersion mutation with a resolved, NON-EMPTY connectedAccountId in
// the trigger payload (F1). Two hard facts drive this design:
//
//  1. The API_KEY apiToken is FORBIDDEN on runWorkflowVersion + myConnected-
//     Accounts (both carry a UserAuthGuard). So the send path mints a per-run
//     workspace-member USER access token from vaulted email+password (login ->
//     access token), uses it as the Bearer for those two calls, and discards it.
//  2. runWorkflowVersion is fire-and-forget: it returns ONLY {workflowRunId} —
//     no synchronous messageId/threadId (F13). Send success is NOT synchronously
//     confirmable; sendRun records the workflowRunId + inputs, never a sent id.
//
// Fail-closed identity is the whole point: an empty/ambiguous connectedAccountId,
// an unmapped explicit fromBrand (F4), a non-opp/null-LoB target with no explicit
// fromBrand (F5), a live-missing id (F3), or a domain mismatch (F3) each REFUSE
// before any send. PII discipline mirrors the read layer: the sendRun audit
// stores JOIN KEYS + connectedAccountId + a hashed recipient (never the raw `to`)
// + subject/body LENGTHS (never the text) (F6/F7).

/** Full lowercase-hex SHA-256 of `input` (used for dedup keys + recipient hash). */
export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * The DOMAIN part of a mail handle (lowercased), or "" — the ONLY slice of a
 * connected-account handle we ever keep (brand-matching + the PII-conservative
 * connectedAccountList snapshot). Never returns the local-part / full handle.
 */
export function handleDomain(handle: unknown): string {
  if (handle == null) return "";
  const s = String(handle).trim().toLowerCase();
  const at = s.lastIndexOf("@");
  if (at === -1) return "";
  return s.slice(at + 1);
}

/**
 * Validate the brand->connectedAccountId map at load (F14): every value must be a
 * non-empty UUID and no two brands may point at the SAME connectedAccountId
 * (duplicate = ambiguous identity). Returns a human error string, or null when
 * the map is valid (an empty map is valid — it just means no brand resolves).
 */
export function validateBrandMap(map: Record<string, unknown>): string | null {
  const seen = new Map<string, string>();
  for (const [brand, raw] of Object.entries(map ?? {})) {
    const cid = validateUuid(raw);
    if (!cid) {
      return `brandConnectedAccounts['${brand}'] is not a non-empty UUID`;
    }
    const prior = seen.get(cid);
    if (prior) {
      return `brandConnectedAccounts['${brand}'] duplicates the connectedAccountId already mapped to '${prior}'`;
    }
    seen.set(cid, brand);
  }
  return null;
}

/** Outcome of the pure brand->connectedAccountId resolution (F3/F4/F5/F14). */
export type BrandResolution =
  | {
    ok: true;
    brand: string;
    connectedAccountId: string;
    source: "explicit" | "lob-default";
  }
  | { ok: false; reason: string };

/**
 * Resolve exactly one connectedAccountId to send from, fail-closed (pure, so the
 * refusal matrix is unit-testable without I/O):
 *  - explicit fromBrand: MUST be in brandMap (F4 — an unmapped explicit brand is a
 *    HARD REFUSE, never a fall-through to the LoB default). Its mapped id must be a
 *    non-empty UUID (an empty/ambiguous id is a HARD REFUSE).
 *  - absent fromBrand: the per-lineOfBusiness default applies ONLY to an
 *    Opportunity target with a NON-EMPTY lineOfBusiness (F5). Every other target
 *    (person/company/leadId-> person/null-LoB opp/workspace) REFUSES.
 * The live existence + domain-match re-check (F3) happens at send time, not here.
 */
export function resolveBrandForSend(input: {
  fromBrand?: string;
  targetKind: string | null;
  lineOfBusiness?: string | null;
  brandMap: Record<string, string>;
  lobMap: Record<string, string>;
}): BrandResolution {
  const brandMap = input.brandMap ?? {};
  const fromBrand = (input.fromBrand ?? "").trim();
  if (fromBrand) {
    if (!Object.prototype.hasOwnProperty.call(brandMap, fromBrand)) {
      return {
        ok: false,
        reason:
          `fromBrand '${fromBrand}' is not in brandConnectedAccounts — hard refuse (F4), never falls through to a default`,
      };
    }
    const cid = validateUuid(brandMap[fromBrand]);
    if (!cid) {
      return {
        ok: false,
        reason:
          `brandConnectedAccounts['${fromBrand}'] is empty/ambiguous (not a UUID) — hard refuse`,
      };
    }
    return {
      ok: true,
      brand: fromBrand,
      connectedAccountId: cid,
      source: "explicit",
    };
  }
  // No explicit brand: the LoB default is opp-only, non-empty-LoB-only (F5).
  const lob = (input.lineOfBusiness ?? "").trim();
  if (input.targetKind === "opportunity" && lob) {
    const lobMap = input.lobMap ?? {};
    const brand = (lobMap[lob] ?? "").trim();
    if (!brand) {
      return {
        ok: false,
        reason:
          `lineOfBusiness '${lob}' has no lineOfBusinessBrand default — supply an explicit fromBrand`,
      };
    }
    const cid = validateUuid(brandMap[brand]);
    if (!cid) {
      return {
        ok: false,
        reason:
          `default brand '${brand}' (from lineOfBusiness '${lob}') has no valid connectedAccountId — hard refuse`,
      };
    }
    return { ok: true, brand, connectedAccountId: cid, source: "lob-default" };
  }
  return {
    ok: false,
    reason:
      "no fromBrand and no per-lineOfBusiness default applies (target is not an Opportunity with a non-empty lineOfBusiness) — explicit fromBrand required (F5)",
  };
}

// --- USER-token GraphQL transport (send/auth only) --------------------------
// A DELIBERATE mutation-capable POST — distinct from the read-only, guarded
// twentyGraphQL. `query` is always an in-code constant literal built in this
// module; never caller-supplied. Throws (caller redacts) on non-2xx or a GraphQL
// `errors` array. Never echoes the request body (which may carry credentials).

async function postGraphQLRaw(
  url: string,
  query: string,
  variables: Record<string, unknown>,
  bearer?: string,
  // TE-1/TE-2: when set, thrown errors carry ONLY status/statusText under this
  // label — NEVER the response body slice or GraphQL errors[].message text. The
  // auth mint (sendUserPassword) and workflow send (raw to/subject/body) submit
  // secrets/PII in the request; Twenty may echo them in a 4xx body, and Rule 11
  // captures thrown errors into durable reports — so those callers pass a label.
  label?: string,
): Promise<Record<string, unknown>> {
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      "Accept": "application/json",
      "Content-Type": "application/json",
      ...(bearer ? { "Authorization": `Bearer ${bearer}` } : {}),
    },
    body: JSON.stringify({ query, variables }),
  });
  const text = await resp.text();
  if (!resp.ok) {
    if (label) {
      // Drop the body entirely — status/statusText only.
      throw new Error(`${label}: HTTP ${resp.status} ${resp.statusText}`);
    }
    // The response body may echo submitted values; slice + let the caller redact.
    throw new Error(
      `Twenty send GraphQL failed: ${resp.status} ${resp.statusText} — ${
        text.slice(0, 200)
      }`,
    );
  }
  const json = (text ? JSON.parse(text) : {}) as {
    data?: Record<string, unknown>;
    errors?: Array<{ message?: string }>;
  };
  if (json.errors && json.errors.length > 0) {
    if (label) {
      // GraphQL errors[].message can echo the submitted input — suppress it.
      throw new Error(`${label}: HTTP ${resp.status} ${resp.statusText}`);
    }
    const msg = json.errors.map((e) => e?.message ?? "").join("; ");
    throw new Error(`Twenty send GraphQL errors: ${msg.slice(0, 200)}`);
  }
  return json.data ?? {};
}

const LOGIN_TOKEN_MUTATION =
  `mutation($email:String!,$password:String!,$origin:String!){ getLoginTokenFromCredentials(input:{email:$email,password:$password}, origin:$origin){ loginToken } }`;
const AUTH_TOKENS_MUTATION =
  `mutation($loginToken:String!,$origin:String!){ getAuthTokensFromLoginToken(input:{loginToken:$loginToken}, origin:$origin){ tokens { accessOrWorkspaceAgnosticToken { token expiresAt } refreshToken { token expiresAt } } } }`;
const MY_CONNECTED_ACCOUNTS_QUERY =
  `query { myConnectedAccounts { id handle provider authFailedAt archivedAt } }`;
const RUN_WORKFLOW_VERSION_MUTATION =
  `mutation($input:RunWorkflowVersionInput!){ runWorkflowVersion(input:$input){ workflowRunId } }`;

/**
 * Mint a fresh, per-run workspace-member USER access token (F1b) from the vaulted
 * send credentials via the two public core-/graphql mutations
 * (getLoginTokenFromCredentials -> getAuthTokensFromLoginToken). Returns the
 * 30-min `accessOrWorkspaceAgnosticToken` (carries user context); the refresh
 * token is intentionally discarded (no rotation/write-back). FAIL-CLOSED: any
 * missing credential or missing token throws — a caller must NEVER fall through
 * to a send on a mint failure. The password/token are never logged or persisted;
 * thrown messages carry neither.
 */
export async function mintUserAccessToken(cfg: GlobalArgs): Promise<string> {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const origin = (cfg.twentyOrigin ?? "").trim() || base;
  const email = (cfg.sendUserEmail ?? "").trim();
  const password = cfg.sendUserPassword ?? "";
  if (!email || !password) {
    throw new Error(
      "send subsystem is not configured: sendUserEmail/sendUserPassword are empty (fail-closed)",
    );
  }
  const d1 = await postGraphQLRaw(
    `${base}/graphql`,
    LOGIN_TOKEN_MUTATION,
    {
      email,
      password,
      origin,
    },
    undefined,
    "credential mint failed",
  );
  const loginToken =
    (d1.getLoginTokenFromCredentials as Record<string, unknown> | undefined)
      ?.loginToken;
  if (!loginToken || typeof loginToken !== "string") {
    throw new Error("token mint step 1 returned no loginToken (fail-closed)");
  }
  const d2 = await postGraphQLRaw(
    `${base}/graphql`,
    AUTH_TOKENS_MUTATION,
    {
      loginToken,
      origin,
    },
    undefined,
    "credential mint failed",
  );
  const tokens =
    (d2.getAuthTokensFromLoginToken as Record<string, unknown> | undefined)
      ?.tokens as Record<string, unknown> | undefined;
  const access = (
    tokens?.accessOrWorkspaceAgnosticToken as
      | Record<string, unknown>
      | undefined
  )?.token;
  if (!access || typeof access !== "string") {
    throw new Error("token mint step 2 returned no access token (fail-closed)");
  }
  return access;
}

/** A live connected account reduced to non-sensitive fields (domain-only). */
export interface ConnectedAccountLite {
  id: string;
  provider: string;
  /** DOMAIN of the handle only — never the local-part / full handle (F6). */
  domain: string;
  authFailed: boolean;
  archived: boolean;
}

/**
 * The calling USER's own connected accounts via /metadata `myConnectedAccounts`
 * (SELF-SCOPED — there is no admin "list all"; the design assumes ONE sending
 * service user owns every brand mailbox, so its accounts enumerate them all).
 * Reduces each row to id/provider/domain-only + authFailed/archived booleans; the
 * raw handle is split at '@' and discarded (F6).
 */
export async function fetchConnectedAccounts(
  cfg: GlobalArgs,
  userToken: string,
): Promise<ConnectedAccountLite[]> {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const data = await postGraphQLRaw(
    `${base}/metadata`,
    MY_CONNECTED_ACCOUNTS_QUERY,
    {},
    userToken,
  );
  const rows = Array.isArray(data.myConnectedAccounts)
    ? (data.myConnectedAccounts as Array<Record<string, unknown>>)
    : [];
  return rows.map((r) => ({
    id: String(r.id ?? ""),
    provider: String(r.provider ?? ""),
    domain: handleDomain(r.handle),
    authFailed: r.authFailedAt != null && String(r.authFailedAt) !== "",
    archived: r.archivedAt != null && String(r.archivedAt) !== "",
  }));
}

/**
 * Resolve the ACTIVE/published version id of the named Send-Email workflow over
 * REST + the API_KEY token (F12 — never pin a version id). GET /rest/workflows
 * filtered by name, read lastPublishedVersionId. Returns null when the workflow
 * is absent or has no published version (the caller REFUSES the send).
 */
export async function resolveActiveWorkflowVersionId(
  cfg: GlobalArgs,
  workflowName: string,
): Promise<string | null> {
  const name = sanitizeText(workflowName, 120);
  if (!name || !isFilterSafe(name)) return null;
  const json = await twentyRequest(
    cfg,
    "GET",
    buildFilterPath("/rest/workflows", "name", name),
  );
  const list = unwrapList(json, "workflows");
  // EMAIL-WF-1: a duplicate workflow NAME is ambiguous — refuse loudly rather
  // than taking the first row (an operator mistake could point the send at the
  // wrong workflow). The caller refuses the send on the thrown error.
  if (list.length > 1) {
    throw new Error(
      `Ambiguous Send-Email workflow name '${name}': ${list.length} matches (refused)`,
    );
  }
  for (const wf of list) {
    const vid = validateUuid(wf.lastPublishedVersionId);
    if (vid) return vid;
  }
  return null;
}

/**
 * Invoke the Send-Email workflow version via runWorkflowVersion (core /graphql,
 * USER token). The caller `payload` becomes the manual-trigger output the send
 * step reads connectedAccountId/to/subject/body from (F1). Returns ONLY the
 * workflowRunId (fire-and-forget; no messageId/threadId — F13).
 */
export async function runSendWorkflow(
  cfg: GlobalArgs,
  userToken: string,
  workflowVersionId: string,
  payload: Record<string, unknown>,
): Promise<string> {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const data = await postGraphQLRaw(
    `${base}/graphql`,
    RUN_WORKFLOW_VERSION_MUTATION,
    { input: { workflowVersionId, payload } },
    userToken,
    // TE-2: the payload carries raw to/subject/body — never ride it back through
    // a thrown/sliced response body.
    "send enqueue failed",
  );
  const runId = (data.runWorkflowVersion as Record<string, unknown> | undefined)
    ?.workflowRunId;
  if (!runId || typeof runId !== "string") {
    throw new Error("runWorkflowVersion returned no workflowRunId");
  }
  return runId;
}

/**
 * The DURABLE, cross-run dedup marker id for a dedupKey (F9/F10). The dedupKey is
 * hashed so the marker is ALWAYS filter-safe hex regardless of a caller-supplied
 * key, and namespaced under `send-` so it never collides with a lead marker. The
 * marker is a body-free Note stored in the Note TITLE as `sent:<markerId>` and
 * queried by that title (EMAIL-DEDUP-1) — deliberately NOT on the leadId field,
 * so a leadId-keyed reconciliation can never mistake it for a real lead note.
 */
export async function sendDedupMarkerId(dedupKey: string): Promise<string> {
  return "send-" + await sha256Hex(dedupKey);
}

/**
 * Compute the dedupKey when the caller supplies none (F9): a hash over the
 * recipient + connectedAccountId + reply-thread + a COARSE (UTC-day) time bucket
 * + subject + body. A deliberate identical resend within the same day needs a
 * distinct caller-supplied dedupKey (documented). `now` is injectable for tests.
 */
export async function computeDedupKey(input: {
  to: string;
  connectedAccountId: string;
  inReplyToThreadId?: string;
  subject: string;
  body: string;
  now?: Date;
}): Promise<string> {
  const bucket = (input.now ?? new Date()).toISOString().slice(0, 10); // UTC day
  const parts = [
    input.to,
    input.connectedAccountId,
    input.inReplyToThreadId ?? "",
    bucket,
    input.subject,
    input.body,
  ];
  // TE-3: JSON.stringify gives an unambiguous, injective field boundary (fields
  // are already sanitized) so distinct part sets can never merge - replaces a
  // raw-NUL join that was ASCII-illegal and tooling-hostile.
  return await sha256Hex(JSON.stringify(parts));
}

/**
 * Query the durable dedup store for a prior send of `markerId` (a Note marker).
 * EMAIL-DEDUP-1: markers live in the Note TITLE namespace (`sent:<markerId>`), NOT
 * the leadId custom field, so a leadId-keyed lead reconciliation
 * (findNoteByLeadId / listNotes' leadId filter / notes-drift) can never mistake a
 * dedup marker for a lead note. We therefore query the title exact-match, never
 * leadId. The title value is a constant `sent:` prefix + a filter-safe hex marker,
 * URL-encoded by buildFilterPath.
 */
async function findPriorSend(
  cfg: GlobalArgs,
  markerId: string,
): Promise<Record<string, unknown> | null> {
  if (!isFilterSafe(markerId)) return null;
  const json = await twentyRequest(
    cfg,
    "GET",
    buildFilterPath("/rest/notes", "title", `sent:${markerId}`),
  );
  return unwrapList(json, "notes")[0] ?? null;
}

/** Write the durable dedup marker AFTER a successful enqueue (body-free Note). */
async function writeSendMarker(
  cfg: GlobalArgs,
  markerId: string,
): Promise<void> {
  // EMAIL-DEDUP-1: write the marker in the TITLE only (`sent:<markerId>`) and do
  // NOT set the leadId custom field — that keeps dedup markers OUT of the leadId
  // Note namespace so a leadId-keyed reconciliation cannot mistake them for lead
  // notes. findPriorSend queries this title. Body-free.
  await twentyRequest(cfg, "POST", "/rest/notes", {
    title: `sent:${markerId}`,
  });
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

// upsertOpportunity.customFields reserved keys (TWENTY-OPP-FIELDS F1/F4): the
// immutable leadId idempotency marker, every Opportunity field owned by a typed
// upsertOpportunity argument, and the base system fields. A customFields key in
// this set is a HARD reject pre-write — the generic escape hatch can never
// rewrite the idempotency marker or bypass a typed arg's enum validation, and a
// collision with a typed arg is an error, not a silent merge.
const OPP_CUSTOMFIELDS_RESERVED = new Set<string>([
  ...UPSERT_RESERVED_FIELDS, // id, createdAt, updatedAt, deletedAt, position
  "leadId",
  "name",
  "stage",
  "amount",
  "currencyCode",
  "closeDate",
  "companyId",
  "company",
  "pointOfContactId",
  "pointOfContact",
  "isEmergency",
  "lineOfBusiness",
  "sourceChannel",
  "asn",
  "qualStatus",
  "offering",
  "channelPartnerId",
  "channelPartner",
]);

// upsertCompany.customFields reserved keys (TWENTY-COMPANY-UPSERT, ADV-8/SEC-3):
// every Company field owned by a typed upsertCompany argument, the composite
// field owners those typed args write (domainName / linkedinLink / xLink /
// address), and the base system fields (UPSERT_RESERVED_FIELDS). A customFields
// key in this set is a HARD reject pre-write — the generic escape hatch can
// never shadow a typed arg's validation/encoding or rewrite an identity field.
const COMPANY_CUSTOMFIELDS_RESERVED = new Set<string>([
  ...UPSERT_RESERVED_FIELDS, // id, createdAt, updatedAt, deletedAt, position
  "name",
  "domainName",
  "accountOwnerId",
  "accountOwner",
  "legalName",
  "employees",
  "idealCustomerProfile",
  "addressCity",
  "addressState",
  "addressCountry",
  "addressStreet1",
  "addressStreet2",
  "addressPostcode",
  // Composite owners written by the typed address/link args.
  "address",
  "linkedinLink",
  "xLink",
]);

/**
 * Resolve the write-relevant metadata for ONE object by nameSingular: its REST
 * plural (read from metadata, never guessed) and a name→{type, SELECT-option
 * values} map for every field. upsertRecord uses this to resolve the plural,
 * cross-check that matchField and every `fields` key exist and are scalar, and
 * validate SELECT values against the LIVE enum before a write. Throws if the
 * object is absent from workspace metadata.
 *
 * NOTE (isCustom — live-verified 2026-09-16 against the Twenty instance, Twenty
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

// TWENTY-OPTION-REMOVE: the SELECT picklists removeSelectOption may retire an
// option from. Checked BEFORE any I/O (SO-4 discipline); `force` cannot bypass it.
// All four opportunity SELECTs (human decision). CAVEAT (ADV-7): opportunity.stage
// is a STANDARD/system field tied to board OPEN/WON/LOST semantics — its metadata
// option edits may be constrained differently than the custom SELECTs; verified
// independently on the sandbox (design OQ6) and the method surfaces a clean error
// (never a partial write) if Twenty rejects a standard-field option removal.
const OPTION_REMOVE_ALLOWLIST = new Set<string>([
  "opportunity.stage",
  "opportunity.sourceChannel",
  "opportunity.lineOfBusiness",
  "opportunity.offering",
]);

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
  /**
   * The field's default option token, NORMALIZED to the bare value (TWENTY-OPTION-REMOVE
   * ADV-10): Twenty returns a SELECT field's defaultValue as a quoted enum literal
   * (e.g. "'NEW'"), so this strips the surrounding single-quotes; null/empty/unset →
   * undefined (no default). removeSelectOption refuses to remove the default option.
   */
  defaultValue?: string;
}

/**
 * Normalize a Twenty SELECT field.defaultValue to its bare option token (ADV-10).
 * Twenty stores the default as a quoted enum literal — e.g. the string `'NEW'`
 * (with the single-quotes as literal characters) — so a raw compare against the
 * bare `NEW` token never matches. Strip ONE layer of surrounding single-quotes and
 * trim; treat null/undefined/empty (and a bare `null` literal) as "no default".
 */
function normalizeDefaultValue(raw: unknown): string | undefined {
  if (typeof raw !== "string") return undefined;
  let s = raw.trim();
  if (s === "" || s === "null") return undefined;
  if (s.length >= 2 && s.startsWith("'") && s.endsWith("'")) {
    s = s.slice(1, -1).trim();
  }
  return s === "" ? undefined : s;
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
  // ADV-10: capture the field's default option (normalized) so removeSelectOption
  // can refuse to remove it. Best-effort — an absent/odd-shaped default is treated
  // as "no default" (undefined), never a hard-stop (ensureStageOption ignores it).
  const defaultValue = normalizeDefaultValue(field.defaultValue);
  return { objectId, fieldId, type, options, defaultValue };
}

/** True if two option arrays are equivalent (keyed by value; id/label/color/position). */
function optionsEquivalent(a: SelectOption[], b: SelectOption[]): boolean {
  if (a.length !== b.length) return false;
  const key = (o: SelectOption) =>
    JSON.stringify([o.value, o.label, o.color, o.position, o.id ?? ""]);
  const setB = new Set(b.map(key));
  return a.every((o) => setB.has(key(o)));
}

/**
 * TWENTY-OPTION-REMOVE anti-orphan count — exact, PII-minimal, fail-closed.
 * Reads ONLY the authoritative `totalCount` the Twenty REST list envelope exposes
 * for a server-side `<field>[eq]:<value>` filter (limit=1: at most one record body
 * transits and is DISCARDED — never paged in bulk, never logged). Server-side
 * filtering counts custom SELECTs incl. `offering` correctly (the filter is
 * independent of any node/field selection) and is authoritative so there is no
 * truncation (ADV-1/ADV-11/SEC-1/SEC-6/SEC-8).
 *
 * Returns { count, trusted }. `trusted` is false when the envelope omits a usable
 * numeric totalCount (no-total) — the caller then REFUSES ('refused-untrusted-count')
 * rather than trust a silent 0. NOTE (ADV-14): the per-field filter ENCODING is
 * proven by the positive-control acceptance test (design OQ8: a known-referenced
 * value must count nonzero and a known-absent value must count 0) — a mis-targeting
 * filter that silently matches nothing cannot be caught at runtime, only by that test.
 * `value` is UPPER_SNAKE-validated by the caller and URL-encoded here (anti-injection).
 */
async function countOpportunitiesByFieldValue(
  cfg: TwentyCfg,
  fieldName: string,
  value: string,
): Promise<{ count: number; trusted: boolean }> {
  const clause = `${fieldName}[eq]:${encodeURIComponent(value)}`;
  const json = await twentyRequest(
    cfg,
    "GET",
    `/rest/opportunities?filter=${clause}&limit=1`,
  );
  const tc = (json as { totalCount?: unknown }).totalCount;
  if (typeof tc === "number" && Number.isFinite(tc) && tc >= 0) {
    return { count: tc, trusted: true };
  }
  return { count: 0, trusted: false };
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
 * Page a metadata collection (`/rest/metadata/<object>`) fully — envelope is
 * `{data:[...], pageInfo}`, cursor-paginated exactly like /rest/metadata/objects.
 * Used for views + viewFilters (TWENTY-VIEW-MGMT). Read-only; throws on a non-2xx
 * (a caller that wants classification should rawGet-probe first).
 */
export async function fetchMetadataList(
  cfg: TwentyCfg,
  object: string,
): Promise<Array<Record<string, unknown>>> {
  const out: Array<Record<string, unknown>> = [];
  const seen = new Set<string>();
  let cursor: string | undefined;
  for (let page = 0; page < 50; page++) {
    const pageCursor = cursor;
    const path = `/rest/metadata/${object}?limit=${PAGE_SIZE}` +
      (pageCursor ? `&starting_after=${encodeURIComponent(pageCursor)}` : "");
    const json = await twentyRequest(cfg, "GET", path);
    const batch = ((json as { data?: unknown }).data ?? []) as Array<
      Record<string, unknown>
    >;
    let fresh = 0;
    for (const rec of Array.isArray(batch) ? batch : []) {
      const id = String(rec.id ?? "");
      if (id && seen.has(id)) continue;
      if (id) seen.add(id);
      fresh++;
      out.push(rec);
    }
    const pageInfo = (json as {
      pageInfo?: { hasNextPage?: boolean; endCursor?: string };
    }).pageInfo;
    if (!pageInfo?.hasNextPage) break;
    const endCursor = pageInfo.endCursor;
    if (!endCursor || endCursor === pageCursor || fresh === 0) break;
    cursor = endCursor;
  }
  return out;
}

/**
 * Resolve the Opportunity objectMetadataId and the live metadata (id + option
 * tokens) for the fields the target views filter on. Shared by listViews (probe)
 * and ensureOpportunityViews (write): both bind filters to a live fieldMetadataId
 * (F6) and rebuild the value allowlist from the live options (S1). Best-effort —
 * returns whatever resolves; callers fail-closed per field on a missing id.
 */
export async function resolveOpportunityFilterFields(
  cfg: TwentyCfg,
  fieldNames: string[] = ["stage", "lineOfBusiness"],
): Promise<{
  oppOid?: string;
  fields: Record<
    string,
    { fieldMetadataId?: string; type?: string; options: string[] }
  >;
}> {
  const fields: Record<
    string,
    { fieldMetadataId?: string; type?: string; options: string[] }
  > = {};
  let oppOid: string | undefined;
  const objs = await fetchObjectsMeta(cfg);
  const opp = objs.find((o) => String(o.nameSingular) === "opportunity");
  if (opp?.id) oppOid = String(opp.id);
  const fieldList = (opp?.fields ?? []) as Array<Record<string, unknown>>;
  for (const fname of fieldNames) {
    const f = (Array.isArray(fieldList) ? fieldList : []).find(
      (x) => String(x.name ?? "") === fname,
    );
    if (!f) continue;
    const opts = (f.options ?? []) as Array<Record<string, unknown>>;
    fields[fname] = {
      fieldMetadataId: f.id ? String(f.id) : undefined,
      type: f.type != null ? String(f.type) : undefined,
      options: Array.isArray(opts)
        ? opts.map((o) => String(o.value ?? "")).filter(Boolean)
        : [],
    };
  }
  return { oppOid, fields };
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
 * The Opportunity segmentation SELECT fields (CRM-TASKS #5): `lineOfBusiness`,
 * `sourceChannel`, and `offering`. Analytics only — NOT a pipeline gate.
 * `sourceChannel` is what push_leads stamps (see the `leadSourceChannel` global);
 * `offering` is set deliberately per deal (push_leads does not stamp it).
 * Provisioned via the shared append-only ensureField path so a re-run is a clean
 * no-op.
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
  {
    objectNameSingular: "opportunity",
    name: "offering",
    label: "Offering",
    type: "SELECT",
    options: [
      { value: "MANAGED", label: "Managed", color: "blue" },
      { value: "SUBSTRATE", label: "Substrate", color: "turquoise" },
      { value: "PROJECT", label: "Project", color: "orange" },
      { value: "RETAINER", label: "Retainer", color: "green" },
      { value: "LOCAL_IT", label: "Local IT", color: "sky" },
      { value: "PEERING", label: "Peering", color: "pink" },
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

// --- noteHash provisioned-ness (TWENTY-NOTE-RECONCILE, ADV-2/OQ8) -----------

/**
 * Memo of whether note.noteHash is provisioned, keyed by baseUrl with a short
 * TTL, so the createNote/updateNote population guard determines provisioned-ness
 * "from the schema (introspect / a cached check), not by assuming" (ADV-2)
 * WITHOUT a full metadata read on every write (OQ8). A serve process reuses the
 * cached answer across writes; a one-shot CLI reads once. Cleared by
 * {@link __clearNoteFieldCache} in tests (module state would otherwise leak
 * across cases sharing a baseUrl).
 */
const noteHashFieldCache = new Map<
  string,
  { expires: number; present: boolean }
>();
const NOTE_FIELD_CACHE_TTL_MS = 5 * 60 * 1000;

/** Test hook: drop the noteHash provisioned-ness memo. */
export function __clearNoteFieldCache(): void {
  noteHashFieldCache.clear();
}

/**
 * True iff the workspace has provisioned the note.noteHash TEXT field
 * (ensureNoteFields). Memoized per baseUrl (see {@link noteHashFieldCache}).
 */
async function noteHashFieldProvisioned(cfg: TwentyCfg): Promise<boolean> {
  const now = Date.now();
  const cached = noteHashFieldCache.get(cfg.baseUrl);
  if (cached && cached.expires > now) return cached.present;
  const objs = await fetchObjectsMeta(cfg);
  const note = objs.find((o) => String(o.nameSingular ?? "") === "note");
  const fields = (note?.fields ?? []) as Array<Record<string, unknown>>;
  const present = (Array.isArray(fields) ? fields : []).some(
    (f) => String(f.name ?? "") === "noteHash",
  );
  noteHashFieldCache.set(cfg.baseUrl, {
    expires: now + NOTE_FIELD_CACHE_TTL_MS,
    present,
  });
  return present;
}

/**
 * The population decision for the opted-in reconcile writers (createNote/
 * updateNote): compute the keyed noteHash for `title`+`body` when note.noteHash
 * is provisioned, else return undefined (field absent ⇒ skip the hash, NEVER
 * break the write — ADV-2). FAIL CLOSED (SEC-5): when the field IS provisioned
 * but the HMAC key is empty/unset, THROW rather than store an empty-keyed hash.
 * push_leads/ensureNoteForLead do NOT call this — the lead sink never hashes.
 */
async function computeNoteHashForWrite(
  cfg: GlobalArgs,
  title: string,
  body: string,
): Promise<string | undefined> {
  if (!(await noteHashFieldProvisioned(cfg))) return undefined;
  const key = cfg.noteHashHmacKey ?? "";
  if (!key) {
    throw new Error(
      "note.noteHash is provisioned but noteHashHmacKey is empty — refusing " +
        "to write an empty-keyed (zero-confidentiality) note hash (SEC-5 fail " +
        "closed). Set the vault-held HMAC key, or unprovision note.noteHash.",
    );
  }
  return await hashNote(key, title, body);
}

// --- Note write core (TWENTY-NOTE-MGMT) -------------------------------------

/**
 * A Note write (POST/PATCH `/rest/notes…`, POST `/rest/noteTargets`) whose thrown
 * error NEVER carries the response body (CR-NOTE A3/S1): a note title/body is
 * submitted here and Twenty can echo the submitted value in a 4xx, which
 * redactError's pattern-scrubber does NOT cover (it only scrubs bearer/filter/
 * email/digits, not arbitrary free text). So the response body is DISCARDED and a
 * GENERIC `note <label> failed (status N)` is thrown. Returns parsed JSON on 2xx.
 */
async function noteWriteRequest(
  cfg: TwentyCfg,
  method: string,
  path: string,
  body: Record<string, unknown>,
  label: string,
): Promise<unknown> {
  const base = cfg.baseUrl.replace(/\/+$/, "");
  const resp = await fetch(`${base}${path}`, {
    method,
    headers: {
      "Authorization": `Bearer ${cfg.apiToken}`,
      "Accept": "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const text = await resp.text();
  if (!resp.ok) {
    // Body intentionally discarded — never echo a submitted title/body.
    throw new Error(`note ${label} failed (status ${resp.status})`);
  }
  return text ? JSON.parse(text) : {};
}

/** Envelope-independent first record from a `{data:{<op>:{...}}}` response. */
function firstRecordOf(json: unknown): Record<string, unknown> {
  const d = (json as { data?: Record<string, unknown> })?.data ?? {};
  const v = Object.values(d)[0];
  return (v && typeof v === "object" ? v : {}) as Record<string, unknown>;
}

/** The three noteTarget kinds and their REST field names. */
const NOTE_TARGET_KINDS = [
  { arg: "opportunityId", field: "targetOpportunityId" },
  { arg: "personId", field: "targetPersonId" },
  { arg: "companyId", field: "targetCompanyId" },
] as const;

interface NoteTarget {
  field: string;
  id: string;
  kind: string;
}

/**
 * Normalize a `{opportunityId?|personId?|companyId?}` target entry to
 * `{field,id,kind}` — EXACTLY one UUID-validated id, else throw (pre-I/O).
 */
function normalizeNoteTarget(t: Record<string, unknown>): NoteTarget {
  const present = NOTE_TARGET_KINDS
    .map((k) => ({ ...k, raw: t[k.arg] }))
    .filter((k) => k.raw != null && String(k.raw).trim() !== "");
  if (present.length !== 1) {
    throw new Error(
      "each note target must carry EXACTLY one of opportunityId/personId/companyId",
    );
  }
  const only = present[0];
  const id = validateUuid(only.raw);
  if (!id) throw new Error(`note target ${only.arg} is not a valid UUID`);
  return { field: only.field, id, kind: only.arg };
}

/**
 * Shared note create-or-reuse core (used by ensureNoteForLead + createNote).
 * When `dedupByLeadId` and a Note already carries `leadId`, reuse it (no create);
 * otherwise POST a new Note. Title/body are submitted VERBATIM (caller sanitizes
 * the title; untrusted callers escapeMarkdown the body). Uses noteWriteRequest so
 * a failure never echoes the submitted content (A3/S1). A1: POST unwraps
 * `createNote`.
 */
async function createOrReuseNote(
  cfg: TwentyCfg,
  input: {
    title: string;
    body?: string;
    leadId?: string;
    dedupByLeadId?: boolean;
    // Pre-computed keyed HMAC of title+body (TWENTY-NOTE-RECONCILE). Set ONLY by
    // the opted-in createNote reconcile writer; ensureNoteForLead (push_leads)
    // NEVER passes it, so the shared lead-sink note-write path never stores a
    // noteHash and stays UNCHANGED (pushLeadsContract). Written only on a real
    // CREATE — the leadId dedup-reuse path leaves the existing note untouched.
    noteHash?: string;
  },
): Promise<{ noteId: string; created: boolean }> {
  if (input.dedupByLeadId && input.leadId) {
    const existing = await findNoteByLeadId(cfg, input.leadId);
    if (existing) return { noteId: String(existing.id ?? ""), created: false };
  }
  const bodyRec: Record<string, unknown> = { title: input.title };
  if (input.body != null) bodyRec.bodyV2 = { markdown: input.body };
  if (input.leadId != null && input.leadId !== "") {
    bodyRec.leadId = input.leadId;
  }
  if (input.noteHash != null && input.noteHash !== "") {
    bodyRec.noteHash = input.noteHash;
  }
  const json = await noteWriteRequest(
    cfg,
    "POST",
    "/rest/notes",
    bodyRec,
    "create",
  );
  return {
    noteId: String(unwrapRecord(json, "createNote").id ?? ""),
    created: true,
  };
}

/**
 * Idempotently link `targets` to a Note. A4: EXACT target-id equality (never the
 * any-of-kind check) so linking person B never no-ops because A is linked, and
 * unlink can't hit the wrong row. S7: after a create POST, verify the returned
 * row carries the intended id before counting it linked (guards a silent
 * schema-drift no-op — e.g. a wrong targetCompanyId field — from a false audit).
 * A6: with `bestEffort`, a link failure is collected, never thrown, so a partial
 * failure after the note create can't orphan/duplicate. Returns linked + failed.
 */
async function reconcileNoteTargets(
  cfg: TwentyCfg,
  noteId: string,
  targets: NoteTarget[],
  opts: { bestEffort?: boolean } = {},
): Promise<{ linked: string[]; failed: string[] }> {
  const linked: string[] = [];
  const failed: string[] = [];
  if (!targets.length) return { linked, failed };
  const existing = unwrapList(
    await twentyRequest(
      cfg,
      "GET",
      buildFilterPath("/rest/noteTargets", "noteId", noteId),
    ),
    "noteTargets",
  );
  for (const t of targets) {
    if (existing.some((r) => String(r[t.field] ?? "") === t.id)) {
      linked.push(t.id); // already linked (exact match) — idempotent no-op
      continue;
    }
    try {
      const json = await noteWriteRequest(
        cfg,
        "POST",
        "/rest/noteTargets",
        { noteId, [t.field]: t.id },
        "link",
      );
      if (String(firstRecordOf(json)[t.field] ?? "") === t.id) {
        linked.push(t.id); // S7: row confirmed to carry the intended id
      } else {
        failed.push(t.id); // schema-drift no-op — do NOT report as linked
      }
    } catch (e) {
      if (opts.bestEffort) failed.push(t.id);
      else throw e;
    }
  }
  return { linked, failed };
}

/**
 * Attach the per-lead Note idempotently — a THIN wrapper over the shared note
 * core (rule 2). Preserves the push_leads contract exactly (A7): forced machine
 * title `Inbound lead <leadId>`, `leadId` set, person/opp target reconcile, and
 * the `{noteId,created}` return. Target links are best-effort (A6) so a link
 * failure never aborts a lead.
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
  const { noteId, created } = await createOrReuseNote(cfg, {
    title: `Inbound lead ${input.leadId}`,
    body: input.body,
    leadId: input.leadId,
    dedupByLeadId: true,
  });
  if (!noteId) return { noteId, created };
  const targets: NoteTarget[] = [];
  if (input.personId) {
    targets.push({
      field: "targetPersonId",
      id: input.personId,
      kind: "personId",
    });
  }
  if (input.opportunityId) {
    targets.push({
      field: "targetOpportunityId",
      id: input.opportunityId,
      kind: "opportunityId",
    });
  }
  await reconcileNoteTargets(cfg, noteId, targets, { bestEffort: true });
  return { noteId, created };
}

// Does a markdown-only PATCH of `bodyV2` make Twenty RE-DERIVE the `blocknote`
// rich-text representation? Settled by the implement step-0 twenty-local probe
// (design §6). Decision (1): write-both-or-refuse, NO stale-UI caveat.
// PROBE OUTCOME (twenty-local, Twenty v2.38.1, 2026-09-17): a markdown-only write
// RE-DERIVES bodyV2.blocknote on BOTH create and PATCH (verified by reading the
// note.bodyV2Blocknote column before/after — it tracked the new markdown, never
// went stale). So this is TRUE and updateNote/appendNote write the body freely.
// The refuse-blocknote branch below is a DORMANT fallback: flip to false to re-arm
// it if a future Twenty version stops re-deriving (A5/S6: a stale blocknote would
// be a cross-representation lost-update AND a false-redaction).
const BODYV2_MARKDOWN_REDERIVES = true;

/** True if a Note record already carries a non-empty `bodyV2.blocknote`. */
function noteHasBlocknote(note: Record<string, unknown>): boolean {
  const bv2 = note.bodyV2 as { blocknote?: unknown } | null | undefined;
  const bn = bv2?.blocknote;
  if (bn == null) return false;
  const s = typeof bn === "string" ? bn : JSON.stringify(bn);
  return s.trim() !== "" && s.trim() !== "null" && s.trim() !== "[]";
}

/** The current `bodyV2.markdown` of a Note record, or "" when absent/empty. */
function noteMarkdown(note: Record<string, unknown>): string {
  const bv2 = note.bodyV2 as { markdown?: unknown } | null | undefined;
  return bv2?.markdown != null ? String(bv2.markdown) : "";
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

/**
 * The custom fields note reconciliation depends on (TWENTY-NOTE-RECONCILE),
 * provisioned by the thin ensureNoteFields wrapper (parallels ensureLeadFields
 * over REQUIRED_FIELDS). `noteHash` (TEXT) stores the keyed HMAC of title+body;
 * provisioning it ENABLES population (createNote/updateNote then require the
 * HMAC key, SEC-5). note.leadId is already covered by REQUIRED_FIELDS.
 */
const NOTE_FIELDS: ReadonlyArray<
  { object: string; name: string; label: string; type: string }
> = [
  { object: "note", name: "noteHash", label: "Note Hash", type: "TEXT" },
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
  spamScore: z.number().optional().describe(
    "Shadow-mode spam score from classifyLead (>= threshold => would be quarantined in the future enforce phase; NOT quarantined now).",
  ),
  spamReasons: z.array(z.string()).optional().describe(
    "PII-free coded reasons behind spamScore (e.g. identity-repeat:6, localpart-machine-generated). Never raw lead text.",
  ),
  spamFlagged: z.boolean().optional().describe(
    "Shadow verdict: spamScore >= threshold. Reported only; the lead still synced this phase.",
  ),
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
    spamFlagged: z.number().optional().describe(
      "Shadow-mode count of leads classifyLead WOULD quarantine at the current threshold. NOT quarantined in this phase - the leads still synced.",
    ),
    perLead: z.array(
      z.object({
        leadId: z.string(),
        action: z.string(),
        status: z.string(),
        emergency: z.boolean(),
        spamScore: z.number().optional(),
        spamReasons: z.array(z.string()).optional(),
        spamFlagged: z.boolean().optional(),
      }),
    ),
  }),
});

export const OpportunityUpsertSchema = z.object({
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
  asn: z
    .string()
    .optional()
    .describe("ASN (AS<digits>) written, if set"),
  qualStatus: z
    .string()
    .optional()
    .describe("Qualification-status SELECT token written, if set"),
  offering: z
    .string()
    .optional()
    .describe("Offering segmentation SELECT token written, if set"),
  customFields: z
    .record(z.string(), z.union([z.string(), z.number(), z.boolean()]))
    .optional()
    .describe(
      "Generic scalar custom fields written, if any (keys+values as submitted; PII in non-identity scalars is out of contract)",
    ),
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
  channelPartnerId: z
    .string()
    .optional()
    .describe("channelPartner relation id linked, if set/resolved"),
  channelPartnerSkipped: z
    .string()
    .optional()
    .describe(
      "Why the channelPartner was not linked (name not found), if applicable",
    ),
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

export const OpportunityRefSchema = z.object({
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
  channelPartnerId: z.string().optional(),
  lineOfBusiness: z.string().optional(),
  sourceChannel: z.string().optional(),
  asn: z.string().optional(),
  qualStatus: z.string().optional(),
  offering: z.string().optional(),
  isEmergency: z.boolean().optional(),
  retrievedAt: z.iso.datetime(),
});

export const OppViewSchema = z.object({
  id: z.string(),
  leadId: z.string().optional(),
  name: z.string(),
  stage: z.string(),
  amount: z.number().optional(),
  currencyCode: z.string().optional(),
  closeDate: z.string().optional(),
  companyId: z.string().optional(),
  channelPartnerId: z.string().optional(),
  lineOfBusiness: z.string().optional(),
  sourceChannel: z.string().optional(),
  asn: z.string().optional(),
  qualStatus: z.string().optional(),
  offering: z.string().optional(),
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

// --- Dashboard aggregate snapshot (TWENTY-DASHBOARDS) -----------------------

const AmountEntrySchema = z.object({
  currency: z.string(),
  amount: z.number(),
});

/**
 * PII-free CRM pipeline analytics snapshot from aggregateOpportunities. Only
 * counts, per-currency sums, and enum labels — no opp names/ids/contacts.
 * `source` = which acquisition path produced the numbers (rest until the live
 * `graphqlProbe` verifies GraphQL aggregation); `graphqlProbe` records the
 * verify-first Phase-0 findings (introspection state + whether a GraphQL read
 * worked) without depending on them.
 */
export const OppAggregatesSchema = z.object({
  baseUrl: z.string(),
  source: z.enum(["graphql", "rest"]),
  truncated: z
    .boolean()
    .describe("True if acquisition was capped with more opps available"),
  includeEmergency: z.boolean(),
  totalOpps: z.number(),
  emergencyExcluded: z.number(),
  currencies: z.array(z.string()),
  byStage: z.array(z.object({
    stage: z.string(),
    count: z.number(),
    amounts: z.array(AmountEntrySchema),
  })),
  byLineOfBusiness: z.array(z.object({
    lineOfBusiness: z.string(),
    count: z.number(),
    amounts: z.array(AmountEntrySchema),
  })),
  bySourceChannel: z.array(z.object({
    sourceChannel: z.string(),
    count: z.number(),
  })),
  openPipeline: z.object({
    count: z.number(),
    amounts: z.array(AmountEntrySchema),
  }),
  winLoss: z.object({
    won: z.number(),
    lost: z.number(),
    winRate: z.number().nullable(),
  }),
  activeCustomers: z.number(),
  graphqlProbe: z.object({
    attempted: z.boolean().describe("Whether GraphQL acquisition was tried"),
    ok: z.boolean().describe("GraphQL acquisition succeeded (source==graphql)"),
    serverSumMicros: z
      .number()
      .nullable()
      .describe("Connection sumAmountAmountMicros (all-currency micros sum)"),
    crossCheck: z
      .enum(["match", "mismatch", "na"])
      .describe("Server micros sum vs in-extension raw micros sum"),
    detail: z.string().optional(),
  }),
  retrievedAt: z.iso.datetime(),
});

// --- View listing / probe snapshot (TWENTY-VIEW-MGMT Phase 0) ---------------

/**
 * Snapshot from listViews: the read-only Phase-0 probe. Records which view
 * endpoint answered (and how each candidate classified), the opportunity views
 * found, and a capped raw sample for live shape-discovery (lock flag +
 * viewFilter shape) before any write method is authored.
 */
export const ViewListSchema = z.object({
  baseUrl: z.string(),
  probes: z.array(z.object({
    path: z.string(),
    status: z.number(),
    verdict: z.enum(["ok", "absent", "forbidden", "error"]),
    count: z.number().optional(),
    bodySample: z.string().optional(),
  })),
  readPath: z.string().optional(),
  writeEndpointCandidate: z.string().optional(),
  opportunityObjectMetadataId: z.string().optional(),
  viewCount: z.number(),
  opportunityViews: z.array(z.object({
    id: z.string(),
    name: z.string(),
    type: z.string().optional(),
    key: z.string().nullable().optional(),
    isSystemSideEffect: z.boolean().optional(),
    isCustom: z.boolean().optional(),
    position: z.number().optional(),
    objectMetadataId: z.string().optional(),
    filters: z.array(z.object({
      id: z.string(),
      fieldMetadataId: z.string().optional(),
      operand: z.string().optional(),
      value: z.unknown().optional(),
      subFieldName: z.string().nullable().optional(),
      viewFilterGroupId: z.string().nullable().optional(),
    })).optional(),
  })),
  /** Human-readable note on which field marks the locked/default index view. */
  lockFlagObserved: z.string().optional(),
  /**
   * Live field metadata for the fields the target views filter on (stage,
   * lineOfBusiness): resolved fieldMetadataId + the current option token set
   * (S1 allowlist source) + which target options are covered (A5 dependency
   * assert). Absent if the field metadata read failed.
   */
  filterFields: z.record(
    z.string(),
    z.object({
      fieldMetadataId: z.string().optional(),
      type: z.string().optional(),
      options: z.array(z.string()),
    }),
  ).optional(),
  /** Live stage options NOT covered by the Sales-pipeline open-stage set (A5 drift). */
  uncoveredStageOptions: z.array(z.string()).optional(),
  sample: z.string().optional(),
  retrievedAt: z.iso.datetime(),
});

// --- Opportunity view management (TWENTY-VIEW-MGMT) --------------------------

/**
 * Target opportunity view set (re-scoped spec 2026-09-17). Each is a single
 * `IS`-any-of filter on one SELECT field, binding only to live enum tokens
 * (asserted present per run — A5). Sales Pipeline enumerates the OPEN stages
 * positively (A1/A2) so won/terminal/parked/legacy stages are structurally
 * excluded. `field` resolves to a live fieldMetadataId per run (F6); the value
 * allowlist is intersected with the live option set each run (S1).
 */
export const OPP_VIEW_TARGETS: ReadonlyArray<
  { name: string; field: "stage" | "lineOfBusiness"; values: readonly string[] }
> = [
  {
    name: "Sales Pipeline",
    field: "stage",
    values: ["NEW", "SCREENING", "MEETING", "PROPOSAL"],
  },
  { name: "Consulting", field: "lineOfBusiness", values: ["CONSULTING"] },
  { name: "Hosting", field: "lineOfBusiness", values: ["HOSTING"] },
  { name: "Local IT", field: "lineOfBusiness", values: ["LOCAL_IT"] },
];

// Only the known target names may ever be minted — a typo/injection can't create
// an arbitrary view (F10). Rebuilt from the target set, never appended live.
const OPP_VIEW_NAME_ALLOWLIST: ReadonlySet<string> = new Set(
  OPP_VIEW_TARGETS.map((t) => t.name),
);

/**
 * Stored form of a Twenty viewFilter `value` for an `IS`-any-of SELECT filter: a
 * JSON array of option tokens (matches the UI-created reference filter captured
 * in Phase 0, e.g. `["CUSTOMER"]`). Centralised so the write form is ONE point of
 * control if the confirm-gated first write shows Twenty wants the stringified
 * variant `"[\"CUSTOMER\"]"` instead (the other form also observed live — F5/A4).
 */
export function buildViewFilterValue(values: readonly string[]): string[] {
  return [...values];
}

/**
 * Normalise a viewFilter `value` — observed live as EITHER a real JSON array
 * (`["CUSTOMER"]`) OR a stringified array (`"[\"NETWORK_PROVIDER\"]"`) — to a
 * token array, so an existing filter can be compared to the desired set
 * regardless of how it was stored.
 */
export function normalizeFilterValueTokens(value: unknown): string[] {
  let v = value;
  if (typeof v === "string") {
    const s = v.trim();
    if (s.startsWith("[")) {
      try {
        v = JSON.parse(s);
      } catch {
        return s ? [s] : [];
      }
    } else {
      return s ? [s] : [];
    }
  }
  if (Array.isArray(v)) return v.map((x) => String(x)).filter(Boolean);
  return v == null ? [] : [String(v)];
}

export interface OppViewFilterRef {
  id?: string;
  fieldMetadataId?: string;
  operand?: string;
  value?: unknown;
  // Carried for the reconciling upsert path (TWENTY-VIEW-UPSERT / ADV-9): the
  // viewFilter identity key includes subFieldName + viewFilterGroupId so a field
  // reused across groups can't alias, and a grouped view can round-trip.
  subFieldName?: string | null;
  viewFilterGroupId?: string | null;
  positionInViewFilterGroup?: number | null;
}
export interface OppViewFilterGroupRef {
  id: string;
  logicalOperator?: string; // "AND" | "OR"
  parentViewFilterGroupId?: string | null;
}
export interface OppViewRef {
  id: string;
  name: string;
  key?: string | null;
  isSystemSideEffect?: boolean;
  isCustom?: boolean;
  objectMetadataId?: string;
  filters?: OppViewFilterRef[];
  filterGroups?: OppViewFilterGroupRef[];
}
export interface OppViewPlan {
  target: string;
  field: string;
  fieldMetadataId?: string;
  desiredValues: string[];
  operand: "IS";
  action: "create" | "noop" | "refuse";
  reason: string;
  viewId?: string;
}

function setEq(a: string[], b: string[]): boolean {
  // Set-based: duplicate tokens (e.g. malformed live value ["NEW","NEW"]) must
  // not read as equal to a distinct desired set of the same length (L5).
  const sa = new Set(a);
  const sb = new Set(b);
  if (sa.size !== sb.size) return false;
  for (const x of sa) if (!sb.has(x)) return false;
  return true;
}

/**
 * Pure planner for ONE target opportunity view. Fail-closed and NON-MUTATING by
 * construction: it only ever plans a CREATE (name absent) or a NO-OP (present +
 * filter already matches desired); every other case is a REFUSE with a reason. It
 * never plans a mutation of a pre-existing view — this API surface exposes no
 * writable swamp-authorship marker on a view, and a method cannot read prior
 * swamp state to prove it authored one, so reconciling a same-named drifted view
 * cannot be done without risking a user's view (F3/A6). Callers surface refusals
 * for a human to resolve.
 */
export function planOpportunityView(
  target: { name: string; field: string; values: readonly string[] },
  fieldMeta: { fieldMetadataId?: string; options: string[] } | undefined,
  existingViews: OppViewRef[],
): OppViewPlan {
  const base = {
    target: target.name,
    field: target.field,
    desiredValues: [] as string[],
    operand: "IS" as const,
  };
  // Defense-in-depth: only known target names may be minted (F10).
  if (!OPP_VIEW_NAME_ALLOWLIST.has(target.name)) {
    return {
      ...base,
      action: "refuse",
      reason: `view name '${target.name}' is not in the target allowlist`,
    };
  }
  const fieldMetadataId = fieldMeta?.fieldMetadataId;
  if (!fieldMetadataId) {
    return {
      ...base,
      action: "refuse",
      reason:
        `field '${target.field}' has no resolvable fieldMetadataId in live schema (F6)`,
    };
  }
  // S1: allowlist rebuilt from live options each run; A5: every target option
  // must be present live — fail-closed on any absent/invalid token.
  const liveOpts = new Set(fieldMeta?.options ?? []);
  const missing = target.values.filter(
    (v) => !STAGE_OPTION_VALUE_RE.test(v) || !liveOpts.has(v),
  );
  if (missing.length) {
    return {
      ...base,
      fieldMetadataId,
      action: "refuse",
      reason: `target option(s) [${
        missing.join(", ")
      }] absent from live '${target.field}' schema — fail-closed (A5/S1)`,
    };
  }
  const desiredValues = [...target.values];
  const withFilter = { ...base, fieldMetadataId, desiredValues };
  const matches = existingViews.filter((v) => v.name === target.name);
  // F2: never touch a locked / system / default (INDEX) view.
  const locked = matches.find(
    (v) =>
      v.key != null || v.isSystemSideEffect === true ||
      v.isCustom === false,
  );
  if (locked) {
    return {
      ...withFilter,
      action: "refuse",
      reason: `a view named '${target.name}' is locked/system (key=${
        JSON.stringify(locked.key)
      }, isSystemSideEffect=${locked.isSystemSideEffect}, isCustom=${locked.isCustom}) — never mutate (F2)`,
      viewId: locked.id,
    };
  }
  if (matches.length === 0) {
    return {
      ...withFilter,
      action: "create",
      reason: "no opportunity view with this name — create",
    };
  }
  if (matches.length > 1) {
    return {
      ...withFilter,
      action: "refuse",
      reason:
        `${matches.length} opportunity views named '${target.name}' — ambiguous, fail-closed (A6)`,
      viewId: matches[0].id,
    };
  }
  const view = matches[0];
  const filters = view.filters ?? [];
  const alreadyDesired = filters.length === 1 &&
    filters[0].fieldMetadataId === fieldMetadataId &&
    String(filters[0].operand ?? "") === "IS" &&
    setEq(normalizeFilterValueTokens(filters[0].value), desiredValues);
  if (alreadyDesired) {
    return {
      ...withFilter,
      action: "noop",
      reason: "view exists with the desired filter — no change",
      viewId: view.id,
    };
  }
  return {
    ...withFilter,
    action: "refuse",
    reason:
      `view '${target.name}' exists but its filter differs from desired; not mutating a pre-existing view (no swamp-authorship marker on this API surface — F3/A6). Rename or delete it, or adopt manually.`,
    viewId: view.id,
  };
}

/**
 * Snapshot from ensureOpportunityViews: the per-target plan/outcome for the
 * gated view-write. dryRun (default) records the plan; confirm executes creates.
 */
export const ViewEnsuredSchema = z.object({
  baseUrl: z.string(),
  dryRun: z.boolean(),
  confirm: z.boolean(),
  reachable: z.boolean(),
  objectMetadataId: z.string().optional(),
  results: z.array(z.object({
    target: z.string(),
    field: z.string(),
    fieldMetadataId: z.string().optional(),
    desiredValues: z.array(z.string()),
    operand: z.string(),
    action: z.enum(["create", "noop", "refuse", "created", "failed"]),
    reason: z.string(),
    viewId: z.string().optional(),
    error: z.string().optional(),
  })),
  createdCount: z.number(),
  refusedCount: z.number(),
  retrievedAt: z.iso.datetime(),
});

// --- Opportunity view UPSERT (TWENTY-VIEW-UPSERT) ----------------------------
// Additive reconciling view management. Does NOT touch the create-only
// ensureOpportunityViews / planOpportunityView / ViewEnsuredSchema surface
// (ADV-6). Snapshots the extended-action viewEnsured2 resource. All shapes
// settled by the S0 twenty-local spike (2026-09-19).

/** Operands the reconciler will manage on a SELECT viewFilter (fail-closed). */
const UPSERT_ALLOWED_OPERANDS: ReadonlySet<string> = new Set(["IS", "IS_NOT"]);

/**
 * Write form of a viewFilter `value` for the reconciling upsert path: a
 * JSON-STRINGIFIED array of option tokens (e.g. `"[\"CUSTOMER\"]"`) — the exact
 * form the Twenty UI writes (S0 spike). Twenty does NOT normalize the stored
 * type (a bare array in reads back as a bare array), so writing the UI form
 * keeps swamp-authored filters byte-identical to UI-authored ones and avoids
 * churn; reads are normalized via normalizeFilterValueTokens regardless of the
 * stored form. Distinct from buildViewFilterValue (the legacy create-only path,
 * left unchanged — ADV-6).
 */
export function buildViewFilterValueString(values: readonly string[]): string {
  return JSON.stringify([...values]);
}

export interface DesiredViewFilter {
  field: string;
  operand: string;
  values: string[];
  subFieldName?: string | null;
}
export interface DesiredView {
  name: string;
  filters: DesiredViewFilter[];
  filterGroup?: "and" | "or";
  adoptFrom?: string;
}

interface ResolvedClause {
  field: string;
  fieldMetadataId: string;
  operand: string;
  values: string[];
  subFieldName: string | null;
}

/**
 * An ordered reconcile operation the executor performs (only under confirm).
 * Expressed so it needs NO pre-existing id EXCEPT where it references an
 * existing filter/group id (patch/delete/ungroup/patch-group-operator). A
 * `create-group` id is resolved at execution and reused by later grouped
 * `create-filter`s; a `delete-group` is only ever emitted for a group that the
 * plan leaves EMPTY (ADV-3 — never dangle a member).
 */
export type ViewUpsertOp =
  | { op: "rename-view"; toName: string }
  | { op: "create-group"; logicalOperator: string }
  | { op: "patch-group-operator"; groupId: string; logicalOperator: string }
  | { op: "delete-group"; groupId: string }
  | {
    op: "create-filter";
    fieldMetadataId: string;
    operand: string;
    value: string;
    subFieldName: string | null;
    grouped: boolean;
    position: number | null;
  }
  | {
    op: "patch-filter";
    filterId: string;
    operand?: string;
    value?: string;
    ungroup?: boolean;
  }
  | { op: "delete-filter"; filterId: string };

export interface ViewUpsertPlan {
  name: string;
  action: "create" | "adopt" | "reconcile" | "present" | "refuse";
  reason: string;
  viewId?: string;
  adoptFrom?: string;
  grouped: boolean;
  groupOperator?: string;
  ops: ViewUpsertOp[];
  filtersAdded: number;
  filtersRemoved: number;
  filtersPatched: number;
  existingGroupId?: string;
}

/** viewFilter identity within a view (ADV-9): field + subField + operand. */
function clauseKey(
  fieldMetadataId: string,
  subFieldName: string | null,
  operand: string,
): string {
  return `${fieldMetadataId} ${subFieldName ?? ""} ${operand}`;
}

/** Positive proof of mutability (S0 spike): API-created views report
 * isCustom=true; system/seeded views report isCustom=false and/or a non-null
 * key / isSystemSideEffect. Absent/false => LOCKED (fail-closed, SEC-1/ADV-1). */
function viewIsMutable(v: OppViewRef): boolean {
  return v.isCustom === true && v.key == null && v.isSystemSideEffect !== true;
}

/** Resolve + validate desired filters against live field metadata. Fail-closed:
 * unresolved fieldMetadataId, retired/invalid option token, unsupported
 * operand, missing filterGroup on a multi-clause view, or a duplicate clause
 * key all REFUSE. */
function resolveDesiredClauses(
  desired: DesiredView,
  fieldMeta: Record<
    string,
    { fieldMetadataId?: string; options: string[] } | undefined
  >,
): { clauses: ResolvedClause[] } | { refuse: string } {
  if (!desired.filters || desired.filters.length === 0) {
    return {
      refuse: "no filters specified — a managed view needs >=1 filter clause",
    };
  }
  if (desired.filters.length > 1 && desired.filterGroup == null) {
    return {
      refuse:
        `filterGroup ('and'|'or') is required for a multi-clause view (${desired.filters.length} clauses)`,
    };
  }
  const clauses: ResolvedClause[] = [];
  const seen = new Set<string>();
  for (const f of desired.filters) {
    const operand = String(f.operand ?? "").toUpperCase();
    if (!UPSERT_ALLOWED_OPERANDS.has(operand)) {
      return {
        refuse:
          `operand '${f.operand}' on field '${f.field}' is not supported (allowed: IS, IS_NOT)`,
      };
    }
    const meta = fieldMeta[f.field];
    const fieldMetadataId = meta?.fieldMetadataId;
    if (!fieldMetadataId) {
      return {
        refuse:
          `field '${f.field}' has no resolvable fieldMetadataId in live schema (fail-closed)`,
      };
    }
    const liveOpts = new Set(meta?.options ?? []);
    const values = [...(f.values ?? [])];
    if (values.length === 0) {
      return { refuse: `field '${f.field}' clause has no values` };
    }
    const missing = values.filter(
      (v) => !STAGE_OPTION_VALUE_RE.test(v) || !liveOpts.has(v),
    );
    if (missing.length) {
      return {
        refuse: `option(s) [${
          missing.join(", ")
        }] absent from live '${f.field}' schema — fail-closed (retired/invalid token)`,
      };
    }
    const subFieldName = f.subFieldName ?? null;
    const key = clauseKey(fieldMetadataId, subFieldName, operand);
    if (seen.has(key)) {
      return {
        refuse: `duplicate desired clause on (field=${f.field}, subField=${
          subFieldName ?? "-"
        }, operand=${operand})`,
      };
    }
    seen.add(key);
    clauses.push({
      field: f.field,
      fieldMetadataId,
      operand,
      values,
      subFieldName,
    });
  }
  return { clauses };
}

/**
 * Compute the ordered reconcile ops to bring an existing (already-proven-mutable)
 * view to the desired clause set + grouping. Fail-closed on unsafe group
 * structure (ADV-10): a nested group, >1 top-level group, an ambiguous
 * duplicate clause key, or an ungrouped-view -> grouped-desired restructure all
 * REFUSE rather than risk corrupting the boolean structure.
 */
function diffExistingView(
  existing: OppViewRef,
  clauses: ResolvedClause[],
  grouped: boolean,
  groupOperator: string | undefined,
):
  | {
    ops: ViewUpsertOp[];
    added: number;
    removed: number;
    patched: number;
    groupOpPatched: boolean;
    existingGroupId?: string;
  }
  | { refuse: string } {
  const groups = existing.filterGroups ?? [];
  const topGroups = groups.filter((g) => g.parentViewFilterGroupId == null);
  const nested = groups.filter((g) => g.parentViewFilterGroupId != null);
  if (nested.length > 0) {
    return {
      refuse:
        "existing view has nested viewFilterGroup(s) — multi-group/nested reconcile is deferred (fail-closed, ADV-10)",
    };
  }
  if (topGroups.length > 1) {
    return {
      refuse:
        `existing view has ${topGroups.length} top-level viewFilterGroups — single-flat-group scope only (fail-closed, ADV-10)`,
    };
  }
  const existingGroupId = topGroups.length === 1 ? topGroups[0].id : undefined;
  const filters = existing.filters ?? [];

  if (grouped) {
    const anyUngrouped = filters.some((f) =>
      (f.viewFilterGroupId ?? null) == null
    );
    if (filters.length > 0 && (existingGroupId == null || anyUngrouped)) {
      return {
        refuse:
          `desired is a grouped (${groupOperator}) multi-clause view but the existing view has ungrouped/absent group structure — grouped restructure of an existing view is deferred (fail-closed)`,
      };
    }
  }

  const ops: ViewUpsertOp[] = [];
  let added = 0, removed = 0, patched = 0;
  let groupOpPatched = false;

  const byKey = new Map<string, OppViewFilterRef>();
  for (const f of filters) {
    const k = clauseKey(
      String(f.fieldMetadataId ?? ""),
      f.subFieldName ?? null,
      String(f.operand ?? "").toUpperCase(),
    );
    if (byKey.has(k)) {
      return {
        refuse:
          `existing view has two viewFilters sharing key (fieldMetadataId,subFieldName,operand) — ambiguous, fail-closed (ADV-9)`,
      };
    }
    byKey.set(k, f);
  }
  const desiredKeys = new Set(
    clauses.map((c) => clauseKey(c.fieldMetadataId, c.subFieldName, c.operand)),
  );

  let pos = 0;
  for (const c of clauses) {
    const k = clauseKey(c.fieldMetadataId, c.subFieldName, c.operand);
    const ex = byKey.get(k);
    const desiredValueStr = buildViewFilterValueString(c.values);
    if (!ex) {
      ops.push({
        op: "create-filter",
        fieldMetadataId: c.fieldMetadataId,
        operand: c.operand,
        value: desiredValueStr,
        subFieldName: c.subFieldName,
        grouped,
        position: grouped ? pos : null,
      });
      added++;
    } else {
      const valueDrift = !setEq(normalizeFilterValueTokens(ex.value), c.values);
      const exGrouped = (ex.viewFilterGroupId ?? null) != null;
      const needUngroup = !grouped && exGrouped;
      if (grouped && !exGrouped) {
        return {
          refuse:
            `existing clause ${k} is ungrouped but desired is grouped — grouped restructure deferred (fail-closed)`,
        };
      }
      if (valueDrift || needUngroup) {
        const patch: ViewUpsertOp = {
          op: "patch-filter",
          filterId: String(ex.id),
        };
        if (valueDrift) patch.value = desiredValueStr;
        if (needUngroup) patch.ungroup = true;
        ops.push(patch);
        patched++;
      }
    }
    pos++;
  }

  for (const f of filters) {
    const k = clauseKey(
      String(f.fieldMetadataId ?? ""),
      f.subFieldName ?? null,
      String(f.operand ?? "").toUpperCase(),
    );
    if (!desiredKeys.has(k)) {
      ops.push({ op: "delete-filter", filterId: String(f.id) });
      removed++;
    }
  }

  if (grouped && existingGroupId && groupOperator) {
    if (
      String(topGroups[0].logicalOperator ?? "").toUpperCase() !== groupOperator
    ) {
      ops.push({
        op: "patch-group-operator",
        groupId: existingGroupId,
        logicalOperator: groupOperator,
      });
      // Group-operator drift is a group-level change, NOT a filter patch — kept
      // out of `patched` so the audit doesn't misattribute it to a viewFilter.
      groupOpPatched = true;
    }
  }

  if (grouped && existingGroupId == null) {
    // grouped fresh-in-existing (existing had no filters): create the group first.
    ops.unshift({
      op: "create-group",
      logicalOperator: groupOperator as string,
    });
  }

  if (!grouped && existingGroupId) {
    // ungrouped desired collapses every member out of the existing group; it
    // ends EMPTY, so deleting it is safe (no dangling member — ADV-3). Emitted
    // LAST so it runs after the ungroup patches + member deletes.
    ops.push({ op: "delete-group", groupId: existingGroupId });
  }

  return { ops, added, removed, patched, groupOpPatched, existingGroupId };
}

/**
 * Pure planner for ONE desired opportunity view. Decides create / adopt /
 * reconcile / present / refuse, resolves + validates the desired clauses, proves
 * mutability, and emits the ordered op list the executor applies under confirm.
 * NON-MUTATING by construction.
 */
export function planUpsertOpportunityView(
  desired: DesiredView,
  fieldMeta: Record<
    string,
    { fieldMetadataId?: string; options: string[] } | undefined
  >,
  existingViews: OppViewRef[],
  objectMetadataId: string | undefined,
): ViewUpsertPlan {
  const grouped = (desired.filters?.length ?? 0) > 1;
  const groupOperator = desired.filterGroup
    ? desired.filterGroup.toUpperCase()
    : undefined;
  const base = {
    name: desired.name,
    grouped,
    groupOperator,
    ops: [] as ViewUpsertOp[],
    filtersAdded: 0,
    filtersRemoved: 0,
    filtersPatched: 0,
  };
  const refuse = (
    reason: string,
    extra?: Partial<ViewUpsertPlan>,
  ): ViewUpsertPlan => ({ ...base, action: "refuse", reason, ...extra });

  const name = String(desired.name ?? "").trim();
  if (!name) return refuse("desired view name is empty");
  if (!objectMetadataId) {
    return refuse("opportunity objectMetadataId unresolved — fail-closed");
  }

  const resolved = resolveDesiredClauses(desired, fieldMeta);
  if ("refuse" in resolved) return refuse(resolved.refuse);
  const clauses = resolved.clauses;

  const inObject = existingViews.filter(
    (v) => (v.objectMetadataId ?? objectMetadataId) === objectMetadataId,
  );
  const adoptRef = String(desired.adoptFrom ?? "").trim();

  const nameMatches = inObject.filter((v) => v.name === name);
  if (nameMatches.length > 1) {
    return refuse(
      `${nameMatches.length} views named '${name}' — ambiguous, fail-closed`,
      { viewId: nameMatches[0].id },
    );
  }

  if (nameMatches.length === 1) {
    const view = nameMatches[0];
    if (!viewIsMutable(view)) {
      return refuse(
        `view '${name}' is locked/system (key=${
          JSON.stringify(view.key)
        }, isSystemSideEffect=${view.isSystemSideEffect}, isCustom=${view.isCustom}) — never mutate (fail-closed)`,
        { viewId: view.id },
      );
    }
    const diff = diffExistingView(view, clauses, grouped, groupOperator);
    if ("refuse" in diff) return refuse(diff.refuse, { viewId: view.id });
    if (diff.ops.length === 0) {
      return {
        ...base,
        action: "present",
        reason: "view exists with the desired filters — no change",
        viewId: view.id,
        existingGroupId: diff.existingGroupId,
      };
    }
    // SEC-3: a name-matched view whose filters DIVERGE from desired must not be
    // mutated on a bare confirm re-run — it could be a human-authored view that
    // merely shares the name (this REST surface exposes no swamp-authorship
    // marker; isCustom=true is true of any UI-built view too). Reconciling the
    // divergence requires an explicit adoptFrom opt-in naming THIS view.
    const selfAdopt = adoptRef !== "" &&
      (UUID_RE.test(adoptRef) ? view.id === adoptRef : view.name === adoptRef);
    if (!selfAdopt) {
      return refuse(
        `view '${name}' exists but its filters diverge from desired; refusing to mutate a name-matched view on a bare run — it may be a human-authored view sharing the name (no swamp-authorship marker exists on this API). Set adoptFrom='${name}' (or its viewId) to explicitly opt in to reconciling it (SEC-3).`,
        { viewId: view.id },
      );
    }
    return {
      ...base,
      action: "reconcile",
      reason:
        `reconcile ${diff.added} add / ${diff.removed} remove / ${diff.patched} patch${
          diff.groupOpPatched ? " + group-operator" : ""
        } (adopt-in-place opt-in)`,
      viewId: view.id,
      adoptFrom: adoptRef,
      ops: diff.ops,
      filtersAdded: diff.added,
      filtersRemoved: diff.removed,
      filtersPatched: diff.patched,
      existingGroupId: diff.existingGroupId,
    };
  }

  // ABSENT — adopt (explicit opt-in) or create.
  if (adoptRef !== "") {
    const byId = UUID_RE.test(adoptRef);
    const adoptMatches = inObject.filter(
      (v) => byId ? v.id === adoptRef : v.name === adoptRef,
    );
    if (adoptMatches.length > 1) {
      return refuse(
        `${adoptMatches.length} views match adoptFrom '${adoptRef}' — ambiguous, fail-closed`,
      );
    }
    if (adoptMatches.length === 1) {
      const src = adoptMatches[0];
      if (!viewIsMutable(src)) {
        return refuse(
          `adoptFrom source '${adoptRef}' is locked/system (key=${
            JSON.stringify(src.key)
          }, isSystemSideEffect=${src.isSystemSideEffect}, isCustom=${src.isCustom}) — refuse to adopt (fail-closed, SEC-8)`,
          { viewId: src.id },
        );
      }
      const diff = diffExistingView(src, clauses, grouped, groupOperator);
      if ("refuse" in diff) return refuse(diff.refuse, { viewId: src.id });
      const ops: ViewUpsertOp[] = [
        { op: "rename-view", toName: name },
        ...diff.ops,
      ];
      return {
        ...base,
        action: "adopt",
        reason:
          `adopt (rename '${src.name}' -> '${name}') + reconcile ${diff.added} add / ${diff.removed} remove / ${diff.patched} patch${
            diff.groupOpPatched ? " + group-operator" : ""
          }`,
        viewId: src.id,
        adoptFrom: adoptRef,
        ops,
        filtersAdded: diff.added,
        filtersRemoved: diff.removed,
        filtersPatched: diff.patched,
        existingGroupId: diff.existingGroupId,
      };
    }
    // adoptFrom given but not found -> fall through to create (per spec).
  }

  const createOps: ViewUpsertOp[] = [];
  if (grouped) {
    createOps.push({
      op: "create-group",
      logicalOperator: groupOperator as string,
    });
  }
  let cpos = 0;
  for (const c of clauses) {
    createOps.push({
      op: "create-filter",
      fieldMetadataId: c.fieldMetadataId,
      operand: c.operand,
      value: buildViewFilterValueString(c.values),
      subFieldName: c.subFieldName,
      grouped,
      position: grouped ? cpos : null,
    });
    cpos++;
  }
  return {
    ...base,
    action: "create",
    reason: "no view with this name — create",
    ops: createOps,
    filtersAdded: clauses.length,
  };
}

/** POST a fresh opportunity view; returns its new id (fail-closed on none). */
async function createOppView(
  cfg: TwentyCfg,
  name: string,
  objectMetadataId: string,
): Promise<string> {
  const resp = await twentyRequest(cfg, "POST", "/rest/metadata/views", {
    name,
    objectMetadataId,
    type: "TABLE",
    icon: "IconTable",
  });
  const id = String(
    ((resp as { data?: { id?: string } }).data ?? (resp as { id?: string }))
      ?.id ?? "",
  );
  if (!id) throw new Error("view create returned no id");
  return id;
}

/**
 * Apply a ViewUpsertPlan's ops against the live API (confirm path). For a
 * `create` action it POSTs the view first; a `create-group` id is captured and
 * reused by later grouped `create-filter`s (falling back to the plan's
 * existingGroupId when reusing an existing group). Returns the target viewId.
 */
async function executeViewUpsertPlan(
  cfg: TwentyCfg,
  plan: ViewUpsertPlan,
  objectMetadataId: string,
): Promise<{ viewId: string }> {
  let viewId = plan.viewId ?? "";
  if (plan.action === "create") {
    viewId = await createOppView(cfg, plan.name, objectMetadataId);
  }
  let createdGroupId: string | undefined;
  const groupIdFor = (): string | undefined =>
    createdGroupId ?? plan.existingGroupId;
  for (const op of plan.ops) {
    switch (op.op) {
      case "rename-view":
        await twentyRequest(
          cfg,
          "PATCH",
          `/rest/metadata/views/${encodeURIComponent(viewId)}`,
          { name: op.toName },
        );
        break;
      case "create-group": {
        const resp = await twentyRequest(
          cfg,
          "POST",
          "/rest/metadata/viewFilterGroups",
          { viewId, logicalOperator: op.logicalOperator },
        );
        createdGroupId = String(
          ((resp as { data?: { id?: string } }).data ??
            (resp as { id?: string }))?.id ?? "",
        );
        if (!createdGroupId) {
          throw new Error("viewFilterGroup create returned no id");
        }
        break;
      }
      case "patch-group-operator":
        await twentyRequest(
          cfg,
          "PATCH",
          `/rest/metadata/viewFilterGroups/${encodeURIComponent(op.groupId)}`,
          { logicalOperator: op.logicalOperator },
        );
        break;
      case "delete-group":
        await twentyRequest(
          cfg,
          "DELETE",
          `/rest/metadata/viewFilterGroups/${encodeURIComponent(op.groupId)}`,
        );
        break;
      case "create-filter": {
        const body: Record<string, unknown> = {
          viewId,
          fieldMetadataId: op.fieldMetadataId,
          operand: op.operand,
          value: op.value,
        };
        if (op.subFieldName != null) body.subFieldName = op.subFieldName;
        if (op.grouped) {
          const gid = groupIdFor();
          if (!gid) throw new Error("grouped create-filter has no group id");
          body.viewFilterGroupId = gid;
          body.positionInViewFilterGroup = op.position;
        }
        await twentyRequest(cfg, "POST", "/rest/metadata/viewFilters", body);
        break;
      }
      case "patch-filter": {
        const body: Record<string, unknown> = {};
        if (op.value != null) body.value = op.value;
        if (op.operand != null) body.operand = op.operand;
        if (op.ungroup) {
          body.viewFilterGroupId = null;
          body.positionInViewFilterGroup = null;
        }
        await twentyRequest(
          cfg,
          "PATCH",
          `/rest/metadata/viewFilters/${encodeURIComponent(op.filterId)}`,
          body,
        );
        break;
      }
      case "delete-filter":
        await twentyRequest(
          cfg,
          "DELETE",
          `/rest/metadata/viewFilters/${encodeURIComponent(op.filterId)}`,
        );
        break;
    }
  }
  return { viewId };
}

/** Load opportunity views WITH their viewFilters + viewFilterGroups joined
 * (the reconcile input). Scoped to the opportunity object. */
async function loadOppViewRefs(
  cfg: TwentyCfg,
  oppOid: string,
): Promise<OppViewRef[]> {
  const [views, filters, groups] = await Promise.all([
    fetchMetadataList(cfg, "views"),
    fetchMetadataList(cfg, "viewFilters"),
    fetchMetadataList(cfg, "viewFilterGroups"),
  ]);
  const filtersByView = new Map<string, OppViewFilterRef[]>();
  for (const f of filters as Array<Record<string, unknown>>) {
    const vid = String(f.viewId ?? "");
    if (!vid) continue;
    const arr = filtersByView.get(vid) ?? [];
    arr.push({
      id: String(f.id ?? ""),
      fieldMetadataId: f.fieldMetadataId != null
        ? String(f.fieldMetadataId)
        : undefined,
      operand: f.operand != null ? String(f.operand) : undefined,
      value: f.value,
      subFieldName: (f.subFieldName ?? null) as string | null,
      viewFilterGroupId: (f.viewFilterGroupId ?? null) as string | null,
      positionInViewFilterGroup: (f.positionInViewFilterGroup ?? null) as
        | number
        | null,
    });
    filtersByView.set(vid, arr);
  }
  const groupsByView = new Map<string, OppViewFilterGroupRef[]>();
  for (const g of groups as Array<Record<string, unknown>>) {
    const vid = String(g.viewId ?? "");
    if (!vid) continue;
    const arr = groupsByView.get(vid) ?? [];
    arr.push({
      id: String(g.id ?? ""),
      logicalOperator: g.logicalOperator != null
        ? String(g.logicalOperator)
        : undefined,
      parentViewFilterGroupId: (g.parentViewFilterGroupId ?? null) as
        | string
        | null,
    });
    groupsByView.set(vid, arr);
  }
  const refs: OppViewRef[] = [];
  for (const v of views as Array<Record<string, unknown>>) {
    if (String(v.objectMetadataId ?? "") !== oppOid) continue;
    const id = String(v.id ?? "");
    refs.push({
      id,
      name: String(v.name ?? ""),
      key: (v.key ?? null) as string | null,
      isSystemSideEffect: typeof v.isSystemSideEffect === "boolean"
        ? v.isSystemSideEffect
        : undefined,
      isCustom: typeof v.isCustom === "boolean" ? v.isCustom : undefined,
      objectMetadataId: v.objectMetadataId != null
        ? String(v.objectMetadataId)
        : undefined,
      filters: filtersByView.get(id) ?? [],
      filterGroups: groupsByView.get(id) ?? [],
    });
  }
  return refs;
}

const UpsertViewFilterArg = z.object({
  field: z.string(),
  operand: z.string(),
  values: z.array(z.string()).min(1),
  subFieldName: z.string().nullable().optional(),
});
const UpsertViewArg = z.object({
  name: z.string(),
  filters: z.array(UpsertViewFilterArg).min(1).max(20),
  filterGroup: z.enum(["and", "or"]).optional(),
  adoptFrom: z.string().optional(),
});

/**
 * Fan-out core (repo rule 6): plan + (under confirm) apply a desired LIST of
 * opportunity views in ONE execution. Resolves object + field metadata once,
 * runs a reachability pre-flight, loads existing views once, then per view:
 * plan -> (confirm) execute -> read-back-verify (re-plan the fresh state and
 * assert it converges to `present`). Refuses fail-closed on load/reachability/
 * id gaps and on a duplicate desired name. Returns the viewEnsured2 payload.
 */
async function runViewUpserts(
  cfg: TwentyCfg,
  desiredViews: DesiredView[],
  confirm: boolean,
  dryRun: boolean,
): Promise<Record<string, unknown>> {
  const willWrite = confirm === true && dryRun !== true;
  const fieldNames = Array.from(
    new Set(desiredViews.flatMap((d) => (d.filters ?? []).map((f) => f.field))),
  );
  const { oppOid, fields: fieldMeta } = await resolveOpportunityFilterFields(
    cfg,
    fieldNames.length ? fieldNames : undefined,
  );

  let reachable = false;
  try {
    const r = await rawGet(cfg, "/rest/metadata/views?limit=1");
    reachable = classifyProbe(r.status) === "ok";
  } catch {
    reachable = false;
  }

  let existing: OppViewRef[] = [];
  let existingLoadOk = false;
  if (oppOid) {
    try {
      existing = await loadOppViewRefs(cfg, oppOid);
      existingLoadOk = true;
    } catch {
      existingLoadOk = false;
    }
  }

  const seenNames = new Set<string>();
  const dupNames = new Set<string>();
  const seenAdopt = new Set<string>();
  const dupAdopt = new Set<string>();
  for (const d of desiredViews) {
    const n = String(d.name ?? "").trim();
    if (seenNames.has(n)) dupNames.add(n);
    seenNames.add(n);
    const a = String(d.adoptFrom ?? "").trim();
    if (a !== "") {
      if (seenAdopt.has(a)) dupAdopt.add(a);
      seenAdopt.add(a);
    }
  }

  const results: Array<Record<string, unknown>> = [];
  for (const d of desiredViews) {
    const row: Record<string, unknown> = { name: d.name };
    if (dupNames.has(String(d.name ?? "").trim())) {
      results.push({
        ...row,
        action: "refuse",
        reason:
          `duplicate desired view name '${d.name}' in this request — fail-closed`,
      });
      continue;
    }
    const adoptRefRaw = String(d.adoptFrom ?? "").trim();
    if (adoptRefRaw !== "" && dupAdopt.has(adoptRefRaw)) {
      results.push({
        ...row,
        action: "refuse",
        reason:
          `duplicate adoptFrom '${adoptRefRaw}' across this request — fail-closed (would re-adopt the same view twice, clobbering the first result)`,
      });
      continue;
    }
    // Baseline honesty (applies to dryRun too): if the existing-view list could
    // not be loaded we cannot tell create from present/adopt, so suppress the
    // plan rather than emit a false "will create N views" (CR-2).
    if (oppOid && !existingLoadOk) {
      results.push({
        ...row,
        action: "refuse",
        reason:
          "existing view baseline failed to load — plan suppressed, fail-closed (cannot distinguish create vs present)",
      });
      continue;
    }
    const plan = planUpsertOpportunityView(d, fieldMeta, existing, oppOid);
    row.action = plan.action;
    row.reason = plan.reason;
    if (plan.viewId) row.viewId = plan.viewId;
    if (plan.adoptFrom) row.adoptFrom = plan.adoptFrom;
    row.grouped = plan.grouped;
    if (plan.groupOperator) row.groupOperator = plan.groupOperator;
    row.filtersAdded = plan.filtersAdded;
    row.filtersRemoved = plan.filtersRemoved;
    row.filtersPatched = plan.filtersPatched;

    const mutating = plan.action === "create" || plan.action === "adopt" ||
      plan.action === "reconcile";
    if (mutating && willWrite) {
      // Exec-time guards: nothing was written, so zero the plan counters in the
      // snapshot (CR-5 — a refused row must not imply changes it never made).
      const refusedRow = (reason: string): Record<string, unknown> => ({
        ...row,
        action: "refuse",
        reason,
        filtersAdded: 0,
        filtersRemoved: 0,
        filtersPatched: 0,
      });
      if (!existingLoadOk) {
        results.push(
          refusedRow(
            "existing view list failed to load — fail-closed (won't write blind)",
          ),
        );
        continue;
      }
      if (!reachable) {
        results.push(refusedRow("metadata API not reachable — fail-closed"));
        continue;
      }
      if (!oppOid) {
        results.push(
          refusedRow("opportunity objectMetadataId unresolved — fail-closed"),
        );
        continue;
      }
      try {
        const { viewId } = await executeViewUpsertPlan(cfg, plan, oppOid);
        row.viewId = viewId;
        const fresh = await loadOppViewRefs(cfg, oppOid);
        const verify = planUpsertOpportunityView(
          {
            name: plan.name,
            filters: d.filters,
            filterGroup: d.filterGroup,
          },
          fieldMeta,
          fresh,
          oppOid,
        );
        if (verify.action === "present") {
          row.readBackOk = true;
          row.action = plan.action === "create"
            ? "created"
            : plan.action === "adopt"
            ? "adopted"
            : "reconciled";
          row.reason = plan.reason;
        } else {
          row.readBackOk = false;
          row.action = "failed";
          row.reason =
            `post-write read-back did not converge (residual plan: ${verify.action} — ${verify.reason})`;
        }
        existing = fresh;
      } catch (e) {
        row.action = "failed";
        row.reason = redactError(e, 300, cfg.apiToken);
      }
    }
    results.push(row);
  }

  const count = (a: string): number =>
    results.filter((r) => r.action === a).length;
  return {
    baseUrl: cfg.baseUrl,
    dryRun: !willWrite,
    confirm: confirm === true,
    reachable,
    existingLoadOk,
    objectMetadataId: oppOid,
    results,
    createdCount: count("created"),
    adoptedCount: count("adopted"),
    reconciledCount: count("reconciled"),
    presentCount: count("present"),
    refusedCount: count("refuse"),
    failedCount: count("failed"),
    retrievedAt: new Date().toISOString(),
  };
}

/**
 * Snapshot from upsertOpportunityView(s): per-view plan/outcome for the gated
 * reconciling view writes. dryRun records the plan action (create/adopt/
 * reconcile/present/refuse); confirm records the executed action (created/
 * adopted/reconciled/present/refuse/failed) + read-back verification.
 */
export const ViewEnsured2Schema = z.object({
  baseUrl: z.string(),
  dryRun: z.boolean(),
  confirm: z.boolean(),
  reachable: z.boolean(),
  existingLoadOk: z.boolean(),
  objectMetadataId: z.string().optional(),
  results: z.array(z.object({
    name: z.string(),
    action: z.enum([
      "create",
      "adopt",
      "reconcile",
      "present",
      "refuse",
      "created",
      "adopted",
      "reconciled",
      "failed",
    ]),
    reason: z.string(),
    viewId: z.string().optional(),
    adoptFrom: z.string().optional(),
    grouped: z.boolean().optional(),
    groupOperator: z.string().optional(),
    filtersAdded: z.number().optional(),
    filtersRemoved: z.number().optional(),
    filtersPatched: z.number().optional(),
    readBackOk: z.boolean().optional(),
    error: z.string().optional(),
  })),
  createdCount: z.number(),
  adoptedCount: z.number(),
  reconciledCount: z.number(),
  presentCount: z.number(),
  refusedCount: z.number(),
  failedCount: z.number(),
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
  legalName: z
    .string()
    .optional()
    .describe(
      "Company legal name — emitted by exportCompanies for the YAML back-sync; omitted by listCompanies (which carries id/name/domain only)",
    ),
  createdAt: z.string().optional(),
});

const NoteViewSchema = z.object({
  id: z.string(),
  title: z.string().optional(),
  leadId: z.string().optional(),
  noteHash: z
    .string()
    .optional()
    .describe(
      "Stored KEYED HMAC of the note's title+body (TWENTY-NOTE-RECONCILE) — body-FREE; the reconciler's match key alongside leadId. Absent for legacy/unprovisioned notes (hash-unknown).",
    ),
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
    // listNotesByOpportunity (TWENTY-NOTE-BODY-READ) reuses this snapshot with an
    // opportunityId filter (still body-free — views come from mapNoteView).
    opportunityId: z.string().optional(),
  }),
  items: z.array(NoteViewSchema),
  retrievedAt: z.iso.datetime(),
});

// --- Email/thread read snapshots (TWENTY-EMAIL) -----------------------------
// Body-free by construction (F6/F7): subject/body are presence + length, NEVER
// text; participants are join keys (personId/workspaceMemberId), NEVER handles.

const MessageDirectionSchema = z.enum(["INCOMING", "OUTGOING", "unknown"]);

const ThreadParticipantSchema = z.object({
  personId: z.string().optional(),
  workspaceMemberId: z.string().optional(),
  role: z
    .string()
    .optional()
    .describe("from/to/cc/bcc — a Twenty enum, not PII"),
});

const ThreadTargetSchema = z.object({
  kind: z.enum(["opportunity", "person", "company", "leadId", "workspace"]),
  id: z.string().optional().describe("The requested target id (or leadId)"),
  resolvedKind: z.enum(["opportunity", "person", "company"]).optional(),
  resolvedId: z
    .string()
    .optional()
    .describe("The UUID actually filtered on (a leadId resolves to this)"),
  found: z
    .boolean()
    .describe("False when a leadId did not resolve to any opp/person"),
});

const ThreadSummarySchema = z.object({
  id: z.string(),
  subjectPresent: z.boolean(),
  subjectLength: z.number().describe(
    "Length of the last message subject, NOT the text",
  ),
  messageCount: z.number().describe(
    "Messages read for this thread (bounded by messageLimit)",
  ),
  lastInboundAt: z.string().optional().describe(
    "Coalesced ts of the newest INCOMING message",
  ),
  lastOutboundAt: z.string().optional().describe(
    "Coalesced ts of the newest OUTGOING message",
  ),
  truncated: z.boolean().optional().describe(
    "True when this thread's message read hit the cap (ORD-1-R) — the last-in/out timestamps are from a partial (newest-first) read, not the whole thread",
  ),
  participants: z.array(ThreadParticipantSchema),
});

const ThreadListSchema = z.object({
  baseUrl: z.string(),
  target: ThreadTargetSchema,
  count: z.number().describe("Threads summarized this call"),
  truncated: z.boolean(),
  hasMore: z.boolean(),
  nextCursor: z.string().optional(),
  totalCount: z.number().optional(),
  incomplete: z.boolean(),
  stopReason: ListStopReasonSchema,
  items: z.array(ThreadSummarySchema),
  retrievedAt: z.iso.datetime(),
});

const MessageViewSchema = z.object({
  id: z.string(),
  direction: MessageDirectionSchema,
  subjectPresent: z.boolean(),
  subjectLength: z.number().describe("Subject length, NEVER the subject text"),
  bodyLength: z.number().describe("Body length, NEVER the body text"),
  participants: z.array(ThreadParticipantSchema),
  receivedAt: z.string().optional(),
  createdAt: z.string().optional(),
});

const ThreadDetailSchema = z.object({
  baseUrl: z.string(),
  threadId: z.string(),
  count: z.number().describe("Messages returned this call"),
  truncated: z.boolean(),
  hasMore: z.boolean(),
  nextCursor: z.string().optional(),
  totalCount: z.number().optional(),
  incomplete: z.boolean(),
  stopReason: ListStopReasonSchema,
  messages: z
    .array(MessageViewSchema)
    .describe("Oldest->newest by coalesced receivedAt/createdAt (F15)"),
  retrievedAt: z.iso.datetime(),
});

const ThreadStatusSchema = z.object({
  threadId: z.string(),
  state: z.enum([
    "awaiting-us",
    "sent-unanswered",
    "dormant",
    "empty",
    "unknown",
  ]),
  lastDirection: MessageDirectionSchema,
  lastMessageAt: z.string().optional(),
  ageDays: z.number().optional(),
  messageCount: z.number(),
  truncated: z.boolean().optional().describe(
    "True when the message read hit the cap (ORD-1-R) — the verdict is from a partial (newest-first) read; treat as lower-confidence",
  ),
});

const ThreadStatusReportSchema = z.object({
  baseUrl: z.string(),
  target: ThreadTargetSchema.optional(),
  threadId: z.string().optional().describe(
    "Set when a single thread was scoped",
  ),
  dormantDays: z.number(),
  count: z.number(),
  items: z.array(ThreadStatusSchema),
  retrievedAt: z.iso.datetime(),
});

// --- Email SEND snapshots (TWENTY-EMAIL send) -------------------------------
// PII-conservative by construction (F6/F7): the connected-account list keeps the
// DOMAIN only (never the full handle); the sendRun audit keeps JOIN KEYS +
// connectedAccountId + a hashed recipient + subject/body LENGTHS, never the raw
// `to` / subject / body text.

const ConnectedAccountLiteSchema = z.object({
  id: z.string(),
  provider: z.string(),
  domain: z
    .string()
    .describe(
      "Handle DOMAIN only (for brand-matching) — NEVER the full handle",
    ),
  authFailed: z.boolean(),
  archived: z.boolean(),
});

const ConnectedAccountListSchema = z.object({
  baseUrl: z.string(),
  count: z.number(),
  items: z.array(ConnectedAccountLiteSchema),
  retrievedAt: z.iso.datetime(),
});

const SendRunSchema = z.object({
  baseUrl: z.string(),
  target: ThreadTargetSchema.describe(
    "Target join keys (kind + validated ids)",
  ),
  personId: z.string().optional().describe(
    "Recipient person join key when known",
  ),
  opportunityId: z.string().optional(),
  companyId: z.string().optional(),
  fromBrand: z.string().describe("The resolved brand domain sent AS"),
  brandSource: z.enum(["explicit", "lob-default"]),
  connectedAccountId: z
    .string()
    .describe("The mailbox id sent from — NOT the mailbox email address (F7)"),
  workflowVersionId: z.string().describe(
    "Resolved active Send-Email version (F12)",
  ),
  dedupKey: z
    .string()
    .describe("Opaque hashed dedup marker id (F9/F10) — not the raw inputs"),
  toHash: z
    .string()
    .describe(
      "SHA-256 of the recipient address — the raw `to` is NEVER stored (F7)",
    ),
  subjectLength: z.number().describe(
    "Subject length, NEVER the subject text (F7)",
  ),
  bodyLength: z.number().describe("Body length, NEVER the body text (F7)"),
  status: z.enum(["planned", "sent", "skipped"]),
  dryRun: z.boolean(),
  wouldSend: z.boolean().describe(
    "True on a dry plan that would send when confirmed",
  ),
  sent: z.boolean(),
  skipped: z.boolean().describe(
    "True on a durable dedup hit (idempotent no-op)",
  ),
  dedupRecorded: z
    .boolean()
    .describe(
      "True only when a live send wrote the durable dedup marker (never on dryRun — F10)",
    ),
  workflowRunId: z
    .string()
    .optional()
    .describe(
      "Async run id from runWorkflowVersion (F13) — NOT a sent-message id",
    ),
  at: z.iso.datetime(),
});

// Gated note-BODY read (TWENTY-NOTE-BODY-READ): the sanctioned, per-id,
// confirm-gated exception to the SR-1 body-withholding. Short-TTL resource (see
// registration) — the body markdown IS persisted here (bounded PII-at-rest).
const NoteBodyReadSchema = z.object({
  baseUrl: z.string(),
  found: z.boolean(),
  id: z.string().optional(),
  leadId: z.string().optional(),
  title: z.string().optional(),
  body: z.string().optional().describe("Note bodyV2.markdown, verbatim"),
  bodyMissing: z
    .boolean()
    .optional()
    .describe(
      "found:true but the note has no markdown body (blocknote-only/empty)",
    ),
  createdAt: z.string().optional(),
  updatedAt: z.string().optional(),
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

// Result of a note WRITE (createNote/updateNote/appendNote/linkNote/unlinkNote).
// NEVER carries a note body: only `bodyLength` (S3-bounded free-text `title` is
// kept for audit but the whole resource is short-TTL, see the noteWrite resource).
const NoteWriteSchema = z.object({
  baseUrl: z.string(),
  op: z.enum(["create", "update", "append", "link", "unlink"]),
  action: z.enum([
    "planned-create",
    "created",
    "present",
    "planned-update",
    "updated",
    "planned-append",
    "appended",
    "planned-link",
    "linked",
    "already-linked",
    "planned-unlink",
    "unlinked",
    "not-linked",
    "not-found",
    "refused-blocknote",
  ]),
  id: z.string().optional(),
  found: z.boolean().optional(),
  title: z
    .string()
    .optional()
    .describe("Note title (free text); PII-at-rest bounded by the 3d TTL"),
  leadId: z.string().optional(),
  targetsLinked: z.array(z.string()).optional(),
  targetsFailed: z.array(z.string()).optional(),
  bodyLength: z
    .number()
    .optional()
    .describe("Length of the resulting body — NEVER the body text"),
  bodyHash: z
    .string()
    .optional()
    .describe(
      "The KEYED HMAC-SHA256 (hex) of the note's TITLE+BODY just written — i.e. the value stored on note.noteHash (TWENTY-NOTE-RECONCILE). A KEYED HMAC (SEC-2), never a plain digest, so not an oracle at rest; covers title+body, NOT body-only (ADV-11). Present only when the noteHash field is provisioned and a real create/update stored it; absent otherwise.",
    ),
  dryRun: z.boolean(),
  confirmed: z.boolean(),
  writtenAt: z.iso.datetime(),
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

// TWENTY-OPTION-REMOVE: result of a removeSelectOption run. Emergency-safe
// (SEC-3/ADV-13): only a SINGLE folded refCount is recorded (emergency+non-emergency
// total) — never the split — so neither emergency volume nor an emergency-presence
// bit is inferable. No opportunity names/ids/PII.
const SelectOptionRemovalSchema = z.object({
  baseUrl: z.string(),
  object: z.string(),
  field: z.string(),
  value: z.string(),
  action: z.enum([
    "absent",
    "planned-remove",
    "removed",
    "refused-in-use",
    "refused-default",
    "refused-untrusted-count",
    "refused-drift",
  ]),
  refCount: z
    .number()
    .int()
    .describe(
      "Total opportunities referencing the value at decision time (emergency+non-emergency folded; the split is never recorded). 0 on the removable path.",
    ),
  countTrusted: z
    .boolean()
    .describe(
      "True when a numeric server totalCount was returned for the reference filter (false ⇒ refused-untrusted-count, fail-closed; also false on the pre-count absent/refused-default short-circuits). Whether the filter actually TARGETS the intended field (incl. custom SELECTs like offering) is proven by the OQ8 sandbox positive-control — a pre-prod acceptance gate — not asserted at runtime.",
    ),
  emergencyReadReliable: z
    .boolean()
    .describe(
      "Best-effort: true when a live Opportunity read completed this run (the count GET returned); false when no read was attempted (absent/refused-default short-circuits). Defense-in-depth for ADV-5 — does NOT prove row-level emergency visibility, which is covered by the documented token precondition, not by code.",
    ),
  forced: z.boolean().describe(
    "True when the in-use guard was overridden via force.",
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
    .describe(
      "The resulting (or planned, on dryRun) full option set after removal",
    ),
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

const PERSON_UPSERT_ACTIONS = [
  "created",
  "updated",
  "noop",
  "planned-create",
  "planned-update",
] as const;

export const PersonUpsertSchema = z.object({
  baseUrl: z.string(),
  action: z.enum(PERSON_UPSERT_ACTIONS),
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

// --- Person reconcile snapshot (TWENTY-PERSON-UPSERT) -----------------------
// Per-entry audit for the reconcilePeople fan-out. Carries NO raw PII: index,
// action, which fields were set, the opaque personId/companyId, and a REDACTED
// per-entry error ONLY - never the person name or primaryEmail (deliberately
// unlike companyReconcile, which echoes company name/domain; a Person entry
// carries raw PII, so it is dropped).
const PersonReconcileEntrySchema = z.object({
  index: z.number().int().describe(
    "0-based position in the desired-state list",
  ),
  ok: z.boolean().describe("False when this entry errored (isolated)"),
  action: z.enum(PERSON_UPSERT_ACTIONS).optional(),
  found: z.boolean().optional(),
  personId: z.string().optional(),
  fieldsSet: z.array(z.string()).optional(),
  companyId: z.string().optional(),
  companyLinked: z.boolean().optional(),
  error: z
    .string()
    .optional()
    .describe(
      "Redacted per-entry error (one bad row never aborts the batch; no name/email)",
    ),
});

export const PersonReconcileSchema = z.object({
  baseUrl: z.string(),
  source: z.string().describe("Provenance label for the desired-state list"),
  dryRun: z.boolean(),
  total: z.number().int().describe("Entries in the desired-state list"),
  processed: z.number().int(),
  cap: z.number().int().describe("Per-run entry cap in effect"),
  counts: z
    .record(z.string(), z.number())
    .describe(
      "Tally of actions (incl. noop) + errors across processed entries",
    ),
  converged: z
    .boolean()
    .describe("True when every processed entry is action==noop (clean re-run)"),
  entries: z.array(PersonReconcileEntrySchema),
  retrievedAt: z.iso.datetime(),
});

// --- Company upsert snapshot (TWENTY-COMPANY-UPSERT) ------------------------
// One candidate surfaced on an ambiguous/near match. PII-free by construction:
// company id/name/domain ONLY (never account-owner email or any person field).
const CompanyCandidateSchema = z.object({
  id: z.string(),
  name: z.string().optional(),
  domain: z.string().optional(),
});

const COMPANY_UPSERT_ACTIONS = [
  "planned-create",
  "planned-update",
  "planned-conflict",
  "created",
  "updated",
  "noop",
  "conflict",
] as const;

export const CompanyUpsertSchema = z.object({
  baseUrl: z.string(),
  found: z.boolean().describe("An existing company matched (id/domain/name)"),
  action: z.enum(COMPANY_UPSERT_ACTIONS),
  dryRun: z.boolean(),
  id: z.string().optional(),
  name: z.string().describe("The input company name (sanitized)"),
  domain: z.string().optional().describe("Canonical bare host, if supplied"),
  legalName: z.string().optional(),
  matchedVia: z
    .enum(["id", "domain", "name"])
    .optional()
    .describe("How the existing record was matched, when found"),
  fieldsSet: z
    .array(z.string())
    .describe(
      "Which Company fields the write actually set/changed (none on noop/conflict)",
    ),
  candidates: z
    .array(CompanyCandidateSchema)
    .optional()
    .describe(
      "Non-exact / ambiguous matches surfaced on planned-conflict/conflict (id+name+domain only; no PII)",
    ),
  accountOwnerResolved: z
    .boolean()
    .optional()
    .describe(
      "True when accountOwnerEmail resolved to a workspace member (the id is written; the email NEVER enters this snapshot)",
    ),
  retrievedAt: z.iso.datetime(),
});

// --- Company reconcile snapshot (TWENTY-COMPANY-UPSERT, Section 2a) ---------
const CompanyReconcileEntrySchema = z.object({
  index: z.number().int().describe(
    "0-based position in the desired-state list",
  ),
  name: z.string().optional(),
  domain: z.string().optional(),
  ok: z.boolean().describe("False when this entry errored (isolated)"),
  action: z.enum(COMPANY_UPSERT_ACTIONS).optional(),
  found: z.boolean().optional(),
  id: z.string().optional(),
  matchedVia: z.enum(["id", "domain", "name"]).optional(),
  fieldsSet: z.array(z.string()).optional(),
  candidates: z.array(CompanyCandidateSchema).optional(),
  error: z
    .string()
    .optional()
    .describe("Redacted per-entry error (one bad row never aborts the batch)"),
});

export const CompanyReconcileSchema = z.object({
  baseUrl: z.string(),
  source: z.string().describe("Provenance label for the desired-state list"),
  dryRun: z.boolean(),
  total: z.number().int().describe("Entries in the desired-state list"),
  processed: z.number().int(),
  cap: z.number().int().describe("Per-run entry cap in effect"),
  counts: z
    .record(z.string(), z.number())
    .describe("Tally of actions + errors across processed entries"),
  converged: z
    .boolean()
    .describe("True when every processed entry is action==noop (clean re-run)"),
  entries: z.array(CompanyReconcileEntrySchema),
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
  // Shadow-mode spam annotation (classifyLead). Reported, never acted on in
  // this phase: the lead still syncs regardless of spamFlagged.
  spamScore?: number;
  spamReasons?: string[];
  spamFlagged?: boolean;
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

// --- Company upsert core (TWENTY-COMPANY-UPSERT) ----------------------------

/** PATCH a Company by id with only the provided fields (non-destructive). */
async function updateCompany(
  cfg: TwentyCfg,
  id: string,
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return unwrapRecord(
    await twentyRequest(cfg, "PATCH", `/rest/companies/${id}`, body),
    "updateCompany",
  );
}

/** Create a Company with the full assembled body. */
async function createCompanyFull(
  cfg: TwentyCfg,
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  return unwrapRecord(
    await twentyRequest(cfg, "POST", "/rest/companies", body),
    "createCompany",
  );
}

/**
 * BROAD company fetch for domain dedup (ADV-1): stored domainName values are
 * often full-URL / www-prefixed, so a server `eq` on the bare host misses them
 * and would duplicate. Fetch a candidate SET whose stored domain contains the
 * canonical host substring, then the caller compares client-side after
 * {@link canonicalCompanyHost} on BOTH sides for exact-canonical equality.
 *
 * Tries an `ilike` substring filter on the nested `domainName.primaryLinkUrl`
 * first (fast path); on ANY error — the operator may be unsupported on that
 * nested LINKS subfield (spec openQuestion, could not be verified live without a
 * raw filtered GET) — falls back to a BOUNDED full page-scan filtered
 * client-side. Either way the result is operator-independent and correct.
 */
/**
 * Host-boundary match for the broad-domain re-narrow (ADV-3). A stored canonical
 * host `h` counts as a near-candidate for `canonHost` ONLY when it is the same
 * host, a true subdomain of it, or a registrable parent of it — never an
 * arbitrary substring. This keeps `notacme.com` and `acme.com.au` from being
 * treated as candidates for `acme.com` (which would force a spurious
 * planned-conflict) while still catching `www.acme.com` (canonicalizes equal)
 * and `sub.acme.com`. Errs SAFE: a real same-registrable collision still blocks
 * a create, so we never duplicate.
 */
function hostMatchesDomainScope(h: string, canonHost: string): boolean {
  return h === canonHost ||
    h.endsWith("." + canonHost) ||
    canonHost.endsWith("." + h);
}

async function findCompaniesBroadByDomain(
  cfg: TwentyCfg,
  canonHost: string,
): Promise<Array<Record<string, unknown>>> {
  const enc = encodeURIComponent(`%${canonHost}%`);
  try {
    const json = await twentyRequest(
      cfg,
      "GET",
      `/rest/companies?filter=domainName.primaryLinkUrl[ilike]:${enc}&limit=${PAGE_SIZE}`,
    );
    const list = unwrapList(json, "companies");
    // Defensive client-side re-narrow: keep rows whose canonical host matches on
    // a host boundary (ilike can match loosely / raw-URL noise); a bare
    // substring would misclassify notacme.com / acme.com.au as candidates.
    return list.filter((c) => {
      const h = canonicalCompanyHost(
        (c.domainName as { primaryLinkUrl?: unknown } | undefined)
          ?.primaryLinkUrl,
      );
      return h != null && hostMatchesDomainScope(h, canonHost);
    });
  } catch (_e) {
    // Fallback: bounded full scan, filter client-side by canonical-host substring.
    const page = await listFiltered(
      cfg,
      "companies",
      [],
      MAX_LIST_CAP,
      LIST_ORDER,
    );
    return page.items.filter((c) => {
      const h = canonicalCompanyHost(
        (c.domainName as { primaryLinkUrl?: unknown } | undefined)
          ?.primaryLinkUrl,
      );
      return h != null && hostMatchesDomainScope(h, canonHost);
    });
  }
}

/**
 * Find companies by exact (filter-safe) name, compared CLIENT-SIDE after
 * {@link canonicalCompanyName} (lower/collapse-space). Unlike the legacy
 * {@link findOneCompanyByName}, a real API/network error here ABORTS (throws) —
 * it is NOT swallowed to null, so a transient error can never masquerade as "no
 * match" and fall through to a create (ADV-2). Caller must pass an
 * already-filter-safe name.
 */
async function findCompaniesByNameExact(
  cfg: TwentyCfg,
  name: string,
): Promise<Array<Record<string, unknown>>> {
  const canon = canonicalCompanyName(name);
  const json = await twentyRequest(
    cfg,
    "GET",
    buildFilterPath("/rest/companies", "name", name),
  );
  return unwrapList(json, "companies").filter(
    (c) => canonicalCompanyName(c.name) === canon,
  );
}

/**
 * Fetch the workspace members (bounded) for accountOwnerEmail resolution. A
 * small set in practice; paged defensively without an order_by (the member
 * object's sortable fields are not asserted here). Read-only.
 */
async function fetchWorkspaceMembers(
  cfg: TwentyCfg,
): Promise<Array<Record<string, unknown>>> {
  const out: Array<Record<string, unknown>> = [];
  let cursor: string | undefined;
  for (let page = 0; page < 10; page++) {
    const path = `/rest/workspaceMembers?limit=${PAGE_SIZE}` +
      (cursor ? `&starting_after=${encodeURIComponent(cursor)}` : "");
    const json = await twentyRequest(cfg, "GET", path);
    for (const m of unwrapList(json, "workspaceMembers")) out.push(m);
    const pageInfo = (json as {
      pageInfo?: { hasNextPage?: boolean; endCursor?: string };
    }).pageInfo;
    if (!pageInfo?.hasNextPage || !pageInfo.endCursor) break;
    if (pageInfo.endCursor === cursor) break;
    cursor = pageInfo.endCursor;
  }
  return out;
}

/** A memoizing company-metadata loader (fail-closed-aware), shared per run. */
function makeCompanyMetaLoader(cfg: TwentyCfg) {
  let cache:
    | {
      meta: {
        plural: string;
        fields: Map<string, { type: string; options: string[] }>;
      } | null;
      readable: boolean;
    }
    | undefined;
  return async () => {
    if (cache) return cache;
    try {
      cache = {
        meta: await fetchUpsertObjectMeta(cfg, "company"),
        readable: true,
      };
    } catch (_e) {
      cache = { meta: null, readable: false };
    }
    return cache;
  };
}

/** A memoizing workspace-members loader, shared across a reconcile batch. */
function makeMembersLoader(cfg: TwentyCfg) {
  let cache: Array<Record<string, unknown>> | undefined;
  return async () => {
    if (!cache) cache = await fetchWorkspaceMembers(cfg);
    return cache;
  };
}

/** The typed inputs upsertCompany/reconcileCompanies accept per company. */
export interface CompanyUpsertInput {
  matchBy?: "id" | "domain" | "name" | "auto";
  id?: string;
  name: string;
  domain?: string;
  legalName?: string;
  addressCity?: string;
  addressState?: string;
  addressCountry?: string;
  addressStreet1?: string;
  addressStreet2?: string;
  addressPostcode?: string;
  employees?: number;
  linkedinUrl?: string;
  xUrl?: string;
  idealCustomerProfile?: boolean;
  accountOwnerEmail?: string;
  customFields?: Record<string, string | number | boolean>;
}

type CompanyAction = (typeof COMPANY_UPSERT_ACTIONS)[number];

export interface CompanyUpsertResult {
  found: boolean;
  action: CompanyAction;
  id?: string;
  name: string;
  domain?: string;
  legalName?: string;
  matchedVia?: "id" | "domain" | "name";
  fieldsSet: string[];
  candidates?: Array<{ id: string; name?: string; domain?: string }>;
  accountOwnerResolved?: boolean;
}

/** PII-free candidate view for conflict surfaces (id/name/domain only). */
function companyCandidate(
  rec: Record<string, unknown>,
): { id: string; name?: string; domain?: string } {
  const out: { id: string; name?: string; domain?: string } = {
    id: String(rec.id ?? ""),
  };
  if (rec.name != null && rec.name !== "") out.name = String(rec.name);
  const h = canonicalCompanyHost(
    (rec.domainName as { primaryLinkUrl?: unknown } | undefined)
      ?.primaryLinkUrl,
  );
  if (h) out.domain = h;
  return out;
}

/** The normalized desired-state used to diff a write (post-sanitize). */
interface CompanyDesired {
  name: string;
  domainCanon?: string;
  legalName?: string;
  employees?: number;
  idealCustomerProfile?: boolean;
  linkedinUrl?: string;
  xUrl?: string;
  accountOwnerId?: string;
  address?: Record<string, string>;
  customFields: Record<string, string | number | boolean>;
}

/**
 * Assemble a non-destructive Company write body + the list of fields it sets.
 * On CREATE (existing null) every provided field is written. On UPDATE a field
 * is written ONLY when it differs from the stored value (so a re-run with the
 * same inputs is a true noop, ADV-5); composites (domainName/linkedinLink/xLink/
 * address) are MERGED with the stored object so a partial update never nulls a
 * sibling subfield. `nameToWrite` is decided by the caller (rename policy).
 */
function buildCompanyWrite(
  existing: Record<string, unknown> | null,
  desired: CompanyDesired,
  nameToWrite: string | undefined,
): { body: Record<string, unknown>; fieldsSet: string[] } {
  const body: Record<string, unknown> = {};
  const fieldsSet: string[] = [];
  const create = !existing;

  if (nameToWrite !== undefined) {
    body.name = nameToWrite;
    fieldsSet.push("name");
  }

  // domainName (LINKS composite) — merge, write only when the canonical host changes.
  if (desired.domainCanon) {
    const cur = canonicalCompanyHost(
      (existing?.domainName as { primaryLinkUrl?: unknown } | undefined)
        ?.primaryLinkUrl,
    );
    if (create || cur !== desired.domainCanon) {
      body.domainName = {
        ...((existing?.domainName as Record<string, unknown>) ?? {}),
        primaryLinkUrl: desired.domainCanon,
      };
      fieldsSet.push("domain");
    }
  }

  // Scalars.
  if (desired.legalName !== undefined) {
    if (create || String(existing?.legalName ?? "") !== desired.legalName) {
      body.legalName = desired.legalName;
      fieldsSet.push("legalName");
    }
  }
  if (desired.employees !== undefined) {
    const cur = existing?.employees;
    if (create || Number(cur) !== desired.employees) {
      body.employees = desired.employees;
      fieldsSet.push("employees");
    }
  }
  if (desired.idealCustomerProfile !== undefined) {
    if (
      create ||
      Boolean(existing?.idealCustomerProfile) !== desired.idealCustomerProfile
    ) {
      body.idealCustomerProfile = desired.idealCustomerProfile;
      fieldsSet.push("idealCustomerProfile");
    }
  }
  if (desired.accountOwnerId !== undefined) {
    // Twenty may return the owner FK either flat (`accountOwnerId`) or nested
    // under the resolved relation (`accountOwner.id`). Read EITHER so a re-run
    // with accountOwnerEmail set is a true noop when the owner is unchanged.
    const curOwnerId = String(
      existing?.accountOwnerId ??
        (existing?.accountOwner as { id?: unknown } | undefined)?.id ??
        "",
    );
    if (create || curOwnerId !== desired.accountOwnerId) {
      body.accountOwnerId = desired.accountOwnerId;
      fieldsSet.push("accountOwner");
    }
  }

  // LINKS composites.
  for (
    const [field, val] of [
      ["linkedinLink", desired.linkedinUrl],
      ["xLink", desired.xUrl],
    ] as const
  ) {
    if (val === undefined) continue;
    const cur = String(
      (existing?.[field] as { primaryLinkUrl?: unknown } | undefined)
        ?.primaryLinkUrl ?? "",
    );
    if (create || cur !== val) {
      body[field] = {
        ...((existing?.[field] as Record<string, unknown>) ?? {}),
        primaryLinkUrl: val,
      };
      fieldsSet.push(field === "linkedinLink" ? "linkedinUrl" : "xUrl");
    }
  }

  // ADDRESS composite — merge provided subfields; write when any differs.
  if (desired.address && Object.keys(desired.address).length) {
    const existingAddr =
      (existing?.address as Record<string, unknown> | undefined) ?? {};
    const merged: Record<string, unknown> = { ...existingAddr };
    let changed = create;
    for (const [k, v] of Object.entries(desired.address)) {
      if (String(existingAddr[k] ?? "") !== v) changed = true;
      merged[k] = v;
    }
    if (changed) {
      body.address = merged;
      fieldsSet.push("address");
    }
  }

  // customFields (already validated scalars).
  for (const [k, v] of Object.entries(desired.customFields)) {
    const cur = existing?.[k];
    const same = typeof v === "number"
      ? Number(cur) === v
      : typeof v === "boolean"
      ? Boolean(cur) === v
      : String(cur ?? "") === String(v);
    if (create || !same) {
      body[k] = v;
      fieldsSet.push(k);
    }
  }

  return { body, fieldsSet };
}

/**
 * The idempotent single-company upsert primitive shared by the upsertCompany
 * method and the reconcileCompanies fan-out. Does all I/O via `cfg`; writes NO
 * resource (callers snapshot the returned {@link CompanyUpsertResult}). Match
 * precedence id -> domain -> name; create requires a domain AND zero broad-fetch
 * candidates; a name-only miss, an unmatched explicit id, an unresolved
 * accountOwner, and a fail-closed customFields violation all THROW (abort);
 * ambiguity / near-candidate / domain-hit-name-mismatch resolve to a no-write
 * conflict/planned-conflict result carrying candidates. `dryRun` plans only.
 */
async function upsertCompanyCore(
  cfg: TwentyCfg,
  input: CompanyUpsertInput,
  dryRun: boolean,
  loadMeta: ReturnType<typeof makeCompanyMetaLoader>,
  loadMembers: ReturnType<typeof makeMembersLoader>,
): Promise<CompanyUpsertResult> {
  const matchBy = input.matchBy ?? "auto";
  const name = sanitizeText(input.name, 200);
  if (!name) throw new Error("name is required");

  // Domain: canonicalize + validate shape up front.
  let domainCanon: string | undefined;
  if (input.domain != null && String(input.domain).trim()) {
    const host = canonicalCompanyHost(input.domain);
    if (!host || !validateDomain(host) || !isFilterSafe(host)) {
      throw new Error(`Invalid domain '${sanitizeText(input.domain, 120)}'`);
    }
    domainCanon = host;
  }

  // Explicit id: validate the UUID shape before any path interpolation.
  let idInput: string | undefined;
  if (input.id != null && String(input.id).trim()) {
    const u = validateUuid(input.id);
    if (!u) throw new Error("Invalid id (must be a UUID)");
    idInput = u;
  }
  if (matchBy === "id" && !idInput) {
    throw new Error("matchBy=id requires a valid id");
  }
  if (matchBy === "domain" && !domainCanon) {
    throw new Error("matchBy=domain requires a domain");
  }

  // Typed scalar fields (sanitize / validate; empty => unset/leave-unchanged).
  const legalName = input.legalName != null
    ? (sanitizeText(input.legalName, 200) || undefined)
    : undefined;
  let employees: number | undefined;
  if (input.employees != null) {
    const n = Number(input.employees);
    if (!Number.isInteger(n) || n < 0) {
      throw new Error("employees must be a non-negative integer");
    }
    employees = n;
  }
  const linkedinUrl = input.linkedinUrl != null
    ? (sanitizeText(input.linkedinUrl, 500) || undefined)
    : undefined;
  const xUrl = input.xUrl != null
    ? (sanitizeText(input.xUrl, 500) || undefined)
    : undefined;
  const idealCustomerProfile = input.idealCustomerProfile;
  const address: Record<string, string> = {};
  for (
    const [arg, field] of [
      [input.addressStreet1, "addressStreet1"],
      [input.addressStreet2, "addressStreet2"],
      [input.addressCity, "addressCity"],
      [input.addressState, "addressState"],
      [input.addressCountry, "addressCountry"],
      [input.addressPostcode, "addressPostcode"],
    ] as const
  ) {
    if (arg != null) {
      const s = sanitizeText(arg, 200);
      if (s) address[field] = s;
    }
  }

  // customFields — FAIL-CLOSED (reject whole map if metadata unreadable).
  const validatedCustomFields: Record<string, string | number | boolean> = {};
  const rawCustomFields = input.customFields ?? {};
  if (Object.keys(rawCustomFields).length) {
    const { meta, readable } = await loadMeta();
    if (!readable || !meta) {
      throw new Error(
        "customFields supplied but company field metadata is unreadable — refusing to write (fail-closed)",
      );
    }
    for (const [k, v] of Object.entries(rawCustomFields)) {
      const key = String(k).trim();
      if (!FIELD_NAME_RE.test(key)) {
        throw new Error(
          `Invalid customFields key '${
            sanitizeText(key, 80)
          }': must be a camelCase identifier (letter-led, alphanumeric)`,
        );
      }
      const safeKey = sanitizeText(key, 80);
      if (COMPANY_CUSTOMFIELDS_RESERVED.has(key)) {
        throw new Error(
          `customFields key '${safeKey}' is reserved — set it via its typed argument, not customFields`,
        );
      }
      if (v === null) {
        throw new Error(
          `customFields key '${safeKey}' is null; null is not permitted (omit the key to leave the field unchanged)`,
        );
      }
      const fMeta = meta.fields.get(key);
      if (!fMeta) {
        throw new Error(
          `Unknown customFields key '${safeKey}' on company (fail-closed; refusing to write an unrecognized field)`,
        );
      }
      if (!UPSERT_SCALAR_TYPES.has(fMeta.type)) {
        throw new Error(
          `customFields key '${safeKey}' has non-scalar type '${fMeta.type}' (allowed: ${
            [...UPSERT_SCALAR_TYPES].join(", ")
          }); composite fields are not supported`,
        );
      }
      if (typeof v === "number" && !Number.isFinite(v)) {
        throw new Error(
          `customFields key '${safeKey}' is a non-finite number (Infinity/NaN); only finite numeric values are permitted`,
        );
      }
      let out: string | number | boolean = v;
      if (typeof v === "string") {
        const s = sanitizeText(v, UPSERT_FIELD_TEXT_CAP);
        if (!s) continue; // empty-string => omit (leave unchanged)
        out = s;
      }
      if (fMeta.type === "SELECT") {
        const token = String(out);
        if (fMeta.options.length && !fMeta.options.includes(token)) {
          throw new Error(
            `Invalid value '${token}' for SELECT customFields key '${safeKey}'. Valid options: ${
              fMeta.options.join(", ")
            }`,
          );
        }
      }
      validatedCustomFields[key] = out;
    }
  }

  // accountOwnerEmail -> opaque workspaceMemberId. The email is validated +
  // filter-safe-guarded and NEVER enters the result snapshot (SEC-5/SEC-10);
  // an unresolved owner ABORTS (ADV-9).
  let accountOwnerId: string | undefined;
  let accountOwnerResolved: boolean | undefined;
  if (
    input.accountOwnerEmail != null && String(input.accountOwnerEmail).trim()
  ) {
    const email = validateEmail(input.accountOwnerEmail);
    if (!email) throw new Error("Invalid accountOwnerEmail");
    if (!isFilterSafe(email)) {
      throw new Error("accountOwnerEmail has filter-unsafe characters");
    }
    const members = await loadMembers();
    const match = members.find(
      (m) => String(m.userEmail ?? "").toLowerCase() === email,
    );
    if (!match || !match.id) {
      throw new Error(
        "accountOwnerEmail did not resolve to a workspace member",
      );
    }
    accountOwnerId = String(match.id);
    accountOwnerResolved = true;
  }

  const desired: CompanyDesired = {
    name,
    domainCanon,
    legalName,
    employees,
    idealCustomerProfile,
    linkedinUrl,
    xUrl,
    accountOwnerId,
    ...(Object.keys(address).length ? { address } : {}),
    customFields: validatedCustomFields,
  };

  // --- MATCH precedence: id -> domain -> name --------------------------------
  let existing: Record<string, unknown> | null = null;
  let matchedVia: "id" | "domain" | "name" | undefined;

  if (idInput || matchBy === "id") {
    existing = await getCompanyById(cfg, idInput!);
    if (!existing) throw new Error(`company id not found: ${idInput}`); // ADV-12
    matchedVia = "id";
  } else if (domainCanon && matchBy !== "name") {
    const cands = await findCompaniesBroadByDomain(cfg, domainCanon);
    const exact = cands.filter(
      (c) =>
        canonicalCompanyHost(
          (c.domainName as { primaryLinkUrl?: unknown } | undefined)
            ?.primaryLinkUrl,
        ) === domainCanon,
    );
    if (exact.length > 1) {
      return {
        found: true,
        action: "conflict",
        name,
        ...(domainCanon ? { domain: domainCanon } : {}),
        ...(legalName ? { legalName } : {}),
        matchedVia: "domain",
        fieldsSet: [],
        candidates: exact.map(companyCandidate),
        ...(accountOwnerResolved ? { accountOwnerResolved } : {}),
      };
    }
    if (exact.length === 1) {
      existing = exact[0];
      matchedVia = "domain";
    } else {
      // Zero exact. Create ONLY when the broad fetch returned ZERO candidates;
      // otherwise a near-candidate blocks the create (planned-conflict, ADV-1).
      if (cands.length > 0) {
        return {
          found: false,
          action: "planned-conflict",
          name,
          domain: domainCanon,
          ...(legalName ? { legalName } : {}),
          fieldsSet: [],
          candidates: cands.map(companyCandidate),
          ...(accountOwnerResolved ? { accountOwnerResolved } : {}),
        };
      }
      // existing stays null -> CREATE path below.
    }
  } else {
    // NAME fallback (only reachable with no id and no usable domain match path).
    if (!isFilterSafe(name)) {
      throw new Error(
        "Refusing to create a company: name has filter-unsafe characters and no domain to dedup/create by",
      );
    }
    const matches = await findCompaniesByNameExact(cfg, name);
    if (matches.length > 1) {
      return {
        found: true,
        action: "conflict",
        name,
        ...(legalName ? { legalName } : {}),
        matchedVia: "name",
        fieldsSet: [],
        candidates: matches.map(companyCandidate),
        ...(accountOwnerResolved ? { accountOwnerResolved } : {}),
      };
    }
    if (matches.length === 1) {
      existing = matches[0];
      matchedVia = "name";
    } else {
      // Name-only miss with no domain: no stable key -> refuse to create.
      throw new Error(
        "Refusing to create a company without a domain: a name-only entry has no stable dedup key (provide a domain)",
      );
    }
  }

  // --- Domain-hit name-conflict guard (ADV-4): never silently rename ---------
  if (
    existing && matchedVia === "domain" &&
    canonicalCompanyName(name) !== canonicalCompanyName(existing.name)
  ) {
    return {
      found: true,
      action: "conflict",
      id: String(existing.id ?? ""),
      name,
      domain: domainCanon,
      ...(legalName ? { legalName } : {}),
      matchedVia: "domain",
      fieldsSet: [],
      candidates: [companyCandidate(existing)],
      ...(accountOwnerResolved ? { accountOwnerResolved } : {}),
    };
  }

  // --- CREATE ---------------------------------------------------------------
  if (!existing) {
    // Reachable only on the domain-create path (domainCanon set, zero candidates).
    const nameToWrite = name;
    const { body, fieldsSet } = buildCompanyWrite(null, desired, nameToWrite);
    if (dryRun) {
      return {
        found: false,
        action: "planned-create",
        name,
        domain: domainCanon,
        ...(legalName ? { legalName } : {}),
        fieldsSet,
        ...(accountOwnerResolved ? { accountOwnerResolved } : {}),
      };
    }
    try {
      const created = await createCompanyFull(cfg, body);
      return {
        found: false,
        action: "created",
        id: String(created.id ?? ""),
        name,
        domain: domainCanon,
        ...(legalName ? { legalName } : {}),
        fieldsSet,
        ...(accountOwnerResolved ? { accountOwnerResolved } : {}),
      };
    } catch (e) {
      // Create-race convergence (PU-1): a concurrent run may have created the
      // same domain between our broad fetch and POST — converge onto it.
      const raced = (await findCompaniesBroadByDomain(cfg, domainCanon!))
        .filter(
          (c) =>
            canonicalCompanyHost(
              (c.domainName as { primaryLinkUrl?: unknown } | undefined)
                ?.primaryLinkUrl,
            ) === domainCanon,
        );
      if (raced.length === 1) {
        const rec = raced[0];
        const id = String(rec.id ?? "");
        // Converged onto a domain match: never silent-rename (nameToWrite undefined).
        const { body: ub, fieldsSet: uf } = buildCompanyWrite(
          rec,
          desired,
          undefined,
        );
        if (uf.length) await updateCompany(cfg, id, ub);
        return {
          found: true,
          action: uf.length ? "updated" : "noop",
          id,
          name,
          domain: domainCanon,
          ...(legalName ? { legalName } : {}),
          matchedVia: "domain",
          fieldsSet: uf,
          ...(accountOwnerResolved ? { accountOwnerResolved } : {}),
        };
      }
      throw e;
    }
  }

  // --- UPDATE / NOOP --------------------------------------------------------
  const id = String(existing.id ?? "");
  // Rename policy: never on a domain match (conflict-guarded above); on an id or
  // name match write the name only when it canonically differs (idempotent).
  const nameToWrite = matchedVia !== "domain" &&
      canonicalCompanyName(name) !== canonicalCompanyName(existing.name)
    ? name
    : undefined;
  const { body, fieldsSet } = buildCompanyWrite(existing, desired, nameToWrite);
  const storedDomain = canonicalCompanyHost(
    (existing.domainName as { primaryLinkUrl?: unknown } | undefined)
      ?.primaryLinkUrl,
  ) ?? domainCanon;
  if (fieldsSet.length === 0) {
    return {
      found: true,
      action: "noop",
      id,
      name,
      ...(storedDomain ? { domain: storedDomain } : {}),
      ...(legalName ? { legalName } : {}),
      matchedVia,
      fieldsSet,
      ...(accountOwnerResolved ? { accountOwnerResolved } : {}),
    };
  }
  if (dryRun) {
    return {
      found: true,
      action: "planned-update",
      id,
      name,
      ...(storedDomain ? { domain: storedDomain } : {}),
      ...(legalName ? { legalName } : {}),
      matchedVia,
      fieldsSet,
      ...(accountOwnerResolved ? { accountOwnerResolved } : {}),
    };
  }
  await updateCompany(cfg, id, body);
  return {
    found: true,
    action: "updated",
    id,
    name,
    ...(storedDomain ? { domain: storedDomain } : {}),
    ...(legalName ? { legalName } : {}),
    matchedVia,
    fieldsSet,
    ...(accountOwnerResolved ? { accountOwnerResolved } : {}),
  };
}

// --- Person upsert core (TWENTY-PERSON-UPSERT) -----------------------------

/** The typed inputs upsertPerson/reconcilePeople accept per person. */
export interface PersonUpsertInput {
  primaryEmail: string;
  firstName?: string;
  lastName?: string;
  // Full name; split into first/last when firstName/lastName are omitted.
  name?: string;
  phone?: string;
  jobTitle?: string;
  city?: string;
  companyDomain?: string;
  companyName?: string;
}

type PersonAction = (typeof PERSON_UPSERT_ACTIONS)[number];

export interface PersonUpsertResult {
  found: boolean;
  action: PersonAction;
  personId?: string;
  fieldsSet: string[];
  companyId?: string;
  companyLinked: boolean;
  companyNote?: string;
}

/** The normalized desired-state used to diff a Person write (post-sanitize). */
interface PersonDesired {
  nameProvided: boolean;
  providedFirst?: string;
  providedLast?: string;
  phone?: string; // normalized; falsy => leave unchanged
  jobTitle?: string; // undefined => not provided (empty is treated as unset)
  city?: string; // undefined => not provided
  companyId?: string; // undefined => no company resolved
}

/**
 * Assemble a non-destructive Person write body + the list of fields it sets. On
 * CREATE (existing null) the name is always written (empty where unset) plus
 * every provided field. On UPDATE a field is written ONLY when it differs from
 * the stored value (so a re-run with the same inputs is a true noop); the name
 * is MERGED so a partial {firstName|lastName} - or a single-token `name` whose
 * split half is empty - never nulls the other subfield (PU-2). Mirrors
 * {@link buildCompanyWrite}.
 */
function buildPersonWrite(
  existing: Record<string, unknown> | null,
  d: PersonDesired,
): { fields: PersonWriteFields; fieldsSet: string[] } {
  const create = !existing;
  const fields: PersonWriteFields = {};
  const fieldsSet: string[] = [];

  // name - always written on create; merged + diffed on update (PU-2).
  if (create) {
    fields.name = {
      firstName: d.providedFirst ?? "",
      lastName: d.providedLast ?? "",
    };
    fieldsSet.push("name");
  } else if (d.nameProvided) {
    const en =
      (existing!.name as { firstName?: unknown; lastName?: unknown }) ?? {};
    const curFirst = String(en.firstName ?? "");
    const curLast = String(en.lastName ?? "");
    // Merge: an EMPTY provided half falls back to existing so a single-token
    // name never nulls the other subfield. Use `||`, not `??` - the empty
    // string is exactly the case we must fall back to existing on.
    const merged = {
      firstName: d.providedFirst || curFirst,
      lastName: d.providedLast || curLast,
    };
    if (merged.firstName !== curFirst || merged.lastName !== curLast) {
      fields.name = merged;
      fieldsSet.push("name");
    }
  }

  // phone - write only when provided AND changed.
  if (d.phone) {
    const cur = String(
      (existing?.phones as { primaryPhoneNumber?: unknown } | undefined)
        ?.primaryPhoneNumber ?? "",
    );
    if (create || cur !== d.phone) {
      fields.phone = d.phone;
      fieldsSet.push("phone");
    }
  }

  // jobTitle / city scalars - write only when provided AND changed.
  if (d.jobTitle !== undefined) {
    if (create || String(existing?.jobTitle ?? "") !== d.jobTitle) {
      fields.jobTitle = d.jobTitle;
      fieldsSet.push("jobTitle");
    }
  }
  if (d.city !== undefined) {
    if (create || String(existing?.city ?? "") !== d.city) {
      fields.city = d.city;
      fieldsSet.push("city");
    }
  }

  // company link - write only when a company resolved AND it differs. Read the
  // FK flat (`companyId`) OR nested (`company.id`), like buildCompanyWrite's
  // accountOwner, so a re-run with the same company is a true noop.
  if (d.companyId) {
    const cur = String(
      existing?.companyId ??
        (existing?.company as { id?: unknown } | undefined)?.id ??
        "",
    );
    if (create || cur !== d.companyId) {
      fields.companyId = d.companyId;
      fieldsSet.push("company");
    }
  }

  return { fields, fieldsSet };
}

/**
 * The idempotent single-person upsert primitive shared by the upsertPerson
 * method and the reconcilePeople fan-out. Does all I/O via `cfg`; writes NO
 * resource (callers snapshot the returned {@link PersonUpsertResult}). Keyed on
 * primaryEmail: on a match with NO changed field returns action='noop' and
 * issues NO PATCH; on a match WITH changes PATCHes ONLY the changed provided
 * fields (never clobbering an unset field, never nulling a partial-name
 * subfield); on a miss creates. NEVER stamps a leadId (curated contacts stay
 * out of the lead namespace). An optional company link is deduped by domain
 * then exact name and created ONLY when a domain is supplied. `dryRun` plans
 * only. Mirrors {@link upsertCompanyCore}.
 */
async function upsertPersonCore(
  cfg: TwentyCfg,
  input: PersonUpsertInput,
  dryRun: boolean,
): Promise<PersonUpsertResult> {
  const email = validateEmail(input.primaryEmail);
  if (!email) throw new Error("Invalid email");

  // Resolve the provided name parts. A single `name` splits into first/last;
  // explicit firstName/lastName win. `nameProvided` gates whether an update
  // touches the name at all (PU-2).
  let providedFirst: string | undefined;
  let providedLast: string | undefined;
  if (input.name != null && String(input.name).trim()) {
    const sp = splitName(input.name);
    providedFirst = sp.firstName;
    providedLast = sp.lastName;
  } else {
    if (input.firstName != null) {
      providedFirst = sanitizeText(input.firstName, 120);
    }
    if (input.lastName != null) {
      providedLast = sanitizeText(input.lastName, 120);
    }
  }
  const nameProvided = providedFirst !== undefined ||
    providedLast !== undefined;

  // Non-name fields, included only when actually provided + non-empty.
  const phone = input.phone != null ? normalizePhone(input.phone) : "";
  const jobTitle = input.jobTitle != null
    ? (sanitizeText(input.jobTitle, 120) || undefined)
    : undefined;
  const city = input.city != null
    ? (sanitizeText(input.city, 120) || undefined)
    : undefined;

  // Company (optional): dedup by domain, else exact filter-safe name. Create
  // ONLY when a domain is supplied; a name-only miss is left unlinked
  // (recorded), mirroring upsertOpportunity to avoid duplicates.
  let companyId: string | undefined;
  let companyNote: string | undefined;
  const companyName = sanitizeText(input.companyName, 120);
  const companyDomain = validateDomain(input.companyDomain) ?? undefined;
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
    } else if (companyDomain && !dryRun) {
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

  const companyLinked = Boolean(companyId);
  const desired: PersonDesired = {
    nameProvided,
    providedFirst,
    providedLast,
    ...(phone ? { phone } : {}),
    ...(jobTitle !== undefined ? { jobTitle } : {}),
    ...(city !== undefined ? { city } : {}),
    ...(companyId ? { companyId } : {}),
  };

  // Idempotency lookup - decides create vs update/noop.
  const existingPerson = await findOnePersonByEmail(cfg, email);

  // --- CREATE ---------------------------------------------------------------
  if (!existingPerson) {
    const { fields, fieldsSet } = buildPersonWrite(null, desired);
    if (dryRun) {
      return {
        found: false,
        action: "planned-create",
        fieldsSet,
        ...(companyId ? { companyId } : {}),
        companyLinked,
        ...(companyNote ? { companyNote } : {}),
      };
    }
    try {
      const created = await createPersonCurated(cfg, email, fields);
      const personId = String(created.record.id ?? "");
      const setFields = fieldsSet.filter(
        (k) => !(created.phoneDropped && k === "phone"),
      );
      return {
        found: false,
        action: "created",
        ...(personId ? { personId } : {}),
        fieldsSet: setFields,
        ...(companyId ? { companyId } : {}),
        companyLinked,
        ...(companyNote ? { companyNote } : {}),
      };
    } catch (e) {
      // PU-1: a concurrent run may have created this email between our lookup
      // and POST - converge onto it instead of duplicating.
      const raced = await findOnePersonByEmail(cfg, email);
      if (!raced) throw e;
      const personId = String(raced.id ?? "");
      const { fields: uf, fieldsSet: us } = buildPersonWrite(raced, desired);
      let phoneDropped = false;
      if (us.length) {
        const res = await updatePerson(cfg, personId, uf);
        phoneDropped = res.phoneDropped;
      }
      const setFields = us.filter((k) => !(phoneDropped && k === "phone"));
      return {
        found: true,
        action: us.length ? "updated" : "noop",
        ...(personId ? { personId } : {}),
        fieldsSet: setFields,
        ...(companyId ? { companyId } : {}),
        companyLinked,
        ...(companyNote ? { companyNote } : {}),
      };
    }
  }

  // --- UPDATE / NOOP --------------------------------------------------------
  const personId = String(existingPerson.id ?? "");
  const { fields, fieldsSet } = buildPersonWrite(existingPerson, desired);
  if (fieldsSet.length === 0) {
    return {
      found: true,
      action: "noop",
      ...(personId ? { personId } : {}),
      fieldsSet: [],
      ...(companyId ? { companyId } : {}),
      companyLinked,
      ...(companyNote ? { companyNote } : {}),
    };
  }
  if (dryRun) {
    return {
      found: true,
      action: "planned-update",
      ...(personId ? { personId } : {}),
      fieldsSet,
      ...(companyId ? { companyId } : {}),
      companyLinked,
      ...(companyNote ? { companyNote } : {}),
    };
  }
  const res = await updatePerson(cfg, personId, fields);
  const setFields = fieldsSet.filter((k) =>
    !(res.phoneDropped && k === "phone")
  );
  return {
    found: true,
    action: "updated",
    ...(personId ? { personId } : {}),
    fieldsSet: setFields,
    ...(companyId ? { companyId } : {}),
    companyLinked,
    ...(companyNote ? { companyNote } : {}),
  };
}

// --- Model ------------------------------------------------------------------

export const model = {
  type: "@shrug/twenty",
  version: "2026.11.10.1",
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
    {
      toVersion: "2026.09.16.1",
      description:
        "Teach upsertOpportunity to write the provider-pipeline Opportunity custom fields: optional asn (TEXT, ^AS<digits>$ guard) and qualStatus (SELECT, validated against the live enum like stage), plus a generic customFields scalar escape hatch (fail-closed: keys must exist and be scalar; reserved keys — the leadId marker + every typed-arg field + system fields — and composite/unknown types rejected pre-write; SELECT validated against the live enum; empty-string omitted; null forbidden). Fields written on both create and update, omitted (never nulled) when unset, and surfaced in the opportunityUpsert/opportunityRef/opportunityList read-back snapshots. Additive method arguments + optional snapshot fields only; globalArguments is unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.16.2",
      description:
        "Add the Opportunity `offering` segmentation SELECT (MANAGED/SUBSTRATE/PROJECT/RETAINER/LOCAL_IT/PEERING): provisioned append-safe via OPPORTUNITY_SEGMENTATION_FIELDS/ensureOpportunitySegmentation; a new optional upsertOpportunity offering arg (sanitized + live-enum validated like stage, written on create+update, omitted-not-nulled when unset, added to OPP_CUSTOMFIELDS_RESERVED so customFields cannot shadow it); surfaced in mapOppView + the opportunityUpsert/opportunityRef/opportunityList read-back snapshots. Additive method argument + optional snapshot fields + one manifest entry only; globalArguments is unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.16.3",
      description:
        "Add upsertOpportunity channelPartner linking (TWENTY-OPP-CHANNEL) for marketplace attribution: a channelPartnerId arg (UUID, validated early so it fails pre-write even under dryRun; sets the opportunity.channelPartner MANY_TO_ONE FK like companyId) and a channelPartnerName resolver (link-only find-by-name via the new findOneChannelPartnerByName; channelPartnerId wins; a name with no match records channelPartnerSkipped, never creates a partner). Both channelPartnerId and channelPartner added to OPP_CUSTOMFIELDS_RESERVED; channelPartnerId surfaced in mapOppView + the opportunityUpsert/opportunityRef/opportunityList read-back snapshots. Additive method arguments + optional snapshot fields only; globalArguments is unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.16.4",
      description:
        "Add note-body access (TWENTY-NOTE-BODY-READ): getNoteBody(noteId, confirm=true) — the sanctioned, per-id, confirm-gated SR-1 exception that returns ONE note's bodyV2.markdown to a short-TTL (3d) noteBodyRead snapshot (found:false on 404; bodyMissing:true when found with no markdown; title verbatim on this gated method only) — and listNotesByOpportunity(opportunityId), a body-FREE discovery read over the noteTargets join returning mapNoteView views into a note-list-opp-<id> noteList snapshot. listNotes/mapNoteView/NoteView are UNCHANGED (still body-free + title-guarded). Additive methods + one new resource + a NoteListSchema.filter.opportunityId; globalArguments unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.17.1",
      description:
        "Add CRM pipeline analytics (TWENTY-DASHBOARDS): aggregateOpportunities — a read-only fan-out that aggregates all Opportunities into a PII-free oppAggregates snapshot (counts + per-currency sums by stage/lineOfBusiness/sourceChannel, open-pipeline, win/loss + win rate, active customers; isEmergency excluded by default) — plus a folded-in read-only Core-GraphQL transport (twentyGraphQL) and a verify-first GraphQL probe recorded on the snapshot. Additive method + one new resource; globalArguments unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.17.2",
      description:
        "Add full Note management (TWENTY-NOTE-MGMT): createNote/updateNote/appendNote/linkNote/unlinkNote — confirm-gated, dryRun-by-default write surface over /rest/notes + /rest/noteTargets (ensureNoteForLead refactored to a thin wrapper over the shared create+link core), plus a short-TTL noteWrite snapshot (no body text). appendNote reads the existing body across the SR-1 boundary only under confirm; body writes refuse on a note with a non-empty blocknote until markdown re-derivation is proven. Also folds in the .17.1 adversarial-review remediation: a string/comment-aware read-only twentyGraphQL guard, redaction of listViews' sample + ensureOpportunityViews' errors. Additive methods + one new resource; globalArguments unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.17.3",
      description:
        "Add removeSelectOption (TWENTY-OPTION-REMOVE): confirm-gated, allowlisted, fail-closed retirement of a SELECT option from an opportunity picklist (stage/sourceChannel/lineOfBusiness/offering) — the reverse of ensureStageOption. Reads the full option set + normalized defaultValue, refuses when the value is the field default / still referenced by any opportunity (authoritative server-side totalCount, fail-closed on no-total) / on a concurrent option-array edit; force overrides the in-use refusal only with a matching expectedInUseCount ack. Adds the selectOptionRemoval snapshot (folded refCount, no PII). globalArguments unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.18.1",
      description:
        'Add note reconciliation (TWENTY-NOTE-RECONCILE), extension scope A+B: ensureNoteFields provisions a noteHash (TEXT) field on Note; a keyed HMAC-SHA256 hashNote helper (canonical title+body serialization) stamps noteHash on createNote/updateNote when the field is provisioned (fail-closed on an empty key, SEC-5), surfaced body-free on listNotes/mapNoteView/NoteView and recorded as noteWrite.bodyHash. push_leads/ensureNoteForLead are UNCHANGED — the lead sink never hashes. globalArguments gains one OPTIONAL SENSITIVE field, noteHashHmacKey (default "", length-only logging, never snapshotted), so this is a no-op attribute migration — existing instances lazily acquire the empty default and behave identically until it is set (and until note.noteHash is provisioned).',
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.19.1",
      description:
        "Add opportunity view UPSERT (TWENTY-VIEW-UPSERT): the additive, reconciling upsertOpportunityView / upsertOpportunityViews methods (create / adopt+rename / reconcile-filters / present no-op / fail-closed refuse) + the viewEnsured2 snapshot with the extended action set. The create-only ensureOpportunityViews + its viewEnsured snapshot are UNCHANGED (ADV-6). Reconcile is keyed on (fieldMetadataId, subFieldName, operand, viewFilterGroupId), writes the UI stringified value form, verifies every write with a read-back, never mutates a non-isCustom/locked/system view, and never blind-deletes a viewFilterGroup. globalArguments is unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.09.21.1",
      description:
        "Add the email READ + SEND surface (TWENTY-EMAIL). READ: read-only listThreads / getThread / threadStatus over Twenty's message tables (messageThread/message/messageParticipant/messageThreadTarget + messageChannelMessageAssociation) + threadList/threadDetail/threadStatus snapshots — all BODY-FREE (F6), direction authoritative from the association (F8), receivedAt-null-safe ordering (F15), every filtered id UUID-validated + filter-safe with the correct polymorphic field (F11/F18). SEND: listConnectedAccounts (USER-token, domain-only connectedAccountList snapshot) + sendEmail (dry-by-default, confirm-gated, fail-closed brand pinning via runWorkflowVersion) + the connectedAccountList/sendRun snapshots — the sendRun audit is PII-conservative (join keys + connectedAccountId + hashed recipient + subject/body lengths, never raw text; F6/F7). Sending mints a per-run workspace-member USER access token (the API_KEY token is forbidden on runWorkflowVersion/myConnectedAccounts; F1b) from vaulted credentials. globalArguments gains SIX new OPTIONAL/defaulted fields — sendUserEmail, sendUserPassword (both SENSITIVE, empty default), brandConnectedAccounts ({} default, load-validated at first send), lineOfBusinessBrand ({} default), sendWorkflowName ('Send Email' default), twentyOrigin ('' default = baseUrl) — so this remains a no-op attribute migration: existing instances lazily acquire the defaults and behave identically (the send methods refuse fail-closed until the credentials + brand map are set).",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.11.07.1",
      description:
        "Add the curated Company write surface (TWENTY-COMPANY-UPSERT): upsertCompany (idempotent, dryRun-DEFAULT, confirm-gated; id->domain->name match with www/registrable-host canonical dedup and a zero-candidate create-guard; non-destructive composite-merge updates; fail-closed customFields; accountOwnerEmail->opaque workspaceMemberId with the email kept out of the snapshot), reconcileCompanies (declarative fan-out over a desired-state list" +
        " with per-entry isolation, a mandatory entry cap, no reconcile-delete, and noop convergence), and exportCompanies (scrubbed id/name/domain/legalName back-sync). Adds the companyUpsert + companyReconcile resources and an optional legalName on the company view; reuses the existing companyList resource for the export. globalArguments is unchanged, so this is a no-op attribute migration.",
      upgradeAttributes: (
        old: Record<string, unknown>,
      ): Record<string, unknown> => old,
    },
    {
      toVersion: "2026.11.10.1",
      description:
        "Add the declarative Person write fan-out (TWENTY-PERSON-UPSERT): upsertPersonCore (the shared single-person find-or-create primitive with field-diff/noop detection - reused by upsertPerson, which now returns noop on an unchanged re-run and no longer issues an unconditional PATCH), reconcilePeople (declarative fan-out over a desired-state person list with primaryEmail-first match, per-entry isolation that records a redacted error + index ONLY - never the person name or primaryEmail, a mandatory entry cap, no reconcile-delete, and noop convergence), and the scoped peopleReconcile audit snapshot (no raw PII). Widens the personUpsert action enum to include noop. globalArguments is unchanged, so this is a no-op attribute migration.",
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
    "viewList": {
      description:
        "Snapshot from listViews: the Phase-0 view probe — endpoint verdicts, opportunity views, and a raw sample for lock-flag/viewFilter shape discovery.",
      schema: ViewListSchema,
      lifetime: "3d",
      garbageCollection: 5,
    },
    "viewEnsured": {
      description:
        "Snapshot from ensureOpportunityViews: per-target plan/outcome for the gated Opportunity view creates (action create/noop/refuse in dryRun; created/failed under confirm) + reachability. Audit trail of what swamp created.",
      schema: ViewEnsuredSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "viewEnsured2": {
      description:
        "Snapshot from upsertOpportunityView(s): per-view plan/outcome for the gated reconciling Opportunity view writes (create/adopt/reconcile/present/refuse in dryRun; created/adopted/reconciled/present/refuse/failed under confirm) + read-back verification + reachability. Audit trail of what swamp reconciled.",
      schema: ViewEnsured2Schema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "oppAggregates": {
      description:
        "Snapshot from aggregateOpportunities: PII-free CRM pipeline analytics (counts + per-currency sums by stage/lineOfBusiness/sourceChannel, open-pipeline, win/loss, active customers) + the read-only GraphQL verification probe. No opp names/ids/contacts.",
      schema: OppAggregatesSchema,
      // Analytics snapshot: finite TTL + tight GC like the other bulk reads.
      lifetime: "3d",
      garbageCollection: 5,
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
    "noteBodyRead": {
      description:
        "Result of a getNoteBody run: ONE note's bodyV2.markdown (the sanctioned, per-id, confirm-gated SR-1 exception). Short-TTL + generous GC so a migration batch of distinct note-body-<id> instances is not truncated; the 3d TTL is the PII-at-rest bound.",
      schema: NoteBodyReadSchema,
      lifetime: "3d",
      garbageCollection: 25,
    },
    "noteWrite": {
      description:
        "Result of a note write (createNote/updateNote/appendNote/linkNote/unlinkNote): note id, action, targets linked/failed, and body LENGTH (never the body text). Short-TTL (3d) + generous GC bounds the free-text `title`'s PII-at-rest (S3).",
      schema: NoteWriteSchema,
      lifetime: "3d",
      garbageCollection: 25,
    },
    "threadList": {
      description:
        "Snapshot from listThreads: per-thread BODY-FREE summaries (id, subject presence+length, participant join keys, last in/out timestamps, message count) for a record target or a recent workspace scan. No handles/subjects/bodies (F6).",
      schema: ThreadListSchema,
      lifetime: "3d",
      garbageCollection: 5,
    },
    "threadDetail": {
      description:
        "Snapshot from getThread: one thread's oldest->newest BODY-FREE message views (id, direction, subject/body presence+length, participant join keys, timestamps). No subject/body text (F6).",
      schema: ThreadDetailSchema,
      lifetime: "3d",
      garbageCollection: 5,
    },
    "threadStatus": {
      description:
        "Snapshot from threadStatus: per-thread follow-up verdicts (awaiting-us/sent-unanswered/dormant/empty/unknown) + last direction/age. PII-free (ids + timestamps + verdict only).",
      schema: ThreadStatusReportSchema,
      lifetime: "3d",
      garbageCollection: 10,
    },
    "connectedAccountList": {
      description:
        "Snapshot from listConnectedAccounts: the send service user's own mailboxes reduced to id/provider/DOMAIN-only + authFailed/archived booleans (the brand-pinning source of truth). PII-conservative — never the full handle/local-part (F6).",
      schema: ConnectedAccountListSchema,
      lifetime: "3d",
      garbageCollection: 10,
    },
    "sendRun": {
      description:
        "Audit of a sendEmail run (planned/sent/skipped): target JOIN KEYS, connectedAccountId (NOT a mailbox email), fromBrand, workflowVersionId, opaque dedupKey, hashed recipient, subject/body LENGTHS, and the async workflowRunId. NEVER the raw `to`/subject/body text (F6/F7). Async send is not synchronously confirmable (F13).",
      schema: SendRunSchema,
      lifetime: "infinite",
      garbageCollection: 200,
    },
    "stageOption": {
      description:
        "Result of an ensureStageOption run: the target picklist, the option, the action taken, and the full option set",
      schema: StageOptionSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "selectOptionRemoval": {
      description:
        "Result of a removeSelectOption run: the target picklist, the removed value, the action, the (folded) reference count, and the resulting/planned option set. No PII, no emergency split.",
      schema: SelectOptionRemovalSchema,
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
    "companyUpsert": {
      description:
        "Result of an upsertCompany run: the action (plan/commit/conflict), the matched/created company id, which fields were set, and any conflict candidates (id/name/domain only — no account-owner email or person PII)",
      schema: CompanyUpsertSchema,
      lifetime: "infinite",
      garbageCollection: 100,
    },
    "companyReconcile": {
      description:
        "Audit of a reconcileCompanies fan-out: per-entry plan/outcome (isolated; one bad row never aborts), action tallies, the entry cap in effect, and whether the batch converged to all-noop. No raw PII (company id/name/domain + redacted per-entry errors).",
      schema: CompanyReconcileSchema,
      lifetime: "3d",
      garbageCollection: 25,
    },
    "peopleReconcile": {
      description:
        "Audit of a reconcilePeople fan-out: per-entry plan/outcome (isolated; one bad row never aborts), action tallies (incl. noop), the entry cap in effect, and whether the batch converged to all-noop. NO raw PII - index + action + fieldsSet + opaque personId/companyId + redacted per-entry errors only (never the person name or primaryEmail).",
      schema: PersonReconcileSchema,
      lifetime: "3d",
      garbageCollection: 25,
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
    ensureNoteFields: {
      description:
        "Idempotently provision the note-reconciliation custom fields (TWENTY-NOTE-RECONCILE): noteHash (TEXT) on Note, via POST /rest/metadata/fields. A thin wrapper over the shared ensureFieldOnce core, paralleling ensureLeadFields. Already-present fields are skipped (a wrong-type field is reported, never mutated). Confirm-gated (mutates workspace metadata). Provisioning noteHash ENABLES population: createNote/updateNote then populate noteHash and REQUIRE the noteHashHmacKey global (SEC-5 fail-closed on an empty key). Snapshots a `fieldsEnsured` resource (instance fieldsEnsured-note).",
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
        const objs = await fetchObjectsMeta(cfg);
        const created: string[] = [];
        const alreadyPresent: string[] = [];
        const failed: Array<{ field: string; error: string }> = [];
        for (const nf of NOTE_FIELDS) {
          const key = `${nf.object}.${nf.name}`;
          try {
            const outcome = await ensureFieldOnce(
              cfg,
              {
                objectNameSingular: nf.object,
                name: nf.name,
                label: nf.label,
                type: nf.type as EnsureFieldType,
              },
              false,
              objs,
            );
            if (outcome.action === "created") created.push(key);
            else if (outcome.typeMismatch) {
              failed.push({ field: key, error: outcome.typeMismatch });
            } else alreadyPresent.push(key);
          } catch (e) {
            failed.push({ field: key, error: redactError(e) });
          }
        }
        // Drop the memoized provisioned-ness UNCONDITIONALLY so the very next
        // write re-reads truth. Clearing only on created.length would miss the
        // case where the field was provisioned out-of-band while a stale
        // `present:false` memo is live: this run would find it alreadyPresent
        // (created:[]), leave the stale memo, and subsequent createNote/
        // updateNote would silently skip the hash for up to the TTL (ADV-1).
        __clearNoteFieldCache();
        context.logger.info(
          "ensureNoteFields: {created} created, {present} present, {failed} failed",
          {
            created: created.length,
            present: alreadyPresent.length,
            failed: failed.length,
          },
        );
        const handle = await context.writeResource(
          "fieldsEnsured",
          "fieldsEnsured-note",
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
    removeSelectOption: {
      description:
        "Retire a SELECT option from an allowlisted opportunity picklist (opportunity.stage/sourceChannel/lineOfBusiness/offering) — the reverse of ensureStageOption. Reads the field's FULL option set and PATCHes it back with the target value DROPPED, preserving every surviving option (id/label/color/position) verbatim. FAIL-CLOSED anti-orphan guard: refuses when the value is the field default, when any opportunity still references it (default path), or when the reference count is untrusted. Idempotent — an already-absent value is a no-op success ('absent'). confirm-gated with dryRun defaulting TRUE (a bare call previews and writes nothing); a real removal needs dryRun=false AND confirm=true. `force` overrides the in-use refusal ONLY, and requires expectedInUseCount to match the live count. SELECT-only; MULTI_SELECT/unknown/non-allowlisted targets rejected. Snapshots a `selectOptionRemoval` resource (folded refCount, no PII). PRECONDITION (ADV-5): the token must be an unrestricted-visibility role.",
      arguments: z.object({
        objectNameSingular: z
          .string()
          .default("opportunity")
          .describe(
            "Object owning the field (allowlisted; default opportunity)",
          ),
        fieldName: z
          .string()
          .describe(
            "SELECT field name (allowlisted: stage/sourceChannel/lineOfBusiness/offering)",
          ),
        value: z
          .string()
          .describe("Option token to remove — UPPER_SNAKE (e.g. CLOSED)"),
        confirm: z
          .boolean()
          .default(false)
          .describe(
            "Must be true (with dryRun:false) to apply — mutates workspace metadata",
          ),
        dryRun: z
          .boolean()
          .default(true)
          .describe(
            "Preview the planned (reduced) option array + refCount; write nothing. Defaults true.",
          ),
        force: z
          .boolean()
          .default(false)
          .describe(
            "Override the in-use refusal ONLY. Requires expectedInUseCount == the live reference count AND confirm. Never bypasses allowlist/default/drift/re-count guards. Sandbox+Neil gated (design OQ1).",
          ),
        expectedInUseCount: z
          .number()
          .int()
          .optional()
          .describe(
            "Required when force=true — must equal the live reference count at write time, or the run aborts (acknowledgement token).",
          ),
      }),
      execute: async (
        args: {
          objectNameSingular: string;
          fieldName: string;
          value: string;
          confirm: boolean;
          dryRun: boolean;
          force: boolean;
          expectedInUseCount?: number;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          // Reject any target not on the allowlist BEFORE any I/O; force cannot bypass.
          const target = `${args.objectNameSingular}.${args.fieldName}`;
          if (!OPTION_REMOVE_ALLOWLIST.has(target)) {
            throw new Error(
              `Target '${target}' is not on the removeSelectOption allowlist (allowed: ${
                [...OPTION_REMOVE_ALLOWLIST].join(", ")
              })`,
            );
          }
          const value = String(args.value ?? "").trim();
          if (!STAGE_OPTION_VALUE_RE.test(value)) {
            throw new Error(
              "Invalid option value: must be UPPER_SNAKE (A-Z, 0-9, _), no spaces",
            );
          }
          // dryRun (default true) previews; a real write needs confirm AND dryRun:false.
          if (!args.confirm && !args.dryRun) {
            throw new Error(
              "Refusing to remove a stage option without confirm:true (mutates workspace metadata). Use dryRun:true (default) to preview.",
            );
          }

          // Mandatory full-shape read (+ normalized default); hard-stops on non-SELECT / lossy.
          const field = await fetchSelectField(
            cfg,
            args.objectNameSingular,
            args.fieldName,
          );
          const optionsFor = (opts: SelectOption[]) =>
            opts.map((o) => ({
              value: o.value,
              label: o.label,
              color: o.color,
              position: o.position,
            }));
          // Set true ONLY when force actually overrides an in-use (count>0)
          // refusal, so the snapshot's `forced` bit is an honest audit signal.
          let overrodeInUse = false;
          const writeSnap = async (
            action:
              | "absent"
              | "planned-remove"
              | "removed"
              | "refused-in-use"
              | "refused-default"
              | "refused-untrusted-count"
              | "refused-drift",
            opts: SelectOption[],
            refCount: number,
            countTrusted: boolean,
            emergencyReadReliable: boolean,
          ): Promise<ExecuteResult> => {
            context.logger.info(
              "removeSelectOption {target} value={value}: {action}",
              { target, value, action },
            );
            const handle = await context.writeResource(
              "selectOptionRemoval",
              `optremove-${args.objectNameSingular}-${args.fieldName}-${value}`,
              {
                baseUrl: cfg.baseUrl,
                object: args.objectNameSingular,
                field: args.fieldName,
                value,
                action,
                refCount,
                countTrusted,
                emergencyReadReliable,
                // CR-2: `forced` is honest — true ONLY when force actually
                // overrode an in-use (count>0) refusal, not merely when force
                // was passed. False on every refusal and on a count==0 run.
                forced: overrodeInUse,
                options: optionsFor(opts),
                retrievedAt: new Date().toISOString(),
              },
            );
            return { dataHandles: [handle] };
          };

          const existing = field.options.find((o) => o.value === value);
          // Idempotent: removing an already-absent value is a success no-op.
          // CR-1: no count/read ran on this path, so countTrusted and
          // emergencyReadReliable are recorded false (not asserted true).
          if (!existing) {
            return await writeSnap("absent", field.options, 0, false, false);
          }
          // ADV-3/ADV-10: never remove the field's (normalized) default option.
          // CR-1: refuses BEFORE any count/read — audit bits false, not true.
          if (field.defaultValue && field.defaultValue === value) {
            return await writeSnap(
              "refused-default",
              field.options,
              0,
              false,
              false,
            );
          }

          // Anti-orphan count (authoritative totalCount; fail-closed on no-total).
          const c = await countOpportunitiesByFieldValue(
            cfg,
            args.fieldName,
            value,
          );
          const emergencyReadReliable = true; // the count GET succeeded ⇒ token can read Opportunity.
          if (!c.trusted) {
            return await writeSnap(
              "refused-untrusted-count",
              field.options,
              0,
              false,
              emergencyReadReliable,
            );
          }
          if (c.count > 0 && !args.force) {
            return await writeSnap(
              "refused-in-use",
              field.options,
              c.count,
              true,
              emergencyReadReliable,
            );
          }
          if (args.force && c.count > 0) {
            if (args.expectedInUseCount !== c.count) {
              throw new Error(
                `force requires expectedInUseCount to equal the live reference count (${c.count}); got ${args.expectedInUseCount}. Re-check and re-run.`,
              );
            }
            // force is genuinely overriding an in-use refusal here.
            overrodeInUse = true;
          }

          const reduced = field.options.filter((o) => o.value !== value);

          if (args.dryRun) {
            return await writeSnap(
              "planned-remove",
              reduced,
              c.count,
              true,
              emergencyReadReliable,
            );
          }

          // Real write. Optimistic concurrency: re-read options + STRICT drift check
          // (a concurrent reorder/edit is drift and aborts — no lost update).
          const fresh = await fetchSelectField(
            cfg,
            args.objectNameSingular,
            args.fieldName,
          );
          if (!optionsEquivalent(fresh.options, field.options)) {
            return await writeSnap(
              "refused-drift",
              fresh.options,
              c.count,
              true,
              emergencyReadReliable,
            );
          }
          // Re-count immediately before the write to close the count→write TOCTOU.
          const rc = await countOpportunitiesByFieldValue(
            cfg,
            args.fieldName,
            value,
          );
          if (!rc.trusted) {
            return await writeSnap(
              "refused-untrusted-count",
              field.options,
              0,
              false,
              emergencyReadReliable,
            );
          }
          if (!args.force) {
            if (rc.count !== 0) {
              return await writeSnap(
                "refused-in-use",
                field.options,
                rc.count,
                true,
                emergencyReadReliable,
              );
            }
          } else if (rc.count !== args.expectedInUseCount) {
            throw new Error(
              `force aborted: reference count changed to ${rc.count} (expected ${args.expectedInUseCount}) between check and write. Re-run.`,
            );
          }

          // options-only PATCH — Twenty's metadata field PATCH is a partial update,
          // so sibling attributes (name/label/type/isNullable/defaultValue) are
          // preserved. Survivors are sent verbatim WITH their ids so Twenty treats
          // them as the same options (never re-creates/duplicates).
          await twentyRequest(
            cfg,
            "PATCH",
            `/rest/metadata/fields/${field.fieldId}`,
            { options: reduced },
          );
          return await writeSnap(
            "removed",
            reduced,
            rc.count,
            true,
            emergencyReadReliable,
          );
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
    listViews: {
      description:
        "Read-only Phase-0 view probe (TWENTY-VIEW-MGMT): resolve which view endpoint is live (core REST /rest/views vs the metadata REST API /rest/metadata/views — views are metadata objects, not core-REST ones, and Core GraphQL has no views query), classify each candidate (ok/absent/forbidden/error), authoritatively fetch the Opportunity views + their viewFilters, resolve stage/lineOfBusiness field ids + live options, and report the locked default (key==='INDEX') and uncovered stage options. GATES the view-write method. No writes. Snapshots a `viewList` resource.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const probes: Array<{
          path: string;
          status: number;
          verdict: "ok" | "absent" | "forbidden" | "error";
          count?: number;
          bodySample?: string;
        }> = [];
        // Capture a raw value to a bounded string for shape-discovery, routed
        // through redactError so a bearer token / email / long-digit / filter or
        // cursor query value in a response body or error text can never land in
        // the durable snapshot (same defense-in-depth as every other write path
        // in this file — SR-2/CR-S-1).
        const cap = (v: unknown) =>
          redactError(
            typeof v === "string" ? v : JSON.stringify(v ?? null),
            600,
            cfg.apiToken,
          );
        // Resolve the Opportunity objectMetadataId + the filter fields' live
        // metadata (id + options) in one metadata read. The filter fields drive
        // the S1 allowlist and the A5 dependency assert in the write method.
        let oppOid: string | undefined;
        let filterFields: Record<
          string,
          { fieldMetadataId?: string; type?: string; options: string[] }
        > = {};
        try {
          const resolved = await resolveOpportunityFilterFields(cfg);
          oppOid = resolved.oppOid;
          filterFields = resolved.fields;
        } catch { /* non-fatal — probe still runs */ }
        const OPEN_STAGES = ["NEW", "SCREENING", "MEETING", "PROPOSAL"];
        const uncoveredStageOptions = (filterFields.stage?.options ?? [])
          .filter(
            (o) => !OPEN_STAGES.includes(o),
          );

        // REACHABILITY PROBES: classify each candidate endpoint and capture the
        // raw envelope (Twenty's 4xx bodies name the reason; a 200 body reveals
        // the real list key) so the true shape is discoverable, not guessed
        // (spec F1/F5). These CLASSIFY only — the authoritative fetch below reads
        // the resolved metadata endpoint.
        const restProbe = async (path: string) => {
          try {
            const r = await rawGet(cfg, path);
            probes.push({
              path,
              status: r.status,
              verdict: classifyProbe(r.status),
              bodySample: cap(r.body),
            });
          } catch (e) {
            probes.push({
              path,
              status: 0,
              verdict: "error",
              bodySample: cap(String(e)),
            });
          }
        };
        for (
          const path of [
            "/rest/views?limit=200", // core REST: 400 (views is not a core object)
            "/rest/metadata/views", // metadata REST: the live endpoint
            "/rest/viewFilters?limit=50",
            "/rest/metadata/viewFilters",
          ]
        ) {
          await restProbe(path);
        }

        // AUTHORITATIVE FETCH: page the resolved metadata endpoint and join views
        // to their viewFilters. Produces the full-shape opportunity view records
        // that gate the write methods (F2 lock-flag / F5 filter shape).
        let allViews: Array<Record<string, unknown>> = [];
        let allFilters: Array<Record<string, unknown>> = [];
        try {
          allViews = await fetchMetadataList(cfg, "views");
        } catch { /* reachability already captured in probes */ }
        try {
          allFilters = await fetchMetadataList(cfg, "viewFilters");
        } catch { /* non-fatal — filters simply unavailable */ }

        const filtersByView = new Map<string, Array<Record<string, unknown>>>();
        for (const f of allFilters) {
          const vid = String(f.viewId ?? "");
          if (!vid) continue;
          const arr = filtersByView.get(vid);
          if (arr) arr.push(f);
          else filtersByView.set(vid, [f]);
        }

        const opportunityViews = allViews
          .filter((v) => !oppOid || String(v.objectMetadataId ?? "") === oppOid)
          .map((v) => {
            const id = String(v.id ?? "");
            return {
              id,
              name: String(v.name ?? ""),
              type: v.type != null ? String(v.type) : undefined,
              key: v.key === null
                ? null
                : (v.key != null ? String(v.key) : undefined),
              isSystemSideEffect: typeof v.isSystemSideEffect === "boolean"
                ? v.isSystemSideEffect
                : undefined,
              isCustom: typeof v.isCustom === "boolean"
                ? v.isCustom
                : undefined,
              position: typeof v.position === "number" ? v.position : undefined,
              objectMetadataId: v.objectMetadataId
                ? String(v.objectMetadataId)
                : undefined,
              filters: (filtersByView.get(id) ?? []).map((f) => ({
                id: String(f.id ?? ""),
                fieldMetadataId: f.fieldMetadataId
                  ? String(f.fieldMetadataId)
                  : undefined,
                operand: f.operand != null ? String(f.operand) : undefined,
                value: f.value,
                subFieldName: f.subFieldName === null
                  ? null
                  : (f.subFieldName != null
                    ? String(f.subFieldName)
                    : undefined),
                viewFilterGroupId: f.viewFilterGroupId === null
                  ? null
                  : (f.viewFilterGroupId != null
                    ? String(f.viewFilterGroupId)
                    : undefined),
              })),
            };
          });

        // F2: identify the locked/default index view. Twenty's per-object default
        // view carries key === "INDEX"; that is the view that must never be mutated.
        const indexView = opportunityViews.find((v) => v.key === "INDEX");
        const lockFlagObserved = indexView
          ? `default/locked index view detected via key==="INDEX" (view '${indexView.name}', id ${indexView.id})`
          : "no key==='INDEX' opportunity view observed";

        const handle = await context.writeResource("viewList", "viewList", {
          baseUrl: cfg.baseUrl,
          probes,
          readPath: "/rest/metadata/views",
          writeEndpointCandidate:
            "POST /rest/metadata/views + POST /rest/metadata/viewFilters",
          opportunityObjectMetadataId: oppOid,
          viewCount: allViews.length,
          opportunityViews,
          lockFlagObserved,
          filterFields,
          uncoveredStageOptions,
          // Allowlisted shape sample (CR-.17.1-R3): serialize ONLY known-safe
          // view-metadata fields + the record's key names — never the raw record
          // (which could carry createdBy/updatedBy-style PII), and never through
          // the field-allowlist the opportunityViews array already applies.
          sample: JSON.stringify((() => {
            const rep = allViews.find((v) =>
              String(v.objectMetadataId ?? "") === oppOid
            ) ?? allViews[0] ?? null;
            if (!rep) {
              return null;
            }
            const ALLOW = [
              "id",
              "name",
              "type",
              "key",
              "isSystemSideEffect",
              "isCustom",
              "position",
              "objectMetadataId",
            ];
            const out: Record<string, unknown> = {
              keys: Object.keys(rep).sort(),
            };
            for (const k of ALLOW) {
              if (rep[k] !== undefined) {
                out[k] = rep[k];
              }
            }
            return out;
          })()).slice(0, 1500),
          retrievedAt: new Date().toISOString(),
        });
        return { dataHandles: [handle] };
      },
    },
    ensureOpportunityViews: {
      description:
        "Gated write (TWENTY-VIEW-MGMT): idempotently CREATE the target Opportunity saved views (Sales Pipeline = stage IS [NEW,SCREENING,MEETING,PROPOSAL]; Consulting/Hosting/Local IT = lineOfBusiness IS [<LOB>]), each with a single `IS`-any-of viewFilter via the metadata API. NON-MUTATING by construction: creates a view only when its name is absent, no-ops when it already carries the desired filter, and REFUSES (never mutates) any pre-existing / locked / ambiguous view (F2/F3). Binds filters to a live fieldMetadataId (F6) and asserts every target enum option is present in the live schema (A5/S1). dryRun (default) plans; confirm=true executes creates after a view-endpoint reachability pre-flight (F4). Snapshots a `viewEnsured` resource. Run listViews first.",
      arguments: z.object({
        confirm: z.boolean().optional(),
        dryRun: z.boolean().optional(),
        names: z.array(z.string()).optional(),
      }),
      execute: async (
        args: { confirm?: boolean; dryRun?: boolean; names?: string[] },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const willWrite = args.confirm === true && args.dryRun !== true;
        // Redact any thrown error (CR-.17.1-R3): the first call below
        // (resolveOpportunityFilterFields → fetchObjectsMeta → twentyRequest) can
        // throw with a raw response body, so wrap the whole body like every other
        // method rather than letting an un-redacted error escape.
        try {
          // Resolve opp object + filter-field metadata (id + live options).
          const { oppOid, fields: fieldMeta } =
            await resolveOpportunityFilterFields(cfg);

          // View-endpoint reachability pre-flight (F4): distinguish reachable from
          // 404 (absent) / 401-403 (forbidden) before any write.
          let reachable = false;
          try {
            const r = await rawGet(cfg, "/rest/metadata/views?limit=1");
            reachable = classifyProbe(r.status) === "ok";
          } catch {
            reachable = false;
          }

          // Load existing opportunity views + their filters (idempotency source).
          // If this fails we CANNOT trust "name absent" → creates are fail-closed.
          let existing: OppViewRef[] = [];
          let existingLoadOk = false;
          try {
            const allViews = await fetchMetadataList(cfg, "views");
            const allFilters = await fetchMetadataList(cfg, "viewFilters");
            const byView = new Map<string, OppViewFilterRef[]>();
            for (const f of allFilters) {
              const vid = String(f.viewId ?? "");
              if (!vid) continue;
              const ref: OppViewFilterRef = {
                id: f.id ? String(f.id) : undefined,
                fieldMetadataId: f.fieldMetadataId
                  ? String(f.fieldMetadataId)
                  : undefined,
                operand: f.operand != null ? String(f.operand) : undefined,
                value: f.value,
              };
              const arr = byView.get(vid);
              if (arr) arr.push(ref);
              else byView.set(vid, [ref]);
            }
            existing = allViews
              .filter((v) =>
                !oppOid || String(v.objectMetadataId ?? "") === oppOid
              )
              .map((v) => {
                const id = String(v.id ?? "");
                return {
                  id,
                  name: String(v.name ?? ""),
                  key: v.key === null
                    ? null
                    : (v.key != null ? String(v.key) : undefined),
                  isSystemSideEffect: typeof v.isSystemSideEffect === "boolean"
                    ? v.isSystemSideEffect
                    : undefined,
                  isCustom: typeof v.isCustom === "boolean"
                    ? v.isCustom
                    : undefined,
                  objectMetadataId: v.objectMetadataId
                    ? String(v.objectMetadataId)
                    : undefined,
                  filters: byView.get(id) ?? [],
                };
              });
            existingLoadOk = true;
          } catch {
            /* existingLoadOk stays false — creates fail-closed below */
          }

          // Optional subset filter by name (still allowlist-guarded by the planner).
          const nameSubset = args.names && args.names.length
            ? new Set(args.names)
            : undefined;
          const targets = OPP_VIEW_TARGETS.filter(
            (t) => !nameSubset || nameSubset.has(t.name),
          );

          const results: Array<{
            target: string;
            field: string;
            fieldMetadataId?: string;
            desiredValues: string[];
            operand: string;
            action: "create" | "noop" | "refuse" | "created" | "failed";
            reason: string;
            viewId?: string;
            error?: string;
          }> = [];

          for (const t of targets) {
            const plan = planOpportunityView(t, fieldMeta[t.field], existing);
            const row = {
              target: plan.target,
              field: plan.field,
              fieldMetadataId: plan.fieldMetadataId,
              desiredValues: plan.desiredValues,
              operand: plan.operand as string,
              action: plan.action as
                | "create"
                | "noop"
                | "refuse"
                | "created"
                | "failed",
              reason: plan.reason,
              viewId: plan.viewId,
              error: undefined as string | undefined,
            };
            if (plan.action === "create" && willWrite) {
              if (!existingLoadOk) {
                row.action = "refuse";
                row.reason =
                  "existing views could not be loaded — refusing to create (would risk a duplicate); fail-closed";
              } else if (!reachable) {
                row.action = "refuse";
                row.reason =
                  "view endpoint not reachable at confirm time — write refused (F4)";
              } else if (!oppOid) {
                row.action = "refuse";
                row.reason =
                  "opportunity objectMetadataId unresolved — write refused";
              } else {
                // Create is TWO non-transactional POSTs (view, then its filter).
                // Record the view id the instant it exists so the audit names it,
                // and if the filter write fails, ROLL BACK the just-created view we
                // own — otherwise an orphaned filterless view is left behind and,
                // being same-named with no matching filter, would make every future
                // run refuse ("filter differs") and permanently wedge (H1). The
                // rollback DELETEs ONLY the id we just minted — never a pre-existing
                // view, so the non-mutating-of-pre-existing invariant holds.
                let newViewId = "";
                let viewCreated = false;
                try {
                  const viewResp = await twentyRequest(
                    cfg,
                    "POST",
                    "/rest/metadata/views",
                    {
                      name: plan.target,
                      objectMetadataId: oppOid,
                      icon: "IconTable",
                      type: "TABLE",
                    },
                  );
                  const created =
                    ((viewResp as { data?: { id?: string } }).data ??
                      viewResp) as { id?: string };
                  newViewId = String(created?.id ?? "");
                  if (!newViewId) throw new Error("create view returned no id");
                  row.viewId = newViewId; // audit-visible before the filter write
                  viewCreated = true;
                } catch (e) {
                  // F1/F9: a write failure (incl. 400/401/403) is a hard STOP —
                  // report, no retry. Nothing was created, so nothing to roll back.
                  row.action = "failed";
                  row.error = redactError(e, 300, cfg.apiToken);
                  row.reason =
                    "view create failed — see error (no retry, fail-closed)";
                }
                if (viewCreated) {
                  try {
                    await twentyRequest(
                      cfg,
                      "POST",
                      "/rest/metadata/viewFilters",
                      {
                        viewId: newViewId,
                        fieldMetadataId: plan.fieldMetadataId,
                        operand: plan.operand,
                        value: buildViewFilterValue(plan.desiredValues),
                      },
                    );
                    row.action = "created";
                    row.reason = "created view + IS-any-of filter";
                  } catch (e) {
                    row.error = redactError(e, 300, cfg.apiToken);
                    let rolledBack = false;
                    try {
                      await twentyRequest(
                        cfg,
                        "DELETE",
                        `/rest/metadata/views/${newViewId}`,
                      );
                      rolledBack = true;
                    } catch {
                      /* rollback failed — surface the orphan id in reason */
                    }
                    row.action = "failed";
                    row.reason = rolledBack
                      ? "filter write failed; created view rolled back (no orphan) — no retry, fail-closed"
                      : `filter write failed AND rollback failed — ORPHAN view ${newViewId} left; delete it manually before re-running`;
                  }
                }
              }
            }
            results.push(row);
          }

          const createdCount = results.filter((r) =>
            r.action === "created"
          ).length;
          const refusedCount = results.filter(
            (r) => r.action === "refuse" || r.action === "failed",
          ).length;

          const handle = await context.writeResource(
            "viewEnsured",
            "viewEnsured",
            {
              baseUrl: cfg.baseUrl,
              dryRun: !willWrite,
              confirm: args.confirm === true,
              reachable,
              objectMetadataId: oppOid,
              results,
              createdCount,
              refusedCount,
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    upsertOpportunityViews: {
      description:
        "TWENTY-VIEW-UPSERT (fan-out, repo rule 6): reconcile a desired LIST of Opportunity views to a YAML source-of-truth in ONE execution. Per view: create (name absent) / adopt+rename (adoptFrom an existing swamp-owned view) / reconcile its viewFilters (add missing, delete extra, patch operand/value drift, patch group AND/OR operator, collapse grouped->ungrouped) / present (already matching, quiet no-op) / refuse (fail-closed). Additive — does NOT change the create-only ensureOpportunityViews. Fail-closed guardrails: never mutates a non-isCustom / key!=null / isSystemSideEffect view (positive-proof-of-mutability); refuses >1 name or adoptFrom match, unresolved objectMetadataId/fieldMetadataId, retired/invalid enum tokens (live-schema allowlist), nested / multi top-level groups, and an ungrouped->grouped restructure; never blind-deletes a viewFilterGroup (deletes members first, empties then removes). Writes the UI stringified value form and verifies every write with a post-write read-back. confirm-gated (default dryRun plans only); confirm=true executes. Snapshots viewEnsured2.",
      arguments: z.object({
        views: z.array(UpsertViewArg).min(1).max(200).describe(
          "Desired view list (all scoped to Opportunity). Each: { name, filters:[{field,operand,values[],subFieldName?}], filterGroup?('and'|'or', required when >1 filter), adoptFrom?(existing view name or viewId) }.",
        ),
        confirm: z.boolean().optional().describe(
          "Execute the writes. Default false = plan only.",
        ),
        dryRun: z.boolean().optional().describe(
          "Plan without writing (default true). A write requires confirm=true AND dryRun=false.",
        ),
      }),
      execute: async (
        args: {
          views: DesiredView[];
          confirm?: boolean;
          dryRun?: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const payload = await runViewUpserts(
            cfg,
            args.views,
            args.confirm === true,
            args.dryRun !== false,
          );
          const handle = await context.writeResource(
            "viewEnsured2",
            "viewEnsured2",
            payload,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    upsertOpportunityView: {
      description:
        "TWENTY-VIEW-UPSERT (single-view convenience over upsertOpportunityViews): reconcile ONE Opportunity view to a desired filter state — create / adopt+rename / reconcile / present / refuse, with the same fail-closed guardrails, stringified-value writes, and read-back verification. Prefer upsertOpportunityViews for multiple views (one lock acquisition). confirm-gated, dryRun default. Snapshots viewEnsured2.",
      arguments: z.object({
        name: z.string().describe(
          "Desired final view name (the stable identity within the object).",
        ),
        filters: z.array(UpsertViewFilterArg).min(1).max(20).describe(
          "Desired filter clauses: [{field, operand(IS|IS_NOT), values[], subFieldName?}].",
        ),
        filterGroup: z.enum(["and", "or"]).optional().describe(
          "Boolean combinator for a multi-clause view (required when filters.length>1).",
        ),
        adoptFrom: z.string().optional().describe(
          "Existing view NAME or viewId to rename->name + reconcile (the adoption opt-in).",
        ),
        confirm: z.boolean().optional(),
        dryRun: z.boolean().optional(),
      }),
      execute: async (
        args: {
          name: string;
          filters: DesiredViewFilter[];
          filterGroup?: "and" | "or";
          adoptFrom?: string;
          confirm?: boolean;
          dryRun?: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const desired: DesiredView = {
            name: args.name,
            filters: args.filters,
            filterGroup: args.filterGroup,
            adoptFrom: args.adoptFrom,
          };
          const payload = await runViewUpserts(
            cfg,
            [desired],
            args.confirm === true,
            args.dryRun !== false,
          );
          const handle = await context.writeResource(
            "viewEnsured2",
            "viewEnsured2",
            payload,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    aggregateOpportunities: {
      description:
        "Read-only CRM pipeline analytics: aggregate all Opportunities into PII-free metrics — counts + per-currency sums grouped by stage / lineOfBusiness / sourceChannel (observed values, incl. a legacy CLOSED bucket), open-pipeline value (NEW/SCREENING/MEETING/PROPOSAL), win/loss + win rate (won = CUSTOMER+CLOSED_WON, lost = CLOSED_LOST, n/a on 0/0), and active customers. isEmergency opps are EXCLUDED by default (never disclose emergency volume). GraphQL-primary: pages the Core-GraphQL opportunities connection (allowlisted fields) and cross-checks its server-side sumAmountAmountMicros against the in-extension sum; falls back to the fully-paginated REST read on any GraphQL failure. Snapshots an `oppAggregates` resource (no opp names/ids/contacts).",
      arguments: z.object({
        includeEmergency: z
          .boolean()
          .default(false)
          .describe(
            "Include isEmergency opps in the aggregates (default false — excluded so the snapshot can't disclose emergency volume to a non-restricted viewer).",
          ),
      }),
      execute: async (
        args: { includeEmergency: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          // GraphQL-primary acquisition (server-side field selection + the
          // connection sumAmountAmountMicros cross-check); on ANY GraphQL
          // failure fall back to the fully-paginated REST read. Both paths yield
          // raw opportunity records that mapOppView maps identically.
          let source: "graphql" | "rest" = "graphql";
          let rows: Array<Record<string, unknown>>;
          let truncated: boolean;
          let serverSumMicros: number | null = null;
          const probe: {
            attempted: boolean;
            ok: boolean;
            serverSumMicros: number | null;
            crossCheck: "match" | "mismatch" | "na";
            detail?: string;
          } = {
            attempted: true,
            ok: false,
            serverSumMicros: null,
            crossCheck: "na",
          };
          try {
            const g = await acquireOppRowsGraphQL(cfg);
            rows = g.rows;
            truncated = g.truncated;
            serverSumMicros = g.serverSumMicros;
            probe.ok = true;
          } catch (e) {
            source = "rest";
            probe.ok = false;
            probe.detail = redactError(e, 200, cfg.apiToken);
            const r = await listOpportunitiesFiltered(cfg, {
              limit: MAX_LIST_CAP,
            });
            rows = r.items;
            truncated = r.truncated;
          }

          const views = rows.map(mapOppView);
          const agg = aggregateOppViews(views, {
            includeEmergency: args.includeEmergency,
          });

          // Cross-check the server's all-currency micros sum against the local
          // raw-micros sum over the SAME (unfiltered) rows — an integrity signal
          // that GraphQL aggregation and our acquisition agree. SKIP when
          // truncated: the server sum is over ALL opps but our local rows are a
          // partial set, so a "mismatch" would just re-signal truncation, not an
          // integrity failure (CR-A-L1). Left "na" in that case.
          probe.serverSumMicros = serverSumMicros;
          if (serverSumMicros !== null && !truncated) {
            const localMicros = rows.reduce((s, r) => {
              const a = parseMicros(
                (r.amount as { amountMicros?: unknown } | null)?.amountMicros,
              );
              return s + (a ?? 0);
            }, 0);
            probe.crossCheck = localMicros === serverSumMicros
              ? "match"
              : "mismatch";
            if (probe.crossCheck === "mismatch") {
              probe.detail =
                `server ${serverSumMicros} != local ${localMicros}`;
            }
          }

          const handle = await context.writeResource(
            "oppAggregates",
            "oppAggregates",
            {
              baseUrl: cfg.baseUrl,
              source,
              truncated,
              includeEmergency: args.includeEmergency,
              ...agg,
              graphqlProbe: probe,
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    getOpportunity: {
      description:
        "Fetch one Opportunity by leadId OR id (exactly one). Records an `opportunityRef` snapshot carrying the reconcile-critical fields (id, leadId, name, stage, amount in whole units, currencyCode, closeDate, companyId, pointOfContactId, channelPartnerId) plus the segmentation SELECTs (lineOfBusiness, sourceChannel, offering) and isEmergency when set — so a written custom-field value is read-back verifiable; found:false + no fields on a miss. No writes.",
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
            if (view.channelPartnerId) {
              snap.channelPartnerId = view.channelPartnerId;
            }
            if (view.lineOfBusiness) snap.lineOfBusiness = view.lineOfBusiness;
            if (view.sourceChannel) snap.sourceChannel = view.sourceChannel;
            if (view.asn) snap.asn = view.asn;
            if (view.qualStatus) snap.qualStatus = view.qualStatus;
            if (view.offering) snap.offering = view.offering;
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
        "Fan-out read (repo rule 6): list Opportunities filtered by companyId and/or stage (both optional; neither => all, capped). Composes filters with AND, pages through Twenty's cursor pagination up to `limit` (hard-capped at 500), dedups by id, and records an `opportunityList` snapshot of compact views (id/leadId/name/stage/amount/currency/closeDate/companyId/channelPartnerId + segmentation lineOfBusiness/sourceChannel/offering + isEmergency when set) + a `truncated` flag. No writes, no per-id loop.",
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
    listNotesByOpportunity: {
      description:
        "Fan-out read (repo rule 6): discover the Notes linked to an Opportunity via noteTargets (targetOpportunityId), returning body-FREE compact views (mapNoteView — SR-1 preserved: id/leadId/machine-'Inbound lead' title/dates, NEVER a body). Resolves the opp's noteTargets page, then reads each linked Note. Records a `noteList` snapshot (instance note-list-opp-<id>). Primary use: find noteIds for getNoteBody when a note is NOT leadId-tagged (so listNotes can't find it). No writes.",
      arguments: z.object({
        opportunityId: z
          .string()
          .describe("Opportunity UUID to list linked notes for"),
        limit: z
          .number()
          .int()
          .positive()
          .max(MAX_LIST_CAP)
          .default(60)
          .describe(
            `Soft per-call floor (1..${MAX_LIST_CAP}) for the noteTargets page`,
          ),
      }),
      execute: async (
        args: { opportunityId: string; limit: number },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const opportunityId = validateUuid(args.opportunityId);
        if (!opportunityId) {
          throw new Error("Invalid opportunityId (must be a UUID)");
        }
        try {
          const cap = Math.min(
            Math.max(1, Math.floor(args.limit)),
            MAX_LIST_CAP,
          );
          // Resolve the opp's note links via the noteTargets join.
          const page = await listFiltered(
            cfg,
            "noteTargets",
            [`targetOpportunityId[eq]:${encodeURIComponent(opportunityId)}`],
            cap,
            LIST_ORDER,
          );
          // Collect + dedup the linked note ids from the join records.
          const noteIds: string[] = [];
          const seen = new Set<string>();
          for (const t of page.items) {
            const nid = t.noteId != null ? String(t.noteId) : "";
            if (nid && !seen.has(nid)) {
              seen.add(nid);
              noteIds.push(nid);
            }
          }
          // Read each linked Note, mapped body-FREE (mapNoteView, SR-1). A
          // deleted/absent note is skipped (getByIdOrNull => null).
          const items = [];
          for (const nid of noteIds) {
            const note = await getByIdOrNull(cfg, `/rest/notes/${nid}`, "note");
            if (note) items.push(mapNoteView(note));
          }
          const retrievedAt = new Date().toISOString();
          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            count: items.length,
            truncated: page.truncated,
            hasMore: page.hasMore,
            incomplete: page.incomplete,
            stopReason: page.stopReason,
            filter: { opportunityId },
            items,
            retrievedAt,
          };
          if (page.nextCursor !== undefined) snap.nextCursor = page.nextCursor;
          if (page.totalCount !== undefined) snap.totalCount = page.totalCount;
          const handle = await context.writeResource(
            "noteList",
            `note-list-opp-${opportunityId}`,
            snap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    listThreads: {
      description:
        "Fan-out read (repo rule 6): summarize the email threads for ONE record (opportunityId | personId | companyId | leadId) via the polymorphic messageThreadTarget join (targetOpportunityId/targetPersonId/targetCompanyId — F18), or a recent workspace-wide scan when no target is given. A leadId resolves to its opportunity (then person) first. Per thread returns BODY-FREE fields only (F6): id, subject presence+length (NOT text), participant JOIN KEYS (personId/workspaceMemberId — NOT emails), last-inbound/last-outbound coalesced timestamps, and message count. Direction is authoritative from messageChannelMessageAssociation (F8). Records a `threadList` snapshot. No writes.",
      arguments: z.object({
        opportunityId: z.string().optional().describe(
          "Opportunity UUID target — at most one of the four targets",
        ),
        personId: z.string().optional().describe("Person UUID target"),
        companyId: z.string().optional().describe("Company UUID target"),
        leadId: z.string().optional().describe(
          "Lead marker target (resolved to its opportunity, then person)",
        ),
        limit: z
          .number()
          .int()
          .positive()
          .max(MAX_LIST_CAP)
          .default(30)
          .describe(
            `Soft per-call floor (1..${MAX_LIST_CAP}) for the thread page`,
          ),
        messageLimit: z
          .number()
          .int()
          .positive()
          .max(MAX_LIST_CAP)
          .default(60)
          .describe(
            "Per-thread cap on messages read to derive counts/last in-out",
          ),
        startingAfter: z
          .string()
          .optional()
          .describe("Cursor from a prior call's nextCursor"),
      }),
      execute: async (
        args: {
          opportunityId?: string;
          personId?: string;
          companyId?: string;
          leadId?: string;
          limit: number;
          messageLimit: number;
          startingAfter?: string;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const cap = Math.min(
            Math.max(1, Math.floor(args.limit)),
            MAX_LIST_CAP,
          );
          const msgCap = Math.min(
            Math.max(1, Math.floor(args.messageLimit)),
            MAX_LIST_CAP,
          );
          const startingAfter = args.startingAfter
            ? String(args.startingAfter)
            : undefined;
          const resolved = await resolveThreadTarget(cfg, args);
          const target: Record<string, unknown> = {
            kind: resolved.kind,
            found: resolved.found,
          };
          if (resolved.id !== undefined) target.id = resolved.id;
          if (resolved.resolvedKind !== undefined) {
            target.resolvedKind = resolved.resolvedKind;
          }
          if (resolved.resolvedId !== undefined) {
            target.resolvedId = resolved.resolvedId;
          }
          const retrievedAt = new Date().toISOString();
          const h = await listInstanceHash({
            kind: resolved.kind,
            id: resolved.id ?? null,
            rid: resolved.resolvedId ?? null,
            after: startingAfter ?? null,
          });
          const instanceName = `threads-${h}`;

          // A leadId that resolved to nothing: emit an empty, found:false snap.
          if (!resolved.found) {
            const handle = await context.writeResource(
              "threadList",
              instanceName,
              {
                baseUrl: cfg.baseUrl,
                target,
                count: 0,
                truncated: false,
                hasMore: false,
                incomplete: false,
                stopReason: "complete",
                items: [],
                retrievedAt,
              },
            );
            return { dataHandles: [handle] };
          }

          const { ids, page } = await fetchThreadIdsForTarget(
            cfg,
            resolved,
            cap,
            startingAfter,
          );

          const items: Array<Record<string, unknown>> = [];
          for (const threadId of ids) {
            if (!isFilterSafe(threadId)) continue;
            // EMAIL-ORD-1: read NEWEST-first so the head page holds the true last
            // (and its lastInbound/lastOutbound) even when the thread exceeds the
            // per-thread cap; an ascending read returned the oldest N and inverted
            // the derived direction.
            const mp = await fetchThreadRecentMessagesPage(
              cfg,
              threadId,
              msgCap,
            );
            const enriched = await enrichThreadMessages(cfg, mp.items);
            const last = pickLastMessage(mp.items);
            const subject = last && last.subject != null
              ? String(last.subject)
              : "";
            let lastInboundAt: string | undefined;
            let lastOutboundAt: string | undefined;
            const partSeen = new Set<string>();
            const participants: Array<Record<string, unknown>> = [];
            for (const e of enriched) {
              if (e.view.direction === "INCOMING") {
                if (lastInboundAt === undefined || e.ts > lastInboundAt) {
                  lastInboundAt = e.ts || lastInboundAt;
                }
              } else if (e.view.direction === "OUTGOING") {
                if (lastOutboundAt === undefined || e.ts > lastOutboundAt) {
                  lastOutboundAt = e.ts || lastOutboundAt;
                }
              }
              for (const p of e.view.participants) {
                const idKey = p.personId ?? p.workspaceMemberId;
                if (!idKey || partSeen.has(idKey)) continue;
                partSeen.add(idKey);
                const rec: Record<string, unknown> = {};
                if (p.personId) rec.personId = p.personId;
                if (p.workspaceMemberId) {
                  rec.workspaceMemberId = p.workspaceMemberId;
                }
                if (p.role) rec.role = p.role;
                participants.push(rec);
              }
            }
            const summary: Record<string, unknown> = {
              id: threadId,
              subjectPresent: subject.length > 0,
              subjectLength: subject.length,
              messageCount: mp.items.length,
              participants,
            };
            if (lastInboundAt) summary.lastInboundAt = lastInboundAt;
            if (lastOutboundAt) summary.lastOutboundAt = lastOutboundAt;
            // EMAIL-ORD-1: a capped per-thread read is only a window on the
            // newest messages — flag it so a partial summary never reads as
            // authoritative (do NOT silently discard mp.truncated/hasMore).
            if (mp.truncated || mp.hasMore) summary.truncated = true;
            items.push(summary);
          }

          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            target,
            count: items.length,
            truncated: page.truncated,
            hasMore: page.hasMore,
            incomplete: page.incomplete,
            stopReason: page.stopReason,
            items,
            retrievedAt,
          };
          if (page.nextCursor !== undefined) snap.nextCursor = page.nextCursor;
          if (page.totalCount !== undefined) snap.totalCount = page.totalCount;
          const handle = await context.writeResource(
            "threadList",
            instanceName,
            snap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    getThread: {
      description:
        "Fan-out read (repo rule 6): the full message list for ONE thread (filter=messageThreadId), presented oldest->newest by coalesced receivedAt/createdAt (F15 — receivedAt is NULLABLE; createdAt is the non-null fallback). Per message returns BODY-FREE fields only (F6): id, direction (authoritative from messageChannelMessageAssociation — F8), subject presence+length (NOT text), body length (NOT text), participant JOIN KEYS, and timestamps. Records a `threadDetail` snapshot. No writes.",
      arguments: z.object({
        threadId: z.string().describe("messageThread UUID"),
        limit: z
          .number()
          .int()
          .positive()
          .max(MAX_LIST_CAP)
          .default(200)
          .describe(
            `Soft per-call floor (1..${MAX_LIST_CAP}) for the message page`,
          ),
        startingAfter: z
          .string()
          .optional()
          .describe("Cursor from a prior call's nextCursor"),
      }),
      execute: async (
        args: { threadId: string; limit: number; startingAfter?: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const threadId = validateUuid(args.threadId);
        if (!threadId) throw new Error("Invalid threadId (must be a UUID)");
        if (!isFilterSafe(threadId)) {
          throw new Error("Unsafe threadId filter value");
        }
        try {
          const cap = Math.min(
            Math.max(1, Math.floor(args.limit)),
            MAX_LIST_CAP,
          );
          const startingAfter = args.startingAfter
            ? String(args.startingAfter)
            : undefined;
          const page = await fetchThreadMessagesPage(
            cfg,
            threadId,
            cap,
            startingAfter,
          );
          const enriched = await enrichThreadMessages(cfg, page.items);
          // Present oldest->newest by coalesced ts (F15), id as the tiebreaker.
          enriched.sort((a, b) => {
            if (a.ts < b.ts) return -1;
            if (a.ts > b.ts) return 1;
            return a.view.id < b.view.id ? -1 : a.view.id > b.view.id ? 1 : 0;
          });
          const messages = enriched.map((e) => e.view);
          const retrievedAt = new Date().toISOString();
          const instanceName = startingAfter
            ? `thread-${threadId}-${await listInstanceHash({
              after: startingAfter,
            })}`
            : `thread-${threadId}`;
          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            threadId,
            count: messages.length,
            truncated: page.truncated,
            hasMore: page.hasMore,
            incomplete: page.incomplete,
            stopReason: page.stopReason,
            messages,
            retrievedAt,
          };
          if (page.nextCursor !== undefined) snap.nextCursor = page.nextCursor;
          if (page.totalCount !== undefined) snap.totalCount = page.totalCount;
          const handle = await context.writeResource(
            "threadDetail",
            instanceName,
            snap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    threadStatus: {
      description:
        "Derive each thread's follow-up state (awaiting-us | sent-unanswered | dormant | empty | unknown) for ONE thread (threadId) OR every thread of a record target (opportunityId | personId | companyId | leadId). Direction is AUTHORITATIVE from messageChannelMessageAssociation.direction joined by messageId (F8) — a message with no association yields direction 'unknown' and the thread state 'unknown' (never a guess). The last message is the true last by coalesced receivedAt/createdAt (F15). OUTGOING last => 'sent-unanswered' until older than dormantDays, then 'dormant'; INCOMING last => 'awaiting-us'. Records a `threadStatus` snapshot. No writes.",
      arguments: z.object({
        threadId: z
          .string()
          .optional()
          .describe(
            "Single messageThread UUID (mutually exclusive with a target)",
          ),
        opportunityId: z.string().optional(),
        personId: z.string().optional(),
        companyId: z.string().optional(),
        leadId: z.string().optional(),
        dormantDays: z
          .number()
          .int()
          .positive()
          .default(7)
          .describe(
            "Outbound-last age (days) beyond which a thread is dormant",
          ),
        limit: z
          .number()
          .int()
          .positive()
          .max(MAX_LIST_CAP)
          .default(30)
          .describe(
            `Soft per-call floor (1..${MAX_LIST_CAP}) for the thread page`,
          ),
        messageLimit: z
          .number()
          .int()
          .positive()
          .max(MAX_LIST_CAP)
          .default(60)
          .describe("Per-thread cap on messages read to find the last message"),
      }),
      execute: async (
        args: {
          threadId?: string;
          opportunityId?: string;
          personId?: string;
          companyId?: string;
          leadId?: string;
          dormantDays: number;
          limit: number;
          messageLimit: number;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const dormantDays = Math.max(1, Math.floor(args.dormantDays));
          const msgCap = Math.min(
            Math.max(1, Math.floor(args.messageLimit)),
            MAX_LIST_CAP,
          );
          const hasTarget = [
            args.opportunityId,
            args.personId,
            args.companyId,
            args.leadId,
          ].some((v) => v != null && String(v).trim() !== "");

          // Derive one thread's status (validated id only reaches a filter).
          const statusOf = async (
            tid: string,
          ): Promise<Record<string, unknown>> => {
            // EMAIL-ORD-1: NEWEST-first so the head page carries the true last
            // message even past msgCap (an ascending read returned the oldest N
            // and inverted the status verdict).
            const mp = await fetchThreadRecentMessagesPage(cfg, tid, msgCap);
            const messageCount = mp.items.length;
            if (messageCount === 0) {
              return {
                threadId: tid,
                state: "empty",
                lastDirection: "unknown",
                messageCount: 0,
              };
            }
            const last = pickLastMessage(mp.items);
            const lastId = last ? validateUuid(last.id) : null;
            const lastDirection: MessageDirection = lastId
              ? await fetchMessageDirection(cfg, lastId)
              : "unknown";
            const ts = last ? messageTs(last) : "";
            let ageDays: number | null = null;
            const parsed = ts ? Date.parse(ts) : NaN;
            if (!Number.isNaN(parsed)) {
              ageDays = (Date.now() - parsed) / 86_400_000;
            }
            const state = deriveThreadState(
              lastDirection,
              ageDays,
              dormantDays,
              messageCount,
            );
            const rec: Record<string, unknown> = {
              threadId: tid,
              state,
              lastDirection,
              messageCount,
            };
            if (ts) rec.lastMessageAt = ts;
            if (ageDays != null) rec.ageDays = Math.round(ageDays * 100) / 100;
            // EMAIL-ORD-1: the read was capped — the derived state comes from the
            // newest-first head, but flag the partial read so it is not taken as
            // an authoritative whole-thread verdict (never silently drop
            // mp.truncated/hasMore).
            if (mp.truncated || mp.hasMore) rec.truncated = true;
            return rec;
          };

          const retrievedAt = new Date().toISOString();

          if (args.threadId != null && String(args.threadId).trim() !== "") {
            if (hasTarget) {
              throw new Error(
                "Provide either threadId OR a record target, not both",
              );
            }
            const tid = validateUuid(args.threadId);
            if (!tid) throw new Error("Invalid threadId (must be a UUID)");
            if (!isFilterSafe(tid)) {
              throw new Error("Unsafe threadId filter value");
            }
            const item = await statusOf(tid);
            const handle = await context.writeResource(
              "threadStatus",
              `thread-status-${tid}`,
              {
                baseUrl: cfg.baseUrl,
                threadId: tid,
                dormantDays,
                count: 1,
                items: [item],
                retrievedAt,
              },
            );
            return { dataHandles: [handle] };
          }

          // Target set: resolve the target's threads, status each.
          const resolved = await resolveThreadTarget(cfg, args);
          const target: Record<string, unknown> = {
            kind: resolved.kind,
            found: resolved.found,
          };
          if (resolved.id !== undefined) target.id = resolved.id;
          if (resolved.resolvedKind !== undefined) {
            target.resolvedKind = resolved.resolvedKind;
          }
          if (resolved.resolvedId !== undefined) {
            target.resolvedId = resolved.resolvedId;
          }
          const h = await listInstanceHash({
            kind: resolved.kind,
            id: resolved.id ?? null,
            rid: resolved.resolvedId ?? null,
          });
          const instanceName = `thread-status-${h}`;

          const items: Array<Record<string, unknown>> = [];
          if (resolved.found) {
            const cap = Math.min(
              Math.max(1, Math.floor(args.limit)),
              MAX_LIST_CAP,
            );
            const { ids } = await fetchThreadIdsForTarget(cfg, resolved, cap);
            for (const tid of ids) {
              if (!isFilterSafe(tid)) continue;
              items.push(await statusOf(tid));
            }
          }
          const handle = await context.writeResource(
            "threadStatus",
            instanceName,
            {
              baseUrl: cfg.baseUrl,
              target,
              dormantDays,
              count: items.length,
              items,
              retrievedAt,
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    listConnectedAccounts: {
      description:
        "Read (USER-token): the send service user's own connected mailboxes via /metadata myConnectedAccounts — the fail-closed brand-pinning source of truth. Mints a per-run USER access token (the API_KEY token is FORBIDDEN here), then records a PII-CONSERVATIVE connectedAccountList snapshot: per account id + provider + handle DOMAIN ONLY (split at '@', local-part discarded) + authFailed/archived booleans. NEVER the full handle. Assumes ONE sending service user owns ALL brand mailboxes (self-scoped; there is no admin list-all). No writes.",
      arguments: z.object({}),
      execute: async (
        _args: Record<string, never>,
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        // Hoisted so the catch can scrub the minted token from a captured error.
        let userToken: string | undefined;
        try {
          userToken = await mintUserAccessToken(cfg);
          const accounts = await fetchConnectedAccounts(cfg, userToken);
          const retrievedAt = new Date().toISOString();
          const handle = await context.writeResource(
            "connectedAccountList",
            "connected-accounts",
            {
              baseUrl: cfg.baseUrl,
              count: accounts.length,
              items: accounts,
              retrievedAt,
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          // TE-1: also mask the send password + minted user token.
          throw new Error(
            redactError(e, 300, cfg.apiToken, [
              cfg.sendUserPassword,
              userToken,
            ]),
          );
        }
      },
    },
    sendEmail: {
      description:
        "Send an email AS a pinned brand via Twenty's native 'Send Email' workflow (runWorkflowVersion) — dry-by-default, confirm-gated, FAIL-CLOSED identity. Resolves exactly ONE connectedAccountId (explicit fromBrand -> per-lineOfBusiness default for opp targets only; F4/F5) and, before sending, re-validates it against the LIVE myConnectedAccounts list AND asserts its account domain equals the brand (F3) — an empty/ambiguous id, unmapped fromBrand, or domain mismatch each REFUSE. Mints a per-run USER access token (F1b). The recipient is validateEmail'd (F11); subject/body are control-char sanitized but UTF-8-PRESERVED (F19). Idempotent via a durable dedup marker keyed on to+connectedAccountId+replyThread+day+subject+body (or a caller dedupKey; F9/F10) — a hit is `skipped`. DEDUP BOUNDARIES (EMAIL-DEDUP-2): the default `day` component is a UTC-CALENDAR-DAY bucket, so a retry that crosses UTC midnight computes a NEW key and MAY re-send (dedup is at-least-once across a midnight boundary); pass an explicit `dedupKey` to pin idempotency across that boundary. Marker semantics are also at-least-once by design — a crash between enqueue and marker-write lets a retry re-send rather than risk a lost mail. Ordering: check-dedup -> send -> record. A live send REQUIRES confirm:true AND dryRun:false; dryRun (default) returns the fully-resolved plan and records NO dedup marker. runWorkflowVersion is fire-and-forget: sendRun records the async workflowRunId, never a sent-message id (F13). The sendRun audit stores JOIN KEYS + connectedAccountId + a hashed recipient + subject/body LENGTHS only — never the raw to/subject/body (F6/F7).",
      arguments: z.object({
        opportunityId: z.string().optional().describe(
          "Opportunity UUID target — at most one of the four targets",
        ),
        personId: z.string().optional().describe("Person UUID target"),
        companyId: z.string().optional().describe("Company UUID target"),
        leadId: z.string().optional().describe(
          "Lead marker target (resolved to its opportunity, then person)",
        ),
        to: z.string().optional().describe(
          "Explicit recipient email. Absent => resolve from a Person target's primary email. validateEmail'd either way (F11).",
        ),
        subject: z.string().default("").describe(
          "Email subject (UTF-8 preserved)",
        ),
        body: z.string().default("").describe(
          "Email body, plaintext (UTF-8 preserved)",
        ),
        fromBrand: z.string().optional().describe(
          "Brand DOMAIN to send AS (a key of brandConnectedAccounts). An explicit-but-unmapped value is a HARD REFUSE (F4); only an ABSENT value may consult the per-lineOfBusiness default (opp targets only, F5).",
        ),
        inReplyToThreadId: z.string().optional().describe(
          "Existing messageThread to reply on (threading + dedup component)",
        ),
        dedupKey: z.string().optional().describe(
          "Caller-supplied idempotency key. Absent => computed from to+connectedAccountId+replyThread+UTC-day+subject+body (F9). A deliberate identical resend needs a distinct key.",
        ),
        confirm: z.boolean().optional().describe(
          "Execute the send. A live send requires confirm:true AND dryRun:false.",
        ),
        dryRun: z.boolean().optional().describe(
          "Plan without sending (default true). Returns the fully-resolved plan and records NO dedup marker.",
        ),
      }),
      execute: async (
        args: {
          opportunityId?: string;
          personId?: string;
          companyId?: string;
          leadId?: string;
          to?: string;
          subject: string;
          body: string;
          fromBrand?: string;
          inReplyToThreadId?: string;
          dedupKey?: string;
          confirm?: boolean;
          dryRun?: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        // Hoisted so the catch can scrub the minted token from a captured error.
        let userToken: string | undefined;
        try {
          const dryRun = args.dryRun !== false; // default true
          const confirm = args.confirm === true;
          if (!dryRun && !confirm) {
            throw new Error(
              "A live send requires confirm:true AND dryRun:false (refused)",
            );
          }
          // F14: validate the brand map at (first-send) load, fail-closed.
          const brandMap = (cfg.brandConnectedAccounts ?? {}) as Record<
            string,
            string
          >;
          const lobMap = (cfg.lineOfBusinessBrand ?? {}) as Record<
            string,
            string
          >;
          const mapErr = validateBrandMap(brandMap);
          if (mapErr) {
            throw new Error(`brandConnectedAccounts invalid: ${mapErr}`);
          }

          // Resolve the target (validates ids; leadId -> opp/person). TE-4:
          // strictLeadId REFUSES an ambiguous (>1) leadId->opportunity match so a
          // duplicate leadId can never silently pick one opp and drive the
          // wrong-brand LoB default. Read methods keep the tolerant first-match.
          const resolved = await resolveThreadTarget(cfg, args, {
            strictLeadId: true,
          });
          if (resolved.kind !== "workspace" && !resolved.found) {
            throw new Error("Target did not resolve to any record (refused)");
          }
          const targetKind = resolved.resolvedKind ?? resolved.kind;

          // F5 default path needs the opp's lineOfBusiness (only when no explicit
          // fromBrand AND the target is an opportunity).
          let lineOfBusiness: string | null = null;
          const fromBrand = (args.fromBrand ?? "").trim();
          if (
            !fromBrand && targetKind === "opportunity" && resolved.resolvedId
          ) {
            const oj = await twentyRequest(
              cfg,
              "GET",
              `/rest/opportunities/${resolved.resolvedId}`,
            );
            const opp = ((oj as { data?: Record<string, unknown> })?.data
              ?.opportunity as Record<string, unknown> | undefined) ?? {};
            lineOfBusiness = opp.lineOfBusiness != null
              ? String(opp.lineOfBusiness)
              : null;
          }

          // Fail-closed brand -> connectedAccountId resolution (F3/F4/F5/F14).
          const br = resolveBrandForSend({
            fromBrand,
            targetKind,
            lineOfBusiness,
            brandMap,
            lobMap,
          });
          if (!br.ok) throw new Error(br.reason);
          const { brand, connectedAccountId, source } = br;

          // Resolve + validate the recipient (F11): explicit `to`, else a Person
          // target's primary email. Attacker-influenced either way => validateEmail.
          let to = validateEmail(args.to);
          if (!to && targetKind === "person" && resolved.resolvedId) {
            const pj = await twentyRequest(
              cfg,
              "GET",
              `/rest/people/${resolved.resolvedId}`,
            );
            const person = ((pj as { data?: Record<string, unknown> })?.data
              ?.person as Record<string, unknown> | undefined) ?? {};
            const emails = person.emails as Record<string, unknown> | undefined;
            to = validateEmail(emails?.primaryEmail);
          }
          if (!to || !isFilterSafe(to)) {
            throw new Error(
              "Could not resolve a valid recipient email (F11 — refused)",
            );
          }

          // UTF-8-preserving sanitize (F19): strips control chars/markup, keeps
          // accented/non-Latin text.
          const subject = sanitizeText(args.subject, 300);
          const body = sanitizeText(args.body, 20000);

          // Mint a per-run USER token (F1b), fail-closed on any error.
          userToken = await mintUserAccessToken(cfg);

          // F3 run-time re-validation: the id must exist LIVE and its domain must
          // equal the brand — this is what stops the wrong-brand fallback bug.
          const accounts = await fetchConnectedAccounts(cfg, userToken);
          const acct = accounts.find((a) => a.id === connectedAccountId);
          if (!acct) {
            throw new Error(
              "Chosen connectedAccountId is not in the live myConnectedAccounts list (F3 — refused)",
            );
          }
          if (acct.domain !== brand) {
            throw new Error(
              `Connected account domain does not match brand '${brand}' (F3 domain mismatch — refused)`,
            );
          }
          if (acct.archived || acct.authFailed) {
            throw new Error(
              "Chosen connected account is archived or in an auth-failed state (refused)",
            );
          }

          // F12: resolve the ACTIVE Send-Email workflow version (never pinned).
          const workflowVersionId = await resolveActiveWorkflowVersionId(
            cfg,
            cfg.sendWorkflowName ?? "Send Email",
          );
          if (!workflowVersionId) {
            throw new Error(
              `Send-Email workflow '${
                cfg.sendWorkflowName ?? "Send Email"
              }' has no active/published version (F12 — refused)`,
            );
          }

          // Dedup identity (F9) + PII-safe audit values (F7).
          const dedupKey = (args.dedupKey ?? "").trim() ||
            await computeDedupKey({
              to,
              connectedAccountId,
              inReplyToThreadId: args.inReplyToThreadId,
              subject,
              body,
            });
          const markerId = await sendDedupMarkerId(dedupKey);
          const toHash = await sha256Hex(to);

          const target: Record<string, unknown> = {
            kind: resolved.kind,
            found: resolved.found,
          };
          if (resolved.id !== undefined) target.id = resolved.id;
          if (resolved.resolvedKind !== undefined) {
            target.resolvedKind = resolved.resolvedKind;
          }
          if (resolved.resolvedId !== undefined) {
            target.resolvedId = resolved.resolvedId;
          }

          const retrievedAt = new Date().toISOString();
          const base: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            target,
            fromBrand: brand,
            brandSource: source,
            connectedAccountId,
            workflowVersionId,
            dedupKey: markerId,
            toHash,
            subjectLength: subject.length,
            bodyLength: body.length,
            at: retrievedAt,
          };
          if (targetKind === "person" && resolved.resolvedId) {
            base.personId = resolved.resolvedId;
          } else if (targetKind === "opportunity" && resolved.resolvedId) {
            base.opportunityId = resolved.resolvedId;
          } else if (targetKind === "company" && resolved.resolvedId) {
            base.companyId = resolved.resolvedId;
          }

          const record = async (extra: Record<string, unknown>) => {
            const h = await listInstanceHash({ markerId, at: retrievedAt });
            return await context.writeResource("sendRun", `send-${h}`, {
              ...base,
              ...extra,
            });
          };

          // dryRun (default): fully-resolved plan, NO dedup marker, NO send (F10).
          if (dryRun) {
            const handle = await record({
              status: "planned",
              dryRun: true,
              wouldSend: true,
              sent: false,
              skipped: false,
              dedupRecorded: false,
            });
            return { dataHandles: [handle] };
          }

          // Live send. Ordering: check-dedup -> send -> record (F10).
          const prior = await findPriorSend(cfg, markerId);
          if (prior) {
            const handle = await record({
              status: "skipped",
              dryRun: false,
              wouldSend: true,
              sent: false,
              skipped: true,
              dedupRecorded: false,
            });
            return { dataHandles: [handle] };
          }

          const payload: Record<string, unknown> = {
            connectedAccountId,
            to,
            subject,
            body,
          };
          if (args.inReplyToThreadId) {
            const rt = validateUuid(args.inReplyToThreadId);
            if (rt) payload.inReplyToThreadId = rt;
          }
          const workflowRunId = await runSendWorkflow(
            cfg,
            userToken,
            workflowVersionId,
            payload,
          );
          // Record the durable dedup marker AFTER a successful enqueue. Accepted
          // crash semantic (F10): a crash between enqueue and marker-write lets a
          // retry re-send (at-least-once) rather than risk a never-sent lost mail.
          await writeSendMarker(cfg, markerId);
          const handle = await record({
            status: "sent",
            dryRun: false,
            wouldSend: true,
            sent: true,
            skipped: false,
            dedupRecorded: true,
            workflowRunId,
          });
          return { dataHandles: [handle] };
        } catch (e) {
          // TE-1: also mask the send password + minted user token.
          throw new Error(
            redactError(e, 300, cfg.apiToken, [
              cfg.sendUserPassword,
              userToken,
            ]),
          );
        }
      },
    },
    getNoteBody: {
      description:
        "SR-1 EXCEPTION — reads ONE Note's body (bodyV2.markdown) across the privacy boundary that listNotes/mapNoteView deliberately withhold. confirm:true REQUIRED as an explicit acknowledgement that this crosses the note-body privacy boundary (NOT a mutation gate). noteId must be a UUID. Result is delivered via a SHORT-TTL (3d) noteBodyRead snapshot — read data.latest('noteBodyRead','note-body-<id>').attributes.body; the body is PII-at-rest bounded by that TTL. 404 => found:false. found:true with no markdown (blocknote-only/empty) => bodyMissing:true, no body. Title is emitted verbatim here (the listNotes title guard does not apply to this gated method). Discover the noteId first via listNotes (leadId-tagged) or listNotesByOpportunity.",
      arguments: z.object({
        noteId: z.string().describe("Note UUID to read the body of"),
        confirm: z
          .boolean()
          .default(false)
          .describe(
            "Must be true — explicit acknowledgement that this READS a note body across the SR-1 privacy boundary (note bodies are withheld everywhere else). Not a mutation gate.",
          ),
      }),
      execute: async (
        args: { noteId: string; confirm: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        if (!args.confirm) {
          throw new Error(
            "Refusing to read a note body without confirm:true — this crosses the SR-1 privacy boundary (note bodies are withheld by default); pass confirm:true to acknowledge the deliberate cross-boundary read",
          );
        }
        const noteId = validateUuid(args.noteId);
        if (!noteId) throw new Error("Invalid noteId (must be a UUID)");
        try {
          const note = await getByIdOrNull(
            cfg,
            `/rest/notes/${noteId}`,
            "note",
          );
          const retrievedAt = new Date().toISOString();
          // Explicit field-by-field allowlist (never a raw-record spread) so no
          // future Note custom field rides into the persisted body snapshot.
          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            found: Boolean(note),
            retrievedAt,
          };
          if (note) {
            snap.id = String(note.id ?? noteId);
            if (note.leadId != null && note.leadId !== "") {
              snap.leadId = String(note.leadId);
            }
            if (note.title != null && note.title !== "") {
              snap.title = String(note.title);
            }
            const md =
              (note.bodyV2 as { markdown?: unknown } | null | undefined)
                ?.markdown;
            if (typeof md === "string" && md.length) snap.body = md;
            else snap.bodyMissing = true;
            if (note.createdAt) snap.createdAt = String(note.createdAt);
            if (note.updatedAt) snap.updatedAt = String(note.updatedAt);
          }
          const handle = await context.writeResource(
            "noteBodyRead",
            `note-body-${noteId}`,
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
    createNote: {
      description:
        "Create a Note (title + optional markdown body) and link it to opportunity/person/company targets, idempotently. With leadId: dedups on the Note carrying it (reuse + reconcile targets, never duplicate) — the push_leads contract. Without leadId: always creates (caller owns identity; amend via updateNote/appendNote). Body written VERBATIM (untrusted-input callers MUST escapeMarkdown first); title sanitized (≤200). confirm-gated, dryRun-by-default. Records a noteWrite snapshot (no body text). NOTE: leadId dedup needs note.leadId provisioned (ensureLeadFields).",
      arguments: z.object({
        title: z.string().describe("Note title (sanitized, ≤200 chars)"),
        body: z
          .string()
          .optional()
          .describe("Markdown body, written verbatim to bodyV2.markdown"),
        targets: z
          .array(
            z.object({
              opportunityId: z.string().optional(),
              personId: z.string().optional(),
              companyId: z.string().optional(),
            }),
          )
          .optional()
          .describe("Records to link; each entry carries EXACTLY one id"),
        leadId: z
          .string()
          .optional()
          .describe("Idempotency marker; when set, dedups on the Note with it"),
        dryRun: z.boolean().default(false),
        confirm: z.boolean().default(false),
      }),
      execute: async (
        args: {
          title: string;
          body?: string;
          targets?: Array<
            { opportunityId?: string; personId?: string; companyId?: string }
          >;
          leadId?: string;
          dryRun: boolean;
          confirm: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const title = sanitizeText(args.title, 200);
          if (!title) throw new Error("createNote requires a non-empty title");
          let leadId: string | undefined;
          if (args.leadId != null && String(args.leadId).trim() !== "") {
            const v = validateLeadId(args.leadId);
            if (!v) throw new Error("createNote: invalid leadId");
            leadId = v;
          }
          const body = args.body != null ? String(args.body) : undefined;
          const targets = (args.targets ?? []).map(normalizeNoteTarget);
          // Stable snapshot identity (A2): survives plan→confirm without a note
          // id — leadId when present, else a content hash.
          const instance = leadId
            ? `note-write-lead-${leadId}`
            : `note-write-${await listInstanceHash({
              title,
              body: body ?? null,
              targets: targets.map((t) => `${t.field}:${t.id}`).sort(),
            })}`;
          const willWrite = args.confirm === true && args.dryRun !== true;
          if (!willWrite) {
            const handle = await context.writeResource("noteWrite", instance, {
              baseUrl: cfg.baseUrl,
              op: "create",
              action: "planned-create",
              title,
              leadId,
              targetsLinked: [],
              bodyLength: body?.length,
              dryRun: args.dryRun === true,
              confirmed: args.confirm === true,
              writtenAt: new Date().toISOString(),
            });
            return { dataHandles: [handle] };
          }
          // Population guard (TWENTY-NOTE-RECONCILE): createNote is an opted-in
          // reconcile writer, so when note.noteHash is provisioned it stamps the
          // keyed HMAC of title+body (fail-closed on an empty key, SEC-5); field
          // absent ⇒ undefined ⇒ no hash written (ADV-2). Computed pre-create so
          // it rides the SAME POST; only stored on a real create (never on a
          // leadId dedup-reuse). push_leads uses ensureNoteForLead, not this
          // method, so the lead sink never hashes (pushLeadsContract).
          const noteHash = await computeNoteHashForWrite(
            cfg,
            title,
            body ?? "",
          );
          // Capture the note id BEFORE reconciling targets (A6) so a link
          // failure never orphans — targets are best-effort, id is returned.
          const { noteId, created } = await createOrReuseNote(cfg, {
            title,
            body,
            leadId,
            dedupByLeadId: Boolean(leadId),
            noteHash,
          });
          const { linked, failed } = await reconcileNoteTargets(
            cfg,
            noteId,
            targets,
            { bestEffort: true },
          );
          const createdSnap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            op: "create",
            action: created ? "created" : "present",
            id: noteId,
            title,
            leadId,
            targetsLinked: linked,
            targetsFailed: failed.length ? failed : undefined,
            bodyLength: body?.length,
            dryRun: false,
            confirmed: true,
            writtenAt: new Date().toISOString(),
          };
          // Only a real create stores the hash; a dedup-reuse leaves the note
          // (and its existing noteHash) untouched.
          if (created && noteHash) createdSnap.bodyHash = noteHash;
          const handle = await context.writeResource(
            "noteWrite",
            instance,
            createdSnap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    updateNote: {
      description:
        "Update a Note's title and/or body (full REPLACE, not append) via PATCH /rest/notes/{id}. Title sanitized; body verbatim. Refuses a body write on a note carrying a non-empty blocknote unless markdown re-derivation is proven (design §6/A5/S6). 404 → not-found. confirm-gated, dryRun-by-default. Records a noteWrite snapshot (no body text).",
      arguments: z.object({
        noteId: z.string(),
        title: z.string().optional().describe("New title (sanitized, ≤200)"),
        body: z
          .string()
          .optional()
          .describe("New markdown body (full replace of bodyV2.markdown)"),
        dryRun: z.boolean().default(false),
        confirm: z.boolean().default(false),
      }),
      execute: async (
        args: {
          noteId: string;
          title?: string;
          body?: string;
          dryRun: boolean;
          confirm: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const noteId = validateUuid(args.noteId);
          if (!noteId) {
            throw new Error("updateNote: noteId is not a valid UUID");
          }
          const hasTitle = args.title != null;
          const hasBody = args.body != null;
          if (!hasTitle && !hasBody) {
            throw new Error("updateNote requires title and/or body");
          }
          const title = hasTitle ? sanitizeText(args.title, 200) : undefined;
          const body = hasBody ? String(args.body) : undefined;
          const instance = `note-write-${noteId}`;
          const willWrite = args.confirm === true && args.dryRun !== true;
          const snap = (
            action: string,
            found?: boolean,
          ): Record<string, unknown> => ({
            baseUrl: cfg.baseUrl,
            op: "update",
            action,
            id: noteId,
            ...(found !== undefined ? { found } : {}),
            title,
            bodyLength: body?.length,
            targetsLinked: [],
            dryRun: args.dryRun === true,
            confirmed: args.confirm === true,
            writtenAt: new Date().toISOString(),
          });
          // SR-1 parity (appendNote/getNoteBody): only a CONFIRMED real write
          // resolves the note. A dryRun / unconfirmed / title-only call plans
          // WITHOUT a body-bearing GET — updateNote is a full-replace and never
          // uses the existing body, so an unconfirmed read would cross the
          // note-body privacy boundary for nothing. Existence is verified at
          // write time; a plan does not pre-confirm the note exists.
          if (!willWrite) {
            const handle = await context.writeResource(
              "noteWrite",
              instance,
              snap("planned-update"),
            );
            return { dataHandles: [handle] };
          }
          // confirm===true, real write: resolving the note here is the SR-1
          // crossing, acknowledged by confirm:true (404 + dormant blocknote guard).
          const note = await getByIdOrNull(
            cfg,
            `/rest/notes/${encodeURIComponent(noteId)}`,
            "note",
          );
          if (!note) {
            const handle = await context.writeResource(
              "noteWrite",
              instance,
              snap("not-found", false),
            );
            return { dataHandles: [handle] };
          }
          if (
            hasBody && !BODYV2_MARKDOWN_REDERIVES && noteHasBlocknote(note)
          ) {
            const handle = await context.writeResource(
              "noteWrite",
              instance,
              snap("refused-blocknote", true),
            );
            return { dataHandles: [handle] };
          }
          // Population guard (TWENTY-NOTE-RECONCILE): updateNote is an opted-in
          // reconcile writer. The hash must cover the note's FULL post-write
          // title+body, so a body-only update reuses the existing title and a
          // title-only update reuses the existing body — both read from the
          // already-fetched `note` (no extra I/O), and the existing body is used
          // ONLY to hash, never snapshotted/logged (SR-1 intact). Fail-closed on
          // an empty key when provisioned (SEC-5); field absent ⇒ no hash.
          // ADV-3 (read-back fidelity): the reconciler's create + full-replace
          // paths hash the INPUT body, so they match a YAML-derived hash
          // regardless of any Twenty normalization. Only this title-only path
          // hashes the READ-BACK bodyV2.markdown. PROBE (twenty-local, Twenty
          // v2.38.1, 2026-09-18): a created markdown body round-trips
          // BYTE-IDENTICAL on read-back (trailing spaces + blank lines
          // preserved), so read-back-body == input-body and the title-only hash
          // stays consistent with the reconciler. Version-dependent, like the §6
          // blocknote probe: if a future Twenty normalizes markdown on read, a
          // title-only update could produce a hash the reconciler reads as
          // diverged (a self-healing full-replace, never a silent clobber).
          const finalTitle = hasTitle
            ? (title ?? "")
            : String(note.title ?? "");
          const finalBody = hasBody ? (body ?? "") : noteMarkdown(note);
          const noteHash = await computeNoteHashForWrite(
            cfg,
            finalTitle,
            finalBody,
          );
          const patch: Record<string, unknown> = {};
          if (hasTitle) patch.title = title;
          if (hasBody) patch.bodyV2 = { markdown: body };
          if (noteHash) patch.noteHash = noteHash;
          await noteWriteRequest(
            cfg,
            "PATCH",
            `/rest/notes/${encodeURIComponent(noteId)}`,
            patch,
            "update",
          );
          const updatedSnap = snap("updated", true);
          if (noteHash) updatedSnap.bodyHash = noteHash;
          const handle = await context.writeResource(
            "noteWrite",
            instance,
            updatedSnap,
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    appendNote: {
      description:
        "Append markdown to a Note's body (read-modify-write). confirm:true REQUIRED — it acknowledges that this READS the existing note body across the SR-1 privacy boundary; without confirm NO read happens (a dryRun-without-confirm returns a shallow 'would append' plan; a non-dry call refuses). The pre-existing body is NEVER snapshotted, logged, or thrown. Refuses on a note carrying a non-empty blocknote unless markdown re-derivation is proven (design §6/A5/S6). 404 → not-found. dryRun-by-default (with confirm) plans without writing. Records a noteWrite snapshot (bodyLength only).",
      arguments: z.object({
        noteId: z.string(),
        text: z.string().describe("Markdown to append (verbatim)"),
        dryRun: z.boolean().default(false),
        confirm: z.boolean().default(false),
      }),
      execute: async (
        args: {
          noteId: string;
          text: string;
          dryRun: boolean;
          confirm: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const noteId = validateUuid(args.noteId);
          if (!noteId) {
            throw new Error("appendNote: noteId is not a valid UUID");
          }
          const text = String(args.text ?? "");
          if (!text) throw new Error("appendNote requires non-empty text");
          const instance = `note-write-${noteId}`;
          // S2: refuse BEFORE any GET when confirm is not true, in BOTH dryRun
          // states — the read itself is the SR-1 crossing that confirm gates.
          if (args.confirm !== true) {
            if (args.dryRun === true) {
              // Shallow plan — no body read, no bodyLength.
              const handle = await context.writeResource(
                "noteWrite",
                instance,
                {
                  baseUrl: cfg.baseUrl,
                  op: "append",
                  action: "planned-append",
                  id: noteId,
                  targetsLinked: [],
                  dryRun: true,
                  confirmed: false,
                  writtenAt: new Date().toISOString(),
                },
              );
              return { dataHandles: [handle] };
            }
            throw new Error(
              "Refusing to appendNote without confirm:true (reads a note body across the SR-1 privacy boundary)",
            );
          }
          // confirm === true: the SR-1 read is acknowledged.
          const note = await getByIdOrNull(
            cfg,
            `/rest/notes/${encodeURIComponent(noteId)}`,
            "note",
          );
          const baseSnap = (
            action: string,
            found: boolean,
            bodyLength?: number,
          ): Record<string, unknown> => ({
            baseUrl: cfg.baseUrl,
            op: "append",
            action,
            id: noteId,
            found,
            bodyLength,
            targetsLinked: [],
            dryRun: args.dryRun === true,
            confirmed: true,
            writtenAt: new Date().toISOString(),
          });
          if (!note) {
            const handle = await context.writeResource(
              "noteWrite",
              instance,
              baseSnap("not-found", false),
            );
            return { dataHandles: [handle] };
          }
          if (!BODYV2_MARKDOWN_REDERIVES && noteHasBlocknote(note)) {
            const handle = await context.writeResource(
              "noteWrite",
              instance,
              baseSnap("refused-blocknote", true),
            );
            return { dataHandles: [handle] };
          }
          const existing = noteMarkdown(note);
          // A10: trim trailing newlines before the \n\n join; empty body → text.
          const merged = existing
            ? existing.replace(/\n+$/, "") + "\n\n" + text
            : text;
          if (args.dryRun === true) {
            const handle = await context.writeResource(
              "noteWrite",
              instance,
              baseSnap("planned-append", true, merged.length),
            );
            return { dataHandles: [handle] };
          }
          await noteWriteRequest(
            cfg,
            "PATCH",
            `/rest/notes/${encodeURIComponent(noteId)}`,
            { bodyV2: { markdown: merged } },
            "append",
          );
          const handle = await context.writeResource(
            "noteWrite",
            instance,
            baseSnap("appended", true, merged.length),
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    linkNote: {
      description:
        "Link a Note to ONE record (opportunity/person/company) via a noteTarget, idempotently. Already linked → already-linked (exact-id match, A4). Verifies the created row carries the intended id (S7). confirm-gated, dryRun-by-default. Records a noteWrite snapshot.",
      arguments: z.object({
        noteId: z.string(),
        target: z.object({
          opportunityId: z.string().optional(),
          personId: z.string().optional(),
          companyId: z.string().optional(),
        }),
        dryRun: z.boolean().default(false),
        confirm: z.boolean().default(false),
      }),
      execute: async (
        args: {
          noteId: string;
          target: {
            opportunityId?: string;
            personId?: string;
            companyId?: string;
          };
          dryRun: boolean;
          confirm: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const noteId = validateUuid(args.noteId);
          if (!noteId) throw new Error("linkNote: noteId is not a valid UUID");
          const target = normalizeNoteTarget(args.target);
          const instance = `note-write-${noteId}`;
          const willWrite = args.confirm === true && args.dryRun !== true;
          const existing = unwrapList(
            await twentyRequest(
              cfg,
              "GET",
              buildFilterPath("/rest/noteTargets", "noteId", noteId),
            ),
            "noteTargets",
          );
          const already = existing.some((r) =>
            String(r[target.field] ?? "") === target.id
          );
          const snap = (
            action: string,
            linked: string[],
          ): Record<string, unknown> => ({
            baseUrl: cfg.baseUrl,
            op: "link",
            action,
            id: noteId,
            targetsLinked: linked,
            dryRun: args.dryRun === true,
            confirmed: args.confirm === true,
            writtenAt: new Date().toISOString(),
          });
          if (already) {
            const handle = await context.writeResource(
              "noteWrite",
              instance,
              snap("already-linked", [target.id]),
            );
            return { dataHandles: [handle] };
          }
          if (!willWrite) {
            const handle = await context.writeResource(
              "noteWrite",
              instance,
              snap("planned-link", []),
            );
            return { dataHandles: [handle] };
          }
          const { linked, failed } = await reconcileNoteTargets(
            cfg,
            noteId,
            [target],
            {},
          );
          const handle = await context.writeResource(
            "noteWrite",
            instance,
            {
              ...snap(linked.length ? "linked" : "not-linked", linked),
              targetsFailed: failed.length ? failed : undefined,
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    unlinkNote: {
      description:
        "Remove ONE noteTarget link (opportunity/person/company) from a Note by exact-id match (A4) — never deletes the Note, never a non-matching target. Absent → not-linked. confirm-gated, dryRun-by-default. Records a noteWrite snapshot.",
      arguments: z.object({
        noteId: z.string(),
        target: z.object({
          opportunityId: z.string().optional(),
          personId: z.string().optional(),
          companyId: z.string().optional(),
        }),
        dryRun: z.boolean().default(false),
        confirm: z.boolean().default(false),
      }),
      execute: async (
        args: {
          noteId: string;
          target: {
            opportunityId?: string;
            personId?: string;
            companyId?: string;
          };
          dryRun: boolean;
          confirm: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const noteId = validateUuid(args.noteId);
          if (!noteId) {
            throw new Error("unlinkNote: noteId is not a valid UUID");
          }
          const target = normalizeNoteTarget(args.target);
          const instance = `note-write-${noteId}`;
          const willWrite = args.confirm === true && args.dryRun !== true;
          const existing = unwrapList(
            await twentyRequest(
              cfg,
              "GET",
              buildFilterPath("/rest/noteTargets", "noteId", noteId),
            ),
            "noteTargets",
          );
          const row = existing.find((r) =>
            String(r[target.field] ?? "") === target.id
          );
          const snap = (action: string): Record<string, unknown> => ({
            baseUrl: cfg.baseUrl,
            op: "unlink",
            action,
            id: noteId,
            targetsLinked: [],
            dryRun: args.dryRun === true,
            confirmed: args.confirm === true,
            writtenAt: new Date().toISOString(),
          });
          if (!row) {
            const handle = await context.writeResource(
              "noteWrite",
              instance,
              snap("not-linked"),
            );
            return { dataHandles: [handle] };
          }
          if (!willWrite) {
            const handle = await context.writeResource(
              "noteWrite",
              instance,
              snap("planned-unlink"),
            );
            return { dataHandles: [handle] };
          }
          const rowId = validateUuid(row.id);
          if (!rowId) throw new Error("unlinkNote: noteTarget row id invalid");
          await twentyRequest(
            cfg,
            "DELETE",
            `/rest/noteTargets/${encodeURIComponent(rowId)}`,
          );
          const handle = await context.writeResource(
            "noteWrite",
            instance,
            snap("unlinked"),
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
        // SHADOW-MODE spam classification: score over the WHOLE corpus (so the
        // repeat-email / IP-rotation velocity signals see every lead, not just
        // this capped page), then annotate the processed results below. This
        // phase only REPORTS - it never quarantines or changes a lead's fate.
        // Uses the operator-configurable blocklist (same as planLead), not the
        // hardcoded default (review M3). knownDomains hard-pass stays empty
        // until the ENFORCE-phase IN/Twenty join wires it (review M1).
        const spamVerdicts = classifyLead(allLeads, {
          freemailDomains: cfg.emailDomainBlocklist,
        });
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

        // Attach the shadow-mode spam verdict to each processed lead. Matched by
        // batch INDEX (results are pushed 1:1 in batch order) against each
        // lead's OWN validated id - never by the result row's leadId, which for
        // a failed plan is the "unknown" sentinel and could collide with a real
        // lead literally id'd "unknown" (review M4). Enriching after the write
        // loop keeps the three results.push sites untouched and makes it
        // unmistakable that the score never gated a lead this phase.
        batch.forEach((lead, i) => {
          const vid = validateLeadId(lead.id);
          const v = vid ? spamVerdicts.get(vid) : undefined;
          if (v && results[i]) {
            results[i].spamScore = v.score;
            results[i].spamReasons = v.reasons;
            results[i].spamFlagged = v.flagged;
          }
        });

        const synced = results.filter((r) => r.status === "synced").length;
        const skipped = results.filter((r) => r.status === "skipped").length;
        const failed = results.filter((r) => r.status === "failed").length;
        const emergencies = results.filter((r) => r.emergency).length;
        const spamFlagged = results.filter((r) => r.spamFlagged).length;

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
            spamFlagged,
            perLead: results.map((r) => ({
              leadId: r.leadId,
              action: r.action,
              status: r.status,
              emergency: r.emergency,
              // Shadow spam annotation surfaced in the audit summary too, not
              // just results[] (design section 5 "reports score + reasons per
              // lead"; review L2).
              ...(r.spamFlagged !== undefined
                ? {
                  spamScore: r.spamScore,
                  spamReasons: r.spamReasons,
                  spamFlagged: r.spamFlagged,
                }
                : {}),
            })),
          },
        });
        context.logger.info(
          "push_leads done: {synced} synced, {skipped} skipped, {failed} failed, {emergencies} emergencies, {spamFlagged} spam-flagged [shadow]",
          { synced, skipped, failed, emergencies, spamFlagged },
        );
        return { dataHandles: [handle] };
      },
    },
    upsertOpportunity: {
      description:
        "Generalized, idempotent Opportunity upsert keyed on leadId — the create/update path with the full field set (name, amount, stage, closeDate, company, point of contact, channelPartner, and the lineOfBusiness/sourceChannel/offering segmentation SELECTs) that push_leads' bare createOpportunity omits. Finds any existing Opportunity by leadId: hit => PATCH the provided fields; miss => create. Optionally finds-or-creates and links a Company (by domain, else by exact name) and a point-of-contact Person (by email), and attaches a markdown Note. amount is given in whole currency units (50000 => $50,000) and stored as Twenty currency micros. confirm:true required for a real run; dryRun:true resolves + plans and writes nothing. Snapshots an `opportunityUpsert` resource.",
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
        asn: z
          .string()
          .optional()
          .describe(
            "Autonomous System Number (TEXT), e.g. AS64496. Format-guarded to ^AS<digits>$ (case-insensitive input, uppercased on store); a non-empty value not matching is rejected. Omitted / empty => left unchanged on both create and update (never nulled).",
          ),
        qualStatus: z
          .string()
          .optional()
          .describe(
            "Technical-qualification SELECT option token (e.g. RESEARCH, CONTACT_IDENTIFIED, TECH_QUALIFICATION_NEEDED, FUTURE). Validated against the live opportunity.qualStatus enum exactly like stage. Omitted / empty => left unchanged on both create and update (never nulled). Requires the field to be provisioned (ensureField).",
          ),
        offering: z
          .string()
          .optional()
          .describe(
            "Offering segmentation SELECT option token (UPPER_SNAKE: MANAGED, SUBSTRATE, PROJECT, RETAINER, LOCAL_IT, PEERING). Validated against the live opportunity.offering enum exactly like stage. Omitted / empty => left unchanged on both create and update (never nulled). Requires the field to be provisioned (ensureOpportunitySegmentation).",
          ),
        customFields: z
          .record(z.string(), z.union([z.string(), z.number(), z.boolean()]))
          .optional()
          .describe(
            "Generic scalar-field escape hatch for Opportunity custom fields without a typed argument. Each key must be a camelCase field that exists on opportunity and is a scalar TYPE (TEXT/NUMBER/BOOLEAN/DATE_TIME/SELECT/UUID); reserved keys (leadId + every typed-arg field + system fields) and composite/unknown types are rejected pre-write; SELECT values are validated against the live enum; string values are sanitized; an empty string means unset (omit); null is not permitted. FAIL-CLOSED: if opportunity metadata is unreadable, the whole map is rejected. Omitted keys are left unchanged.",
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
        channelPartnerId: z
          .string()
          .optional()
          .describe(
            "channelPartner record UUID to link (the opportunity.channelPartner MANY_TO_ONE relation, for marketplace attribution). Validated as a UUID; empty/omitted => left unchanged (never nulled). Takes precedence over channelPartnerName.",
          ),
        channelPartnerName: z
          .string()
          .default("")
          .describe(
            "channelPartner name to resolve-and-link (link-only; channelPartner is keyed by name, e.g. 'Globex'/'Initech'). Used only when channelPartnerId is unset. A name with no match records channelPartnerSkipped and leaves the link unchanged — never creates a partner.",
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
          asn?: string;
          qualStatus?: string;
          offering?: string;
          customFields?: Record<string, string | number | boolean>;
          closeDate: string;
          companyName: string;
          companyDomain: string;
          pointOfContactName: string;
          pointOfContactEmail: string;
          channelPartnerId?: string;
          channelPartnerName: string;
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
        // channelPartnerId (TWENTY-OPP-CHANNEL): validate the UUID format EARLY —
        // before any metadata fetch or write — so a malformed id fails pre-write
        // even under dryRun. Empty/omitted => no id (may be resolved by name
        // below). channelPartnerName is resolved inside the try (needs a GET).
        let channelPartnerId: string | undefined;
        if (args.channelPartnerId) {
          const cp = validateUuid(args.channelPartnerId);
          if (!cp) {
            throw new Error(
              "Invalid channelPartnerId (must be a UUID); or omit it and pass channelPartnerName",
            );
          }
          channelPartnerId = cp;
        }
        // Live Opportunity metadata: used to validate stage and the two
        // segmentation SELECTs against their enums and to learn the closeDate
        // field type. Best-effort — if metadata is unreadable, skip validation
        // rather than block a write.
        let oppMeta: {
          stages: string[];
          closeDateType: string | null;
          lineOfBusiness: string[];
          sourceChannel: string[];
          qualStatus: string[];
          offering: string[];
          fields: Map<string, { type: string; options: string[] }>;
        } = {
          stages: [],
          closeDateType: null,
          lineOfBusiness: [],
          sourceChannel: [],
          qualStatus: [],
          offering: [],
          fields: new Map(),
        };
        // Fail-closed gate for customFields (F2): typed args keep the
        // best-effort "skip validation when metadata unreadable" posture, but
        // customFields is rejected entirely unless metadata was read.
        let oppMetaReadable = false;
        try {
          oppMeta = await fetchOpportunityMeta(cfg);
          oppMetaReadable = true;
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

          // qualStatus SELECT (technical-qualification): same best-effort enum
          // validation posture as the segmentation SELECTs — empty => unset
          // (leave unchanged), invalid token fails fast, skipped when the
          // field's options are unreadable. sanitizeText is applied first so
          // that even in the metadata-unreadable skip-window a control-char /
          // oversized token can never reach the REST body or the snapshot (a
          // valid UPPER_SNAKE token is unaffected). (Pre-existing sibling
          // SELECTs lineOfBusiness/sourceChannel share the same gap — a
          // follow-up outside this work item's scope.)
          const qualStatus = sanitizeText(args.qualStatus ?? "", 120) ||
            undefined;
          if (
            qualStatus !== undefined && oppMeta.qualStatus.length &&
            !oppMeta.qualStatus.includes(qualStatus)
          ) {
            throw new Error(
              `Invalid qualStatus '${qualStatus}'. Valid options: ${
                oppMeta.qualStatus.join(", ")
              }`,
            );
          }

          // offering SELECT (segmentation, TWENTY-OPP-OFFERING): same posture as
          // the other segmentation SELECTs — sanitizeText floor, best-effort
          // enum validation, empty => unset (leave unchanged, never nulled),
          // skipped when options unreadable.
          const offering = sanitizeText(args.offering ?? "", 120) || undefined;
          if (
            offering !== undefined && oppMeta.offering.length &&
            !oppMeta.offering.includes(offering)
          ) {
            throw new Error(
              `Invalid offering '${offering}'. Valid options: ${
                oppMeta.offering.join(", ")
              }`,
            );
          }

          // asn TEXT (F5): sanitize + length-cap, then a positive format guard
          // ^AS\d{1,10}$ (case-insensitive input, uppercased on store). The
          // digit bound is both correct (a 32-bit ASN maxes at 4294967295 = 10
          // digits) and closes a truncate-before-guard false match — an
          // all-digit value longer than the cap would otherwise be truncated
          // and then pass ^AS\d+$; the {1,10} bound rejects it. A non-empty
          // value that does not match is rejected pre-write; empty => unset
          // (omit, never nulled). asn is a write value, never a filter operand.
          let asn: string | undefined;
          {
            const rawAsn = sanitizeText(args.asn ?? "", 64);
            if (rawAsn) {
              const up = rawAsn.toUpperCase();
              if (!/^AS\d{1,10}$/.test(up)) {
                throw new Error(
                  `Invalid asn '${rawAsn}': expected AS followed by 1-10 digits (e.g. AS64496), or empty to leave unchanged`,
                );
              }
              asn = up;
            }
          }

          // customFields (generic scalar escape hatch) — FAIL-CLOSED (F2):
          // reject the whole map if opportunity metadata is unreadable. Each
          // key: reserved-key reject (F1/F4), camelCase shape, must exist and be
          // a scalar TYPE, SELECT validated against the live enum, strings
          // sanitized, empty-string => omit (F8), null forbidden (F8).
          const validatedCustomFields: Record<
            string,
            string | number | boolean
          > = {};
          const rawCustomFields = args.customFields ?? {};
          if (Object.keys(rawCustomFields).length) {
            if (!oppMetaReadable) {
              throw new Error(
                "customFields supplied but opportunity field metadata is unreadable — refusing to write (fail-closed)",
              );
            }
            for (const [k, v] of Object.entries(rawCustomFields)) {
              const key = String(k).trim();
              if (!FIELD_NAME_RE.test(key)) {
                throw new Error(
                  `Invalid customFields key '${
                    sanitizeText(key, 80)
                  }': must be a camelCase identifier (letter-led, alphanumeric)`,
                );
              }
              // `key` has passed FIELD_NAME_RE (ASCII, letter-led) so it carries
              // no control chars/HTML/path separators, but it is length-unbounded
              // — cap it in every surfaced message (matching the "Invalid key"
              // branch above) so a huge key can't bloat a durable error report.
              const safeKey = sanitizeText(key, 80);
              if (OPP_CUSTOMFIELDS_RESERVED.has(key)) {
                throw new Error(
                  `customFields key '${safeKey}' is reserved — set it via its typed argument, not customFields`,
                );
              }
              if (v === null) {
                throw new Error(
                  `customFields key '${safeKey}' is null; null is not permitted (omit the key to leave the field unchanged)`,
                );
              }
              const fMeta = oppMeta.fields.get(key);
              if (!fMeta) {
                throw new Error(
                  `Unknown customFields key '${safeKey}' on opportunity (fail-closed; refusing to write an unrecognized field)`,
                );
              }
              if (!UPSERT_SCALAR_TYPES.has(fMeta.type)) {
                throw new Error(
                  `customFields key '${safeKey}' has non-scalar type '${fMeta.type}' (allowed: ${
                    [...UPSERT_SCALAR_TYPES].join(", ")
                  }); composite fields are not supported`,
                );
              }
              // A non-finite number (Infinity/-Infinity/NaN) passes z.number()
              // and the null check, but JSON.stringify serializes it to `null` —
              // which would silently CLEAR the field, the exact outcome the
              // null-forbidden invariant exists to prevent. Reject it here.
              if (typeof v === "number" && !Number.isFinite(v)) {
                throw new Error(
                  `customFields key '${safeKey}' is a non-finite number (Infinity/NaN); only finite numeric values are permitted`,
                );
              }
              let out: string | number | boolean = v;
              if (typeof v === "string") {
                const s = sanitizeText(v, UPSERT_FIELD_TEXT_CAP);
                if (!s) continue; // empty-string => omit (leave unchanged)
                out = s;
              }
              if (fMeta.type === "SELECT") {
                const token = String(out);
                if (fMeta.options.length && !fMeta.options.includes(token)) {
                  throw new Error(
                    `Invalid value '${token}' for SELECT customFields key '${safeKey}'. Valid options: ${
                      fMeta.options.join(", ")
                    }`,
                  );
                }
              }
              validatedCustomFields[key] = out;
            }
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

          // channelPartner (TWENTY-OPP-CHANNEL): link the marketplace partner.
          // An explicit channelPartnerId (validated UUID, resolved above) wins;
          // otherwise resolve channelPartnerName by exact (filter-safe) name —
          // LINK-ONLY, never create. A name with no match is recorded as a skip
          // and leaves the link unchanged (mirrors the pointOfContact posture).
          let channelPartnerSkipped: string | undefined;
          if (!channelPartnerId) {
            const cpName = sanitizeText(args.channelPartnerName, 120);
            if (cpName) {
              if (isFilterSafe(cpName)) {
                const existingCp = await findOneChannelPartnerByName(
                  cfg,
                  cpName,
                );
                if (existingCp) {
                  channelPartnerId = String(existingCp.id ?? "");
                } else {
                  channelPartnerSkipped =
                    "no existing channelPartner for the given name (link-only; not created)";
                }
              } else {
                channelPartnerSkipped =
                  "channelPartner name has filter-unsafe characters; skipped";
              }
            }
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
            ...(channelPartnerId ? { channelPartnerId } : {}),
            ...(args.isEmergency !== undefined
              ? { isEmergency: args.isEmergency }
              : {}),
            ...(lineOfBusiness !== undefined ? { lineOfBusiness } : {}),
            ...(sourceChannel !== undefined ? { sourceChannel } : {}),
            ...(asn !== undefined ? { asn } : {}),
            ...(qualStatus !== undefined ? { qualStatus } : {}),
            ...(offering !== undefined ? { offering } : {}),
            ...(Object.keys(validatedCustomFields).length
              ? { customFields: validatedCustomFields }
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
              ...(lineOfBusiness !== undefined ? { lineOfBusiness } : {}),
              ...(sourceChannel !== undefined ? { sourceChannel } : {}),
              ...(asn !== undefined ? { asn } : {}),
              ...(qualStatus !== undefined ? { qualStatus } : {}),
              ...(offering !== undefined ? { offering } : {}),
              ...(Object.keys(validatedCustomFields).length
                ? { customFields: validatedCustomFields }
                : {}),
              ...(args.amount !== undefined ? { amount: args.amount } : {}),
              ...(amount ? { currencyCode: amount.currencyCode } : {}),
              ...(closeDate ? { closeDate } : {}),
              ...(companyId ? { companyId } : {}),
              companyLinked: Boolean(companyId),
              ...(companyNote ? { companyNote } : {}),
              ...(pointOfContactId ? { pointOfContactId } : {}),
              ...(pocSkipped ? { pocSkipped } : {}),
              ...(channelPartnerId ? { channelPartnerId } : {}),
              ...(channelPartnerSkipped ? { channelPartnerSkipped } : {}),
              noteEnsured,
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          // Pass the vaulted bearer token for exact scrubbing (mirrors
          // upsertRecord): this commit grows the set of caller-controlled values
          // (asn/qualStatus/customFields) that could be echoed in a Twenty 4xx
          // and land in a durable method-summary report; the token must never.
          throw new Error(redactError(e, 300, cfg.apiToken));
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

        // PU-5: the ENTIRE flow is wrapped so an ambiguous-email throw or any 4xx
        // that echoes a submitted value is redacted before it reaches logs.
        try {
          // Delegate to the shared single-person primitive (find-or-create with
          // field-diff/noop detection): an unchanged re-run now returns noop and
          // issues NO PATCH.
          const result = await upsertPersonCore(
            cfg,
            {
              primaryEmail: args.email,
              firstName: args.firstName,
              lastName: args.lastName,
              name: args.name,
              phone: args.phone,
              jobTitle: args.jobTitle,
              city: args.city,
              companyDomain: args.companyDomain,
              companyName: args.companyName,
            },
            args.dryRun,
          );
          const personId = result.personId ?? "";

          context.logger.info(
            "upsertPerson: {action} (person {person}){dry}",
            {
              action: result.action,
              person: personId || "-",
              dry: args.dryRun ? " [dryRun]" : "",
            },
          );

          const snap: Record<string, unknown> = {
            baseUrl: cfg.baseUrl,
            action: result.action,
            dryRun: args.dryRun,
            ...(result.personId ? { personId: result.personId } : {}),
            fieldsSet: result.fieldsSet,
            ...(result.companyId ? { companyId: result.companyId } : {}),
            companyLinked: result.companyLinked,
            ...(result.companyNote ? { companyNote: result.companyNote } : {}),
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
    upsertCompany: {
      description:
        "Idempotent, confirm-gated, dryRun-DEFAULT Company writer (TWENTY-COMPANY-UPSERT). Match precedence id -> domain -> name. DOMAIN dedup is client-side after canonicalizing BOTH sides (normalizeDomainHost PLUS a leading-www strip), so acme.com matches a stored https://www.acme.com; CREATE happens ONLY when a domain is supplied AND the broad host fetch returns ZERO candidates — a near-candidate yields planned-conflict (never a duplicate)," +
        " an unmatched explicit id aborts, and a name-only miss aborts (no stable key). NAME fallback is best-effort and canonicalized; a real API error aborts (never falls through to create). A domain-hit whose stored name materially differs is a conflict (no silent rename). Updates are non-destructive (provided fields only, composites merged, never nulled); an unchanged re-run is a noop. accountOwnerEmail resolves to an opaque" +
        " workspaceMemberId (the email never enters the snapshot/logs/errors); an unresolved owner aborts. customFields are fail-closed (reserved/unknown/non-scalar/bad-SELECT rejected at plan time via metadata). confirm:true required for a real run; dryRun defaults true and plans without writing. Snapshots a `companyUpsert` resource.",
      arguments: z.object({
        matchBy: z
          .enum(["id", "domain", "name", "auto"])
          .default("auto")
          .describe(
            "Match strategy. auto = id -> domain -> name precedence; or pin one.",
          ),
        id: z
          .string()
          .optional()
          .describe(
            "Explicit company UUID. When set (or matchBy=id) an unmatched id ABORTS (never creates).",
          ),
        name: z.string().describe("Company name (required)"),
        domain: z
          .string()
          .optional()
          .describe(
            "Company domain — the preferred dedup/create key, canonicalized to a bare registrable host (www stripped). Required to CREATE.",
          ),
        legalName: z.string().optional().describe("Legal entity name"),
        addressCity: z.string().optional(),
        addressState: z.string().optional(),
        addressCountry: z.string().optional(),
        addressStreet1: z.string().optional(),
        addressStreet2: z.string().optional(),
        addressPostcode: z.string().optional(),
        employees: z
          .number()
          .int()
          .nonnegative()
          .optional()
          .describe("Headcount (non-negative integer)"),
        linkedinUrl: z.string().optional().describe("LinkedIn profile URL"),
        xUrl: z.string().optional().describe("X / Twitter profile URL"),
        idealCustomerProfile: z
          .boolean()
          .optional()
          .describe("ICP flag"),
        accountOwnerEmail: z
          .string()
          .optional()
          .describe(
            "Resolve to an existing workspace member (by userEmail) and set accountOwnerId. The email is never stored/logged; an unresolved owner aborts.",
          ),
        customFields: z
          .record(z.string(), z.union([z.string(), z.number(), z.boolean()]))
          .optional()
          .describe(
            "Generic scalar escape hatch for Company custom fields without a typed argument. Fail-closed: keys must exist + be scalar; reserved keys (every typed-arg field + composite owners + system fields) and composite/unknown types are rejected pre-write; SELECT values are live-enum validated; empty string => unset; null forbidden.",
          ),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true for a real run (writes to Twenty)"),
        dryRun: z
          .boolean()
          .default(true)
          .describe("Resolve + plan, but write nothing (defaults TRUE)"),
      }),
      execute: async (
        args: CompanyUpsertInput & { confirm: boolean; dryRun: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        if (!args.dryRun && !args.confirm) {
          throw new Error(
            "Refusing to write without confirm:true (use dryRun:true to plan)",
          );
        }
        try {
          const loadMeta = makeCompanyMetaLoader(cfg);
          const loadMembers = makeMembersLoader(cfg);
          const result = await upsertCompanyCore(
            cfg,
            args,
            args.dryRun,
            loadMeta,
            loadMembers,
          );
          context.logger.info(
            "upsertCompany: {action} (company {company}){dry}",
            {
              action: result.action,
              company: result.id || "-",
              dry: args.dryRun ? " [dryRun]" : "",
            },
          );
          const instanceName = result.id
            ? `company-upsert-${result.id}`
            : `company-upsert-${await listInstanceHash({
              name: result.name,
              domain: result.domain ?? null,
            })}`;
          const handle = await context.writeResource(
            "companyUpsert",
            instanceName,
            {
              baseUrl: cfg.baseUrl,
              dryRun: args.dryRun,
              ...result,
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          // Scrub the token AND the account-owner email so neither can leak into
          // a durable method-summary report even if Twenty echoes it (SEC-5/SEC-8).
          throw new Error(
            redactError(e, 300, cfg.apiToken, [args.accountOwnerEmail]),
          );
        }
      },
    },
    reconcileCompanies: {
      description:
        "Declarative Company reconcile fan-out (TWENTY-COMPANY-UPSERT Section 2a, repo rule 6): take a desired-state LIST of company entries (authored as tracked YAML, wired in by the caller — the extension has no filesystem primitive) and upsert each in ONE execution. id-first match per entry; PER-ENTRY ISOLATION (one bad row is recorded redacted and never aborts the batch); a full per-entry plan under the default dryRun; confirm gates the" +
        " whole batch. NO reconcile-delete (YAML-absent companies are never archived). A MANDATORY per-run entry cap (default 100) refuses an over-cap batch unless maxEntries is explicitly raised (never uncapped). A clean re-run converges to every entry action==noop. Snapshots a scoped `companyReconcile` audit.",
      arguments: z.object({
        entries: z
          .array(
            z.object({
              matchBy: z.enum(["id", "domain", "name", "auto"]).optional(),
              id: z.string().optional(),
              name: z.string(),
              domain: z.string().optional(),
              legalName: z.string().optional(),
              addressCity: z.string().optional(),
              addressState: z.string().optional(),
              addressCountry: z.string().optional(),
              addressStreet1: z.string().optional(),
              addressStreet2: z.string().optional(),
              addressPostcode: z.string().optional(),
              employees: z.number().int().nonnegative().optional(),
              linkedinUrl: z.string().optional(),
              xUrl: z.string().optional(),
              idealCustomerProfile: z.boolean().optional(),
              accountOwnerEmail: z.string().optional(),
              customFields: z
                .record(
                  z.string(),
                  z.union([z.string(), z.number(), z.boolean()]),
                )
                .optional(),
            }),
          )
          .default([])
          .describe("Desired-state company list (from the tracked YAML)"),
        source: z
          .string()
          .default("crm/companies.yaml")
          .describe(
            "Provenance label recorded in the audit (not read as a file)",
          ),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to actually write the batch"),
        dryRun: z
          .boolean()
          .default(true)
          .describe("Plan every entry, write nothing (defaults TRUE)"),
        maxEntries: z
          .number()
          .int()
          .positive()
          .max(1000)
          .default(100)
          .describe(
            "Per-run entry cap. A batch larger than this is refused — raise it explicitly to override (never uncapped by default).",
          ),
      }),
      execute: async (
        args: {
          entries: CompanyUpsertInput[];
          source: string;
          confirm: boolean;
          dryRun: boolean;
          maxEntries: number;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        if (!args.dryRun && !args.confirm) {
          throw new Error(
            "Refusing to reconcile without confirm:true (use dryRun:true to plan)",
          );
        }
        try {
          const entries = args.entries ?? [];
          if (entries.length > args.maxEntries) {
            throw new Error(
              `Desired-state list has ${entries.length} entries, over the cap of ${args.maxEntries}; raise maxEntries explicitly to process more (refusing an uncapped batch)`,
            );
          }
          const loadMeta = makeCompanyMetaLoader(cfg);
          const loadMembers = makeMembersLoader(cfg);
          const out: Array<Record<string, unknown>> = [];
          const counts: Record<string, number> = {};
          // An empty batch is trivially converged; any non-noop entry flips it false.
          let converged = true;
          for (let i = 0; i < entries.length; i++) {
            const entry = entries[i];
            try {
              const result = await upsertCompanyCore(
                cfg,
                entry,
                args.dryRun,
                loadMeta,
                loadMembers,
              );
              counts[result.action] = (counts[result.action] ?? 0) + 1;
              if (result.action !== "noop") converged = false;
              out.push({
                index: i,
                name: result.name,
                ...(result.domain ? { domain: result.domain } : {}),
                ok: true,
                action: result.action,
                found: result.found,
                ...(result.id ? { id: result.id } : {}),
                ...(result.matchedVia ? { matchedVia: result.matchedVia } : {}),
                fieldsSet: result.fieldsSet,
                ...(result.candidates ? { candidates: result.candidates } : {}),
              });
            } catch (e) {
              // PER-ENTRY ISOLATION: one bad row never aborts the batch.
              counts.error = (counts.error ?? 0) + 1;
              converged = false;
              out.push({
                index: i,
                ...(entry?.name ? { name: sanitizeText(entry.name, 200) } : {}),
                ...(entry?.domain
                  ? { domain: canonicalCompanyHost(entry.domain) ?? undefined }
                  : {}),
                ok: false,
                error: redactError(e, 300, cfg.apiToken, [
                  entry?.accountOwnerEmail,
                ]),
              });
            }
          }
          context.logger.info(
            "reconcileCompanies: {processed}/{total} processed, converged={converged}{dry}",
            {
              processed: out.length,
              total: entries.length,
              converged,
              dry: args.dryRun ? " [dryRun]" : "",
            },
          );
          const handle = await context.writeResource(
            "companyReconcile",
            `company-reconcile-${await listInstanceHash({
              source: args.source,
              n: entries.length,
            })}`,
            {
              baseUrl: cfg.baseUrl,
              source: args.source,
              dryRun: args.dryRun,
              total: entries.length,
              processed: out.length,
              cap: args.maxEntries,
              counts,
              converged,
              entries: out,
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          // SEC-8 parity with upsertCompany/exportCompanies: scrub the token so it
          // can never leak into a durable method-summary report on a hard error.
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    reconcilePeople: {
      description:
        "Declarative Person reconcile fan-out (TWENTY-PERSON-UPSERT, repo rule 6): take a desired-state LIST of person entries (authored as tracked YAML, wired in by the caller - the extension has no filesystem primitive) and upsert each in ONE execution. primaryEmail-first find-or-create per entry; PER-ENTRY ISOLATION (one bad row is recorded as its INDEX + a REDACTED error ONLY - never the person name or primaryEmail - and never aborts the batch); a full per-entry plan under the default dryRun; confirm gates the" +
        " whole batch. NEVER stamps a leadId (curated contacts stay out of the lead namespace). NO reconcile-delete (YAML-absent people are never archived). A MANDATORY per-run entry cap (default 100) refuses an over-cap batch unless maxEntries is explicitly raised (never uncapped). A clean re-run converges to every entry action==noop. Snapshots a scoped `peopleReconcile` audit (no raw PII - index/action/fieldsSet + redacted per-entry errors only).",
      arguments: z.object({
        entries: z
          .array(
            z.object({
              primaryEmail: z.string(),
              name: z
                .object({
                  firstName: z.string().optional(),
                  lastName: z.string().optional(),
                })
                .optional(),
              phone: z.string().optional(),
              jobTitle: z.string().optional(),
              city: z.string().optional(),
              companyDomain: z.string().optional(),
              companyName: z.string().optional(),
            }),
          )
          .default([])
          .describe("Desired-state person list (from the tracked YAML)"),
        source: z
          .string()
          .default("crm/people.yaml")
          .describe(
            "Provenance label recorded in the audit (not read as a file)",
          ),
        confirm: z
          .boolean()
          .default(false)
          .describe("Must be true to actually write the batch"),
        dryRun: z
          .boolean()
          .default(true)
          .describe("Plan every entry, write nothing (defaults TRUE)"),
        maxEntries: z
          .number()
          .int()
          .positive()
          .max(1000)
          .default(100)
          .describe(
            "Per-run entry cap. A batch larger than this is refused - raise it explicitly to override (never uncapped by default).",
          ),
      }),
      execute: async (
        args: {
          entries: Array<{
            primaryEmail: string;
            name?: { firstName?: string; lastName?: string };
            phone?: string;
            jobTitle?: string;
            city?: string;
            companyDomain?: string;
            companyName?: string;
          }>;
          source: string;
          confirm: boolean;
          dryRun: boolean;
          maxEntries: number;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        if (!args.dryRun && !args.confirm) {
          throw new Error(
            "Refusing to reconcile without confirm:true (use dryRun:true to plan)",
          );
        }
        try {
          const entries = args.entries ?? [];
          if (entries.length > args.maxEntries) {
            throw new Error(
              `Desired-state list has ${entries.length} entries, over the cap of ${args.maxEntries}; raise maxEntries explicitly to process more (refusing an uncapped batch)`,
            );
          }
          const out: Array<Record<string, unknown>> = [];
          const counts: Record<string, number> = {};
          // An empty batch is trivially converged; any non-noop entry flips it false.
          let converged = true;
          for (let i = 0; i < entries.length; i++) {
            const entry = entries[i];
            try {
              const result = await upsertPersonCore(
                cfg,
                {
                  primaryEmail: entry.primaryEmail,
                  firstName: entry.name?.firstName,
                  lastName: entry.name?.lastName,
                  phone: entry.phone,
                  jobTitle: entry.jobTitle,
                  city: entry.city,
                  companyDomain: entry.companyDomain,
                  companyName: entry.companyName,
                },
                args.dryRun,
              );
              counts[result.action] = (counts[result.action] ?? 0) + 1;
              if (result.action !== "noop") converged = false;
              out.push({
                index: i,
                ok: true,
                action: result.action,
                found: result.found,
                ...(result.personId ? { personId: result.personId } : {}),
                fieldsSet: result.fieldsSet,
                ...(result.companyId ? { companyId: result.companyId } : {}),
                companyLinked: result.companyLinked,
              });
            } catch (e) {
              // PER-ENTRY ISOLATION: one bad row never aborts the batch. The
              // audit records the INDEX + a REDACTED error ONLY - deliberately
              // NOT the person name or primaryEmail (unlike reconcileCompanies,
              // which echoes company name/domain: a Person entry carries raw
              // PII, so it is dropped). The entry's primaryEmail AND name tokens
              // (firstName/lastName) are passed as extra secrets so even a value
              // echoed back in a Twenty 4xx response body is scrubbed before it
              // reaches the durable snapshot.
              counts.error = (counts.error ?? 0) + 1;
              converged = false;
              out.push({
                index: i,
                ok: false,
                error: redactError(e, 300, cfg.apiToken, [
                  entry?.primaryEmail,
                  entry?.name?.firstName,
                  entry?.name?.lastName,
                ]),
              });
            }
          }
          context.logger.info(
            "reconcilePeople: {processed}/{total} processed, converged={converged}{dry}",
            {
              processed: out.length,
              total: entries.length,
              converged,
              dry: args.dryRun ? " [dryRun]" : "",
            },
          );
          const handle = await context.writeResource(
            "peopleReconcile",
            `people-reconcile-${await listInstanceHash({
              source: args.source,
              n: entries.length,
            })}`,
            {
              baseUrl: cfg.baseUrl,
              source: args.source,
              dryRun: args.dryRun,
              total: entries.length,
              processed: out.length,
              cap: args.maxEntries,
              counts,
              converged,
              entries: out,
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          // SEC-8 parity with reconcileCompanies: scrub the token so it can never
          // leak into a durable method-summary report on a hard error.
          throw new Error(redactError(e, 300, cfg.apiToken));
        }
      },
    },
    exportCompanies: {
      description:
        "Back-sync READ (TWENTY-COMPANY-UPSERT Section 2a): page through ALL companies and emit a scoped `companyList` DATA resource carrying {id, name, domain, legalName} WITH the Twenty id per entry — the seed for authoring the tracked crm/companies.yaml so reconcileCompanies can round-trip survivors by id. Account-owner emails and every person-linked field are SCRUBBED (id/name/domain/legalName only). The resource is short-TTL (3d) + tightly" +
        " GC'd, not infinite-cached. Read-only; writes nothing to Twenty and nothing to the repo (YAML authoring is a separate reviewed operator step).",
      arguments: z.object({
        maxCompanies: z
          .number()
          .int()
          .positive()
          .max(5000)
          .default(1000)
          .describe("Safety cap on how many companies to export this run"),
      }),
      execute: async (
        args: { maxCompanies: number },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        try {
          const items: Array<Record<string, unknown>> = [];
          const seen = new Set<string>();
          let cursor: string | undefined;
          let truncated = false;
          // Loop the shared bounded paginator until Twenty runs out of pages or
          // we hit the export cap (whichever first).
          for (let call = 0; call < 200; call++) {
            const page = await listFiltered(
              cfg,
              "companies",
              [],
              MAX_LIST_CAP,
              LIST_ORDER,
              cursor,
            );
            for (const rec of page.items) {
              const id = String(rec.id ?? "");
              if (!id || seen.has(id)) continue;
              if (items.length >= args.maxCompanies) {
                truncated = true;
                break;
              }
              seen.add(id);
              const item: Record<string, unknown> = {
                id,
                name: String(rec.name ?? ""),
              };
              // SCRUB: only id/name/domain/legalName are emitted — no accountOwner
              // email, no people/contacts, no custom PII-bearing fields.
              const host = canonicalCompanyHost(
                (rec.domainName as { primaryLinkUrl?: unknown } | undefined)
                  ?.primaryLinkUrl,
              );
              if (host) item.domain = host;
              if (rec.legalName != null && rec.legalName !== "") {
                item.legalName = String(rec.legalName);
              }
              items.push(item);
            }
            if (truncated || !page.hasMore || page.nextCursor === undefined) {
              break;
            }
            cursor = page.nextCursor;
          }
          const handle = await context.writeResource(
            "companyList",
            "companies-export",
            {
              baseUrl: cfg.baseUrl,
              count: items.length,
              truncated,
              hasMore: false,
              incomplete: false,
              stopReason: truncated ? "cap-reached" : "complete",
              filter: {},
              items,
              retrievedAt: new Date().toISOString(),
            },
          );
          return { dataHandles: [handle] };
        } catch (e) {
          throw new Error(redactError(e, 300, cfg.apiToken));
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
        "Fan-out (repo rule 6): idempotently provision the three Opportunity segmentation SELECT fields — Line of Business (Consulting / Hosting / Games), Source Channel (Direct / Referral / Consulting hand-off), and Offering (Managed / Substrate / Project / Retainer / Local IT / Peering) — through the shared append-only ensureField path in ONE execution (single GET, one lock). Analytics only, not a pipeline gate. Re-run is a clean no-op when the live options already match the spec; a field that exists with extra options keeps them, and by default (reconcile) an option whose label/color drifted from the spec is corrected in place (pass reconcile:false for strict append-only). confirm:true for a real run; dryRun:true previews. Snapshots one `fieldEnsured` resource per field.",
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
        "ensureNoteFields",
        "push_leads",
        "upsertOpportunity",
        "ensureStageOption",
        "upsertPerson",
        "ensureField",
        "ensureOpportunitySegmentation",
        "ensureObject",
        "ensureRelation",
        "ensureOpportunityViews",
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
