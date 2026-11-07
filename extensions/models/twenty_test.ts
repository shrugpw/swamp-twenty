/**
 * Unit tests for @shrug/twenty. Everything security-critical in the lead sink is
 * a pure function — email/domain validation (the anti filter-injection gate),
 * text sanitization (anti record-poisoning), the consumer-domain blocklist, the
 * name split, FIFO batch selection, and the whole per-lead plan — so it is all
 * exercised here without a live Twenty. The one impure guard tested is
 * push_leads' confirm-gate, which throws before any I/O.
 */
import {
  assert,
  assertAlmostEquals,
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  __clearNoteFieldCache,
  acquireOppRowsGraphQL,
  aggregateOppViews,
  amountFromMicros,
  buildFilterPath,
  buildLeadNoteBody,
  buildOpportunityBody,
  // TWENTY-VIEW-MGMT
  buildViewFilterValue,
  // TWENTY-VIEW-UPSERT
  buildViewFilterValueString,
  // TWENTY-COMPANY-UPSERT
  canonicalCompanyHost,
  canonicalCompanyName,
  canonicalJson,
  // TWENTY-NOTE-RECONCILE
  canonicalNote,
  // LEAD-SPAM-FILTER (shadow)
  classifyLead,
  CompanyReconcileSchema,
  CompanyUpsertSchema,
  computeDedupKey,
  computeMetadataNameFromLabel,
  DEFAULT_EMAIL_DOMAIN_BLOCKLIST,
  // TWENTY-EMAIL
  deriveThreadState,
  domainOfEmail,
  escapeMarkdown,
  // TWENTY-EMAIL send
  fetchConnectedAccounts,
  fetchObjectsMeta,
  handleDomain,
  hashNote,
  isBlockedDomain,
  isFilterSafe,
  isReadOnlyGraphQL,
  leadFromKvEntry,
  leadFromKvRecord,
  listFiltered,
  listInstanceHash,
  localpartLooksMachine,
  mapCompanyView,
  mapNoteView,
  mapOppView,
  mapPersonView,
  messageTs,
  mintUserAccessToken,
  model,
  nameLooksGibberish,
  normalizeCloseDate,
  normalizeDomainHost,
  normalizeFilterValueTokens,
  normalizePhone,
  normalizeRequestedOption,
  OPP_VIEW_TARGETS,
  OppAggregatesSchema,
  OPPORTUNITY_SEGMENTATION_FIELDS,
  OpportunityRefSchema,
  OpportunityUpsertSchema,
  OppViewSchema,
  parseMicros,
  phoneLooksBogus,
  pickLastMessage,
  planLead,
  planOpportunityView,
  planSelectOptions,
  planUpsertOpportunityView,
  redactError,
  resolveActiveWorkflowVersionId,
  resolveBrandForSend,
  sanitizeText,
  selectBatch,
  sendDedupMarkerId,
  sha256Hex,
  SPAM_SCORE_THRESHOLD,
  splitName,
  titleCaseToken,
  toCurrency,
  twentyGraphQL,
  validateBrandMap,
  validateDomain,
  validateEmail,
  validateLeadId,
  validateUuid,
  ViewEnsuredSchema,
  ViewListSchema,
} from "./twenty.ts";

// --- validateEmail ----------------------------------------------------------

Deno.test("validateEmail lowercases and trims", () => {
  assertEquals(validateEmail("  Alice@Example.COM "), "alice@example.com");
});

Deno.test("validateEmail rejects garbage / missing", () => {
  for (const bad of ["", "  ", "not-an-email", "a@b", "a@@b.com", null, 42]) {
    assertEquals(validateEmail(bad), null);
  }
});

Deno.test("validateEmail rejects filter-breaking characters", () => {
  // Chars that could break out of a Twenty `filter=field[eq]:value` clause.
  for (const bad of ['a"@b.com', "a'@b.com", "a<@b.com", "a,b@c.com"]) {
    assertEquals(validateEmail(bad), null);
  }
});

Deno.test("validateEmail rejects over-long addresses", () => {
  const long = "a".repeat(250) + "@example.com";
  assertEquals(validateEmail(long), null);
});

// --- validateDomain / domainOfEmail -----------------------------------------

Deno.test("validateDomain accepts real domains, rejects junk", () => {
  assertEquals(validateDomain("Example.COM"), "example.com");
  assertEquals(validateDomain("sub.example.co.uk"), "sub.example.co.uk");
  assertEquals(validateDomain("nodot"), null);
  assertEquals(validateDomain("bad_underscore.com"), null);
  assertEquals(validateDomain(""), null);
});

Deno.test("domainOfEmail extracts and validates the domain", () => {
  assertEquals(domainOfEmail("alice@example.com"), "example.com");
  assertEquals(domainOfEmail("alice@localhost"), null);
});

// --- isBlockedDomain --------------------------------------------------------

Deno.test("isBlockedDomain flags consumer providers", () => {
  assertEquals(
    isBlockedDomain("gmail.com", DEFAULT_EMAIL_DOMAIN_BLOCKLIST),
    true,
  );
  assertEquals(
    isBlockedDomain("GMAIL.COM", DEFAULT_EMAIL_DOMAIN_BLOCKLIST),
    true,
  );
  assertEquals(
    isBlockedDomain("example.com", DEFAULT_EMAIL_DOMAIN_BLOCKLIST),
    false,
  );
});

// --- normalizePhone ---------------------------------------------------------

Deno.test("normalizePhone normalizes toward E.164 with a NANP default", () => {
  assertEquals(normalizePhone("+1 (781) 555-0100"), "+17815550100");
  // Bare 10-digit US number gets the +1 country code (Twenty rejects it without).
  assertEquals(normalizePhone("781.555.0100"), "+17815550100");
  // 1XXXXXXXXXX gets a leading +.
  assertEquals(normalizePhone("1 617 555 0143"), "+16175550143");
  assertEquals(normalizePhone("++1++2"), "+12");
  assertEquals(normalizePhone(""), "");
});

// --- sanitizeText -----------------------------------------------------------

Deno.test("sanitizeText strips HTML and control chars, collapses whitespace", () => {
  assertEquals(
    sanitizeText("  <script>alert(1)</script>Hello\t\nworld  ", 100),
    "alert(1) Hello world",
  );
});

Deno.test("sanitizeText caps length", () => {
  assertEquals(sanitizeText("x".repeat(50), 10).length, 10);
});

Deno.test("sanitizeText neutralizes an injected tag", () => {
  // The angle-bracketed markup is removed; the text between survives.
  assertEquals(sanitizeText("<img src=x onerror=y>boom", 100), "boom");
});

// --- escapeMarkdown (anti note-injection) -----------------------------------

Deno.test("escapeMarkdown neutralizes image/link injection", () => {
  // A tracking-pixel image and a phishing link both become inert literal text.
  assertEquals(
    escapeMarkdown("![](http://attacker/beacon.png)"),
    "\\!\\[\\]\\(http://attacker/beacon.png\\)",
  );
  assertEquals(
    escapeMarkdown("[click](http://phish)"),
    "\\[click\\]\\(http://phish\\)",
  );
});

Deno.test("escapeMarkdown leaves plain text alone", () => {
  assertEquals(
    escapeMarkdown("just a normal message"),
    "just a normal message",
  );
});

// --- redactError (anti PII-in-audit) ----------------------------------------

Deno.test("redactError scrubs an echoed email", () => {
  assertEquals(
    redactError("Twenty POST /rest/people failed: email exists foo@bar.com"),
    "Twenty POST /rest/people failed: email exists [email]",
  );
});

Deno.test("redactError scrubs a long digit run (phone)", () => {
  const r = redactError("invalid phone +1 (781) 555-0100 rejected");
  assert(!r.includes("555"), r);
  assert(r.includes("[number]"), r);
});

Deno.test("redactError caps length", () => {
  assertEquals(redactError("x".repeat(500), 50).length, 50);
});

// --- splitName --------------------------------------------------------------

Deno.test("splitName splits on the last space", () => {
  assertEquals(splitName("Ada Lovelace"), {
    firstName: "Ada",
    lastName: "Lovelace",
  });
  assertEquals(splitName("Mary Anne Evans"), {
    firstName: "Mary Anne",
    lastName: "Evans",
  });
});

Deno.test("splitName puts a single token in lastName (per spec)", () => {
  assertEquals(splitName("Madonna"), { firstName: "", lastName: "Madonna" });
});

Deno.test("splitName handles empty", () => {
  assertEquals(splitName(""), { firstName: "", lastName: "" });
});

// --- buildFilterPath (anti-injection) ---------------------------------------

Deno.test("buildFilterPath URL-encodes the value", () => {
  assertEquals(
    buildFilterPath("/rest/people", "emails.primaryEmail", "a b@c.com"),
    "/rest/people?filter=emails.primaryEmail[eq]:a%20b%40c.com",
  );
});

// --- validateLeadId ---------------------------------------------------------

Deno.test("validateLeadId accepts opaque ids, rejects unsafe ones", () => {
  assertEquals(validateLeadId("LEAD-abc_123.4:5"), "LEAD-abc_123.4:5");
  assertEquals(validateLeadId("has space"), null);
  assertEquals(validateLeadId("bad/slash"), null);
  assertEquals(validateLeadId(""), null);
  assertEquals(validateLeadId(null), null);
});

// --- planLead ---------------------------------------------------------------

const baseLead = {
  id: "LEAD-1",
  name: "Ada Lovelace",
  email: "ada@example.com",
  phone: "781-555-0100",
  message: "Need help with our network",
  contact_type: "business" as const,
  company: "Example Corp",
  received_at: "2026-09-01T00:00:00.000Z",
  status: "new",
  geo: "Springfield, IL",
};

Deno.test("planLead validates a good business lead and keeps the corporate domain", () => {
  const p = planLead(baseLead, DEFAULT_EMAIL_DOMAIN_BLOCKLIST);
  if (!p.ok) throw new Error("expected ok");
  assertEquals(p.leadId, "LEAD-1");
  assertEquals(p.email, "ada@example.com");
  assertEquals(p.firstName, "Ada");
  assertEquals(p.lastName, "Lovelace");
  assertEquals(p.companyDomain, "example.com");
  assertEquals(p.companyName, "Example Corp");
  assertEquals(p.emergency, false);
});

Deno.test("planLead fails a bad email with no writes", () => {
  const p = planLead(
    { ...baseLead, email: "nope" },
    DEFAULT_EMAIL_DOMAIN_BLOCKLIST,
  );
  assertEquals(p.ok, false);
  if (p.ok) throw new Error("unreachable");
  assertEquals(p.reason, "invalid email");
  assertEquals(p.leadId, "LEAD-1");
});

Deno.test("planLead fails a missing lead id", () => {
  const p = planLead({ ...baseLead, id: "" }, DEFAULT_EMAIL_DOMAIN_BLOCKLIST);
  assertEquals(p.ok, false);
});

Deno.test("planLead never links a company for a consumer-domain business lead", () => {
  const p = planLead(
    { ...baseLead, email: "ada@gmail.com" },
    DEFAULT_EMAIL_DOMAIN_BLOCKLIST,
  );
  if (!p.ok) throw new Error("expected ok");
  assertEquals(p.companyDomain, null);
});

Deno.test("planLead never links a company for an individual lead", () => {
  const p = planLead(
    { ...baseLead, contact_type: "individual" },
    DEFAULT_EMAIL_DOMAIN_BLOCKLIST,
  );
  if (!p.ok) throw new Error("expected ok");
  assertEquals(p.companyDomain, null);
});

Deno.test("planLead marks an emergency lead", () => {
  const p = planLead(
    { ...baseLead, contact_type: "emergency" },
    DEFAULT_EMAIL_DOMAIN_BLOCKLIST,
  );
  if (!p.ok) throw new Error("expected ok");
  assertEquals(p.emergency, true);
});

Deno.test("planLead sanitizes an HTML-injected message", () => {
  const p = planLead(
    { ...baseLead, message: "<b>hi</b><script>x</script>" },
    DEFAULT_EMAIL_DOMAIN_BLOCKLIST,
  );
  if (!p.ok) throw new Error("expected ok");
  assertEquals(p.message, "hi x");
});

// --- selectBatch ------------------------------------------------------------

Deno.test("selectBatch keeps only 'new' leads, oldest first", () => {
  const leads = [
    { ...baseLead, id: "c", received_at: "2026-09-03T00:00:00Z" },
    { ...baseLead, id: "a", received_at: "2026-09-01T00:00:00Z" },
    {
      ...baseLead,
      id: "done",
      received_at: "2026-08-01T00:00:00Z",
      status: "synced",
    },
    { ...baseLead, id: "b", received_at: "2026-09-02T00:00:00Z" },
  ];
  const { batch, eligible, remaining, cap } = selectBatch(leads, 200);
  assertEquals(eligible, 3);
  assertEquals(remaining, 0);
  assertEquals(cap, 200);
  assertEquals(batch.map((l) => l.id), ["a", "b", "c"]);
});

Deno.test("selectBatch caps the batch and reports the remainder (no starvation)", () => {
  const leads = Array.from({ length: 5 }, (_, i) => ({
    ...baseLead,
    id: `L${i}`,
    received_at: `2026-09-0${i + 1}T00:00:00Z`,
  }));
  const { batch, remaining, eligible } = selectBatch(leads, 2);
  assertEquals(eligible, 5);
  assertEquals(remaining, 3);
  // Oldest two processed first.
  assertEquals(batch.map((l) => l.id), ["L0", "L1"]);
});

// --- leadFromKvRecord / leadFromKvEntry (KV intake adapter) -----------------

Deno.test("leadFromKvRecord adapts a brand record: geo object -> string, null -> ''", () => {
  const l = leadFromKvRecord({
    id: "91c0e5d5",
    received_at: "2026-09-05T02:01:14.776Z",
    status: "new",
    name: "Avery Brand",
    email: "avery@brandmail.example",
    phone: null,
    contact_type: "business",
    message: "Potato engineering",
    source: null,
    geo: { city: "bedford", region: "MA", country: "US" },
  });
  assertEquals(l.id, "91c0e5d5");
  assertEquals(l.phone, ""); // null coalesced
  assertEquals(l.geo, "bedford, MA, US"); // object flattened
  assertEquals(l.contact_type, "business");
  assertEquals(l.company, "");
  assertEquals(l.message, "Potato engineering"); // no extras to fold
});

Deno.test("leadFromKvRecord maps brandhost.example org->company, infers business, keeps needs/reason/timing/source as structured details", () => {
  const l = leadFromKvRecord({
    id: "sh-1",
    received_at: "2026-09-06T12:00:00.000Z",
    status: "new",
    name: "Mike Owens",
    email: "mike@gmail.com",
    phone: null,
    org: "Bob's Roofing",
    needs: ["web", "files"],
    reason: "broken",
    timing: "contract's up in March",
    message: "", // brandhost.example allows an empty message
    source: "shrug.host-contact",
    geo: { city: "Springfield", region: "IL", country: "US" },
  });
  assertEquals(l.company, "Bob's Roofing"); // org -> company
  assertEquals(l.contact_type, "business"); // inferred from source
  // Message stays clean (empty here); extras become labeled Note lines, nothing dropped.
  assertEquals(l.message, "");
  assertEquals(l.details, [
    { label: "Needs", value: "web, files" },
    { label: "Reason", value: "broken" },
    { label: "Timing", value: "contract's up in March" },
    { label: "Via", value: "shrug.host-contact" },
  ]);
});

Deno.test("leadFromKvRecord keeps the message verbatim and extras as details; prefers explicit company/contact_type", () => {
  const l = leadFromKvRecord({
    id: "sh-2",
    name: "Dana Fields",
    email: "dana@bobsroofing.com",
    company: "Bob's Roofing LLC", // explicit company beats org
    org: "ignored org",
    contact_type: "individual", // explicit enum beats source inference
    needs: ["email"],
    message: "Need to move our email.",
    source: "shrug.host-contact",
  });
  assertEquals(l.company, "Bob's Roofing LLC");
  assertEquals(l.contact_type, "individual");
  assertEquals(l.message, "Need to move our email."); // no extras folded in
  assertEquals(l.details, [
    { label: "Needs", value: "email" },
    { label: "Via", value: "shrug.host-contact" },
  ]);
});

Deno.test("buildLeadNoteBody: message first, then each field as its own bold-labeled line (Geo included)", () => {
  const body = buildLeadNoteBody({
    message: "Need to move our email.",
    geo: "medford, MA, US",
    details: [
      { label: "Needs", value: "web, files" },
      { label: "Reason", value: "moving" },
      { label: "Via", value: "shrug.host-contact" },
    ],
  });
  assertEquals(
    body,
    "Need to move our email.\n\n" +
      "**Needs:** web, files\n\n" +
      "**Reason:** moving\n\n" +
      "**Via:** shrug.host-contact\n\n" +
      "**Geo:** medford, MA, US",
  );
});

Deno.test("buildLeadNoteBody: empty message + no details/geo yields '' (caller placeholders it)", () => {
  assertEquals(buildLeadNoteBody({ message: "", geo: "", details: [] }), "");
});

Deno.test("buildLeadNoteBody: only geo, no message/details", () => {
  assertEquals(
    buildLeadNoteBody({ message: "", geo: "boston, MA, US", details: [] }),
    "**Geo:** boston, MA, US",
  );
});

Deno.test("buildLeadNoteBody: a detail value carrying markdown is escaped; the label is not", () => {
  const body = buildLeadNoteBody({
    message: "",
    geo: "",
    details: [{ label: "Reason", value: "see ![](http://x/p.png) now" }],
  });
  assert(body.startsWith("**Reason:** "));
  assert(!body.includes("]("), body); // link/image syntax neutralized
});

Deno.test("leadFromKvEntry parses a JSON value; null on non-JSON / empty", () => {
  const good = leadFromKvEntry({
    key: "lead/1-abc",
    found: true,
    value: JSON.stringify({ id: "abc", email: "a@b.com", status: "new" }),
    valueEncoding: "utf8",
  });
  assert(good !== null);
  assertEquals(good?.id, "abc");
  assertEquals(leadFromKvEntry({ value: "not json{" }), null);
  assertEquals(leadFromKvEntry({ value: "" }), null);
  assertEquals(leadFromKvEntry({ value: "42" }), null); // JSON, but not an object
});

Deno.test("adapted brandhost.example record flows through planLead as a valid business lead", () => {
  const l = leadFromKvRecord({
    id: "sh-3",
    name: "Dana Fields",
    email: "dana@bobsroofing.com",
    org: "Bob's Roofing LLC",
    source: "shrug.host-contact",
    status: "new",
  });
  const p = planLead(l, DEFAULT_EMAIL_DOMAIN_BLOCKLIST);
  if (!p.ok) throw new Error("expected ok");
  assertEquals(p.contactType, "business");
  assertEquals(p.companyDomain, "bobsroofing.com");
  assertEquals(p.companyName, "Bob's Roofing LLC");
});

// --- classifyLead (lead spam classification, SHADOW mode) -------------------
//
// Acceptance fixture = the 2026-09-30 batch (design/lead-spam-filter.md section
// 6): six "Robertjisib" submissions (one solicitation template in six languages,
// shared machine-generated gmail localpart, malformed phone, IPs rotating across
// LT/RO) must all flag; the WEATHER MAN fediverse referral and the avery@brandmail.example
// control must both PASS. Flagging WEATHER MAN is an AUTOMATIC FAIL - it is the
// false-positive canary (a real, now-closed opportunity). Built through
// leadFromKvRecord so the whole KV intake path (incl. client_ip threading) is
// exercised, not a hand-rolled LeadRecord.

// A majority-Cyrillic body (Bulgarian "I want to know the price"), kept as \u
// escapes so this source file stays ASCII while the runtime string is non-Latin.
// Bulgarian "Iskam da znaya tsenata" ("I want to know the price") - a real
// non-Latin body like the Robertjisib Cyrillic submission, to exercise the
// nonlatin-body-ascii-name signal.
const RJ_CYRILLIC_BODY = "Искам да зная цената";

function the20260930Batch() {
  const rjIps = [
    "77.90.185.5",
    "141.98.11.224",
    "80.94.95.173",
    "80.94.95.202",
    "77.90.185.5",
    "141.98.11.224",
  ];
  // Same template, six languages. English + Cyrillic carry extra signals; the
  // Latin-script translations (Latin/Lithuanian/Indonesian) carry NONE of the
  // language-specific signals and MUST still flag on velocity + localpart +
  // phone + IP rotation alone - the whole point of the batch.
  const rjMessages = [
    "Hi, I want to know your price.", // English (solicitation phrase)
    RJ_CYRILLIC_BODY, // Bulgarian (non-Latin body)
    "Salve, volo scire pretium tuum.", // Latin (ASCII, no keyword)
    "Sveiki, noriu suzinoti jusu kaina.", // Lithuanian (ASCII, no keyword)
    "Halo, saya ingin tahu harga anda.", // Indonesian (ASCII, no keyword)
    "Bonjour, je veux connaitre votre prix.", // French (ASCII, no keyword)
  ];
  const robertjisib = rjMessages.map((message, i) =>
    leadFromKvRecord({
      id: `rj-0${i + 1}`,
      received_at: `2026-09-30T0${i}:00:00Z`,
      status: "new",
      name: "Robertjisib",
      email: "gregoryj8tl2g@gmail.com",
      phone: "80055512345", // 11 digits leading 8 -> not NANP/E.164 dialable
      contact_type: null, // raw null (coerced downstream; NOT a gating signal)
      message,
      client_ip: rjIps[i],
    })
  );

  const weatherman = leadFromKvRecord({
    id: "wm-01",
    received_at: "2026-09-30T12:00:00Z",
    status: "new",
    name: "WEATHER MAN",
    email: "WEATHERMAN@WEATHERISHAPPENING.COM",
    phone: null,
    contact_type: null, // null + all-caps + quirky domain: surface-only, must NOT gate
    message: "SNOOPJEDI SENT ME FROM THE FEDIVERSE",
    client_ip: "203.0.113.7",
  });

  const avery = leadFromKvRecord({
    id: "avery-01",
    received_at: "2026-09-30T13:00:00Z",
    status: "new",
    name: "Avery Brand",
    email: "avery@brandmail.example",
    phone: "+1 617 555 0100",
    contact_type: "business",
    message: "Potato engineering",
    client_ip: "198.51.100.23",
  });

  return { robertjisib, weatherman, avery };
}

Deno.test("classifyLead ACCEPTANCE: flags the 6 Robertjisib, PASSES WEATHER MAN + avery (2026-09-30 batch)", () => {
  const { robertjisib, weatherman, avery } = the20260930Batch();
  const batch = [...robertjisib, weatherman, avery];
  const verdicts = classifyLead(batch);

  // All six spam entries flag - regardless of message language.
  for (const l of robertjisib) {
    const v = verdicts.get(l.id);
    assert(v, `missing verdict for ${l.id}`);
    assertEquals(v!.flagged, true, `${l.id} should be flagged (${v!.reasons})`);
    assert(
      v!.score >= SPAM_SCORE_THRESHOLD,
      `${l.id} score ${v!.score} < threshold`,
    );
  }

  // The false-positive canary: WEATHER MAN is a REAL fediverse referral. Flagging
  // it is an AUTOMATIC FAIL of the acceptance (design section 6).
  const wm = verdicts.get("wm-01")!;
  assertEquals(
    wm.flagged,
    false,
    `WEATHER MAN must PASS (reasons: ${wm.reasons})`,
  );
  assert(
    wm.reasons.includes("referral-mention-discount"),
    "WEATHER MAN should earn the referral ham discount",
  );

  // The legit control passes clean.
  assertEquals(verdicts.get("avery-01")!.flagged, false);

  // Exactly six flagged in the whole batch.
  const flagged = [...verdicts.values()].filter((v) => v.flagged);
  assertEquals(flagged.length, 6);
});

Deno.test("classifyLead: velocity + localpart carry the Latin-script translations (language-independent)", () => {
  const { robertjisib } = the20260930Batch();
  // The French/Latin/Lithuanian/Indonesian entries have NO solicitation keyword
  // and a Latin-script body, so only velocity + localpart + phone + IP rotation
  // can flag them. Prove those alone clear the bar.
  const latinOnly = robertjisib.filter((l) =>
    /^(rj-03|rj-04|rj-05|rj-06)$/.test(l.id)
  );
  assertEquals(latinOnly.length, 4);
  const verdicts = classifyLead(robertjisib);
  for (const l of latinOnly) {
    const v = verdicts.get(l.id)!;
    assertEquals(v.flagged, true);
    assert(v.reasons.includes("identity-repeat:6"));
    assert(v.reasons.includes("localpart-machine-generated"));
    assert(!v.reasons.includes("solicitation-template"));
  }
});

Deno.test("classifyLead: a referral mention keeps a surface-spammy lead HAM (WEATHER MAN regression)", () => {
  // All-caps body + quirky .COM domain + null contact_type must not gate when a
  // referral mention is present.
  const lead = leadFromKvRecord({
    id: "ref-1",
    status: "new",
    name: "LOUD REFERRAL",
    email: "someone@weirddomain.example",
    message: "A FRIEND REFERRED ME TO YOUR SHOP",
    contact_type: null,
  });
  const v = classifyLead([lead]).get("ref-1")!;
  assertEquals(v.flagged, false);
  assert(v.reasons.includes("referral-mention-discount"));
});

Deno.test("classifyLead: repeat email ALONE does not flag a clean legit submitter", () => {
  // Three identical submissions from a human (clean localpart, clean phone, no
  // solicitation, single IP) score only the velocity weight (3) < threshold (4).
  const leads = [1, 2, 3].map((i) =>
    leadFromKvRecord({
      id: `dup-${i}`,
      status: "new",
      name: "Jane Roofing",
      email: "jane@example.com",
      phone: "+1 617 555 0133",
      message: "Following up on my quote request, thanks!",
      contact_type: "business",
      client_ip: "198.51.100.9",
    })
  );
  const verdicts = classifyLead(leads);
  for (const id of ["dup-1", "dup-2", "dup-3"]) {
    assertEquals(verdicts.get(id)!.flagged, false);
  }
});

Deno.test("localpartLooksMachine: machine-generated vs human localparts", () => {
  assert(localpartLooksMachine("gregoryj8tl2g@gmail.com"));
  assert(localpartLooksMachine("joshuaguerrero2v7t40d@gmail.com"));
  assert(!localpartLooksMachine("avery@brandmail.example"));
  assert(!localpartLooksMachine("weatherman@weatherishappening.com"));
  assert(!localpartLooksMachine("john.doe@example.com"));
  assert(!localpartLooksMachine("jsmith2024@example.com")); // trailing year: 1 transition
});

Deno.test("phoneLooksBogus: malformed vs dialable numbers", () => {
  assert(phoneLooksBogus("80055512345")); // bare 11-digit trunk-8, not intl -> bogus
  assert(!phoneLooksBogus("+1 617 555 0100")); // clean NANP
  assert(!phoneLooksBogus("617-555-0100")); // bare 10-digit NANP
  assert(!phoneLooksBogus("+44 7911 123456")); // plausible UK E.164
  assert(!phoneLooksBogus("")); // absent -> not a signal
  assert(!phoneLooksBogus("12345")); // too short -> not a signal
  // review M2: real zone-8 E.164 numbers must NOT flag, with or without '+'.
  assert(!phoneLooksBogus("+84912345678")); // Vietnam, entered as E.164
  assert(!phoneLooksBogus("+81312345678")); // Japan, entered as E.164
  assert(!phoneLooksBogus("84912345678")); // Vietnam pasted without '+' (cycle 2)
  assert(!phoneLooksBogus("81312345678")); // Japan pasted without '+'
});

Deno.test("classifyLead reasons are PII-free and client_ip drives ip-rotation (never a raw IP)", () => {
  const { robertjisib } = the20260930Batch();
  const v = classifyLead(robertjisib).get("rj-01")!;
  // IP rotation fired (4 distinct IPs across the identity)...
  assert(v.reasons.some((r) => r.startsWith("ip-rotation:")));
  // ...but no reason token leaks a raw IP, email, name, or message substring.
  const joined = v.reasons.join(" ");
  assert(
    !/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(joined),
    "no raw IP in reasons",
  );
  assert(!/gregory|gmail|robertjisib/i.test(joined), "no raw PII in reasons");
});

// --- classifyLead: review-cycle-1 hardening regressions ---------------------

Deno.test("classifyLead H1: a referral mention CANNOT smuggle a high-velocity burst through", () => {
  // Append a generic referral clause to every Robertjisib message (the exact
  // evasion the reviewer found). The already-flagging score must ignore the
  // discount, so all six still flag.
  const { robertjisib } = the20260930Batch();
  const evasive = robertjisib.map((l) => ({
    ...l,
    message: `${l.message} A friend sent me.`,
  }));
  const verdicts = classifyLead(evasive);
  for (const l of evasive) {
    const v = verdicts.get(l.id)!;
    assertEquals(v.flagged, true, `${l.id} must still flag (${v.reasons})`);
    assert(v.reasons.includes("referral-mention-ignored-corroborated"));
    assert(!v.reasons.includes("referral-mention-discount"));
  }
});

Deno.test("classifyLead H1 (cycle 2): a SINGLE-SHOT spam lead cannot zero itself out with a referral phrase", () => {
  // One submission, one IP (no velocity/rotation) but machine localpart +
  // solicitation + free-mail => score 5, already flagging. A referral clause
  // must NOT rescue it (the cycle-2 finding: the old velocity-only gate let
  // this through).
  const base = {
    id: "oneshot-1",
    status: "new",
    name: "Gregory",
    email: "gregoryj8tl2g@gmail.com",
    message: "I want to know your price",
    client_ip: "77.90.185.5",
  };
  const plain = classifyLead([leadFromKvRecord(base)]).get("oneshot-1")!;
  assertEquals(plain.flagged, true);
  const withReferral = classifyLead([
    leadFromKvRecord({
      ...base,
      message: `${base.message}. A friend sent me.`,
    }),
  ]).get("oneshot-1")!;
  assertEquals(
    withReferral.flagged,
    true,
    `single-shot evasion (${withReferral.reasons})`,
  );
  assert(
    withReferral.reasons.includes("referral-mention-ignored-corroborated"),
  );
});

Deno.test("classifyLead H2: a loyal customer contacting months apart from 2 networks is NOT flagged", () => {
  // Same email, 3 submissions spread across a year, two different IPs. Outside
  // the velocity window each submission is a singleton -> no velocity, no
  // rotation -> clean.
  const leads = [
    { when: "2026-01-10T10:00:00Z", ip: "198.51.100.5" },
    { when: "2026-05-22T14:00:00Z", ip: "203.0.113.9" }, // different network
    { when: "2026-10-01T09:00:00Z", ip: "198.51.100.5" },
  ].map((e, i) =>
    leadFromKvRecord({
      id: `loyal-${i}`,
      status: "new",
      received_at: e.when,
      name: "Pat Customer",
      email: "pat@patsgarage.example",
      phone: "+1 617 555 0144",
      message: "Hi, following up on our project - thanks again!",
      contact_type: "business",
      client_ip: e.ip,
    })
  );
  const verdicts = classifyLead(leads);
  for (const id of ["loyal-0", "loyal-1", "loyal-2"]) {
    const v = verdicts.get(id)!;
    assertEquals(v.flagged, false, `${id} should pass (${v.reasons})`);
    assert(!v.reasons.some((r) => r.startsWith("identity-repeat")));
    assert(!v.reasons.some((r) => r.startsWith("ip-rotation")));
  }
});

Deno.test("classifyLead H2: a same-week burst DOES cluster (window works both ways)", () => {
  const leads = [0, 1, 2, 3].map((i) =>
    leadFromKvRecord({
      id: `burst-${i}`,
      status: "new",
      received_at: `2026-10-0${i + 1}T09:00:00Z`,
      name: "Spammer",
      email: "burst@gmail.com",
      message: "know your price",
      client_ip: `80.94.95.${i + 1}`,
      phone: "80055512345",
    })
  );
  const verdicts = classifyLead(leads);
  for (const l of leads) {
    assertEquals(verdicts.get(l.id)!.flagged, true);
  }
});

Deno.test("classifyLead H3: a legit free-mail B2B inquiry is NOT flagged", () => {
  // A real freelancer from gmail. "cooperation"/"SEO"/"marketing services" are
  // no longer solicitation signals; a bare price question (+freemail) stays
  // below threshold.
  const cooperation = leadFromKvRecord({
    id: "legit-coop",
    status: "new",
    name: "Dana Smith",
    email: "dana.smith@gmail.com",
    message:
      "Hi, I'd love to explore a cooperation on SEO and marketing services for my shop.",
    contact_type: "business",
    client_ip: "198.51.100.40",
  });
  const priceAsk = leadFromKvRecord({
    id: "legit-price",
    status: "new",
    name: "Sam Jones",
    email: "sam.jones@gmail.com",
    message: "Could you let me know your price for a small website?",
    contact_type: "business",
    client_ip: "198.51.100.41",
  });
  const verdicts = classifyLead([cooperation, priceAsk]);
  assertEquals(verdicts.get("legit-coop")!.flagged, false);
  assert(
    !verdicts.get("legit-coop")!.reasons.includes("solicitation-template"),
  );
  const price = verdicts.get("legit-price")!;
  assertEquals(price.flagged, false); // solicitation(2)+freemail(1)=3 < 4
  assert(price.score < SPAM_SCORE_THRESHOLD);
});

Deno.test("classifyLead M1: a known-customer domain hard-passes even a spammy-looking lead", () => {
  const { robertjisib } = the20260930Batch();
  // Same would-be-spam lead, but its domain is on the known-customer allowlist.
  const asCustomer = robertjisib.map((l) => ({
    ...l,
    email: l.email.replace("@gmail.com", "@knowncustomer.example"),
  }));
  const verdicts = classifyLead(asCustomer, {
    knownDomains: ["knowncustomer.example"],
  });
  for (const l of asCustomer) {
    const v = verdicts.get(l.id)!;
    assertEquals(v.flagged, false);
    assertEquals(v.reasons, ["known-customer-hardpass"]);
  }
});

Deno.test("classifyLead M3: the free-mail signal honors the configurable blocklist", () => {
  // gmail.com NOT in the passed list => no freemail-plus-solicitation reason.
  const lead = leadFromKvRecord({
    id: "cfg-1",
    status: "new",
    name: "X",
    email: "someone@gmail.com",
    message: "know your price",
    client_ip: "198.51.100.50",
  });
  const withEmpty = classifyLead([lead], { freemailDomains: [] }).get("cfg-1")!;
  assert(!withEmpty.reasons.includes("freemail-plus-solicitation"));
  const withGmail = classifyLead([lead], { freemailDomains: ["gmail.com"] })
    .get("cfg-1")!;
  assert(withGmail.reasons.includes("freemail-plus-solicitation"));
  // review INFO-7: a mixed-case operator entry still matches (list lowercased).
  const mixedCase = classifyLead([lead], { freemailDomains: ["GMAIL.COM"] })
    .get("cfg-1")!;
  assert(mixedCase.reasons.includes("freemail-plus-solicitation"));
});

Deno.test("classifyLead L1: Latin-with-diacritics (Vietnamese) is NOT treated as non-Latin script", () => {
  const viet = leadFromKvRecord({
    id: "viet-1",
    status: "new",
    name: "Nguyen Van A", // ASCII name
    email: "nguyen@example.com",
    message:
      "Chào bạn, tôi muốn hỏi về dịch vụ của bạn cho một dự án nhỏ sắp tới nhé.",
    contact_type: "business",
    client_ip: "198.51.100.60",
  });
  const v = classifyLead([viet]).get("viet-1")!;
  assert(!v.reasons.includes("nonlatin-body-ascii-name"));
  assertEquals(v.flagged, false);
});

// --- classifyLead: October-wave tuning (name velocity + gibberish handle) ---
//
// The live 2026-10 shadow run surfaced a wave the 09-30 fixture did not cover:
// a persona ("Robertjisib") rotating a FRESH gmail each submission (defeating
// email velocity), and a separate gibberish-handle campaign with random
// uppercase-plus-digits names. These regressions lock in the two language-
// independent signals added to catch them, and the FP guards that keep them off
// real humans. All identities below are synthetic stand-ins (no real lead data).

Deno.test("nameLooksGibberish: machine handles vs human names", () => {
  assert(nameLooksGibberish("NARYTHY911194NEYRTHYT"));
  assert(nameLooksGibberish("NARTYTRYUT911194NEWETREWT"));
  assert(!nameLooksGibberish("Avery Brand")); // multi-word
  assert(!nameLooksGibberish("WEATHER MAN")); // multi-word, all-caps but spaced
  assert(!nameLooksGibberish("Robertjisib")); // no digit run
  assert(!nameLooksGibberish("jsmith2024")); // short + only 4 digits, len < 12
  assert(!nameLooksGibberish("Nguyen Van A")); // multi-word
  assert(!nameLooksGibberish("")); // empty
});

Deno.test("classifyLead: one persona across DISTINCT burner emails corroborates (name-velocity)", () => {
  // Same name, two DIFFERENT gmail addresses, same week => name-repeat:2. Paired
  // with a machine localpart it clears the bar - the exact Robertjisib-wave lead
  // that email velocity alone missed.
  const leads = [
    leadFromKvRecord({
      id: "persona-a",
      status: "new",
      received_at: "2026-10-10T09:00:00Z",
      name: "Robertjisib",
      email: "joshuaguerrero2v7t40d@gmail.com", // machine localpart
      message: "Hi, I want to know your price.",
      client_ip: "77.90.185.5",
    }),
    leadFromKvRecord({
      id: "persona-b",
      status: "new",
      received_at: "2026-10-11T09:00:00Z",
      name: "Robertjisib",
      email: "ninadvhegmannjfc33@gmail.com", // different burner
      message: "Salve, volo scire pretium tuum.",
      client_ip: "141.98.11.224",
    }),
  ];
  const verdicts = classifyLead(leads);
  const a = verdicts.get("persona-a")!;
  assert(a.reasons.includes("name-repeat:2"), `a reasons: ${a.reasons}`);
  assertEquals(a.flagged, true); // solicitation+freemail+localpart+name-repeat
  // The partner lead earns the name-repeat corroboration too (symmetry).
  assert(verdicts.get("persona-b")!.reasons.includes("name-repeat:2"));
});

Deno.test("classifyLead: name-velocity needs DISTINCT emails - a typo resubmit stays HAM", () => {
  // A real human resubmits with the same name but two addresses (work + a typo).
  // name-repeat:2 fires (+1) but can never flag alone, so an otherwise-clean
  // human is safe - the FP guard that keeps name-velocity from over-reaching.
  const leads = [
    leadFromKvRecord({
      id: "human-1",
      status: "new",
      received_at: "2026-10-10T10:00:00Z",
      name: "Jordan Fields",
      email: "jordan.fields@acme.example",
      phone: "+1 617 555 0170",
      message: "Hi, following up on the roofing quote for our warehouse.",
      contact_type: "business",
      client_ip: "198.51.100.70",
    }),
    leadFromKvRecord({
      id: "human-2",
      status: "new",
      received_at: "2026-10-10T10:05:00Z",
      name: "Jordan Fields",
      email: "jordan.fields@acme.exampl", // typo'd domain on resubmit
      phone: "+1 617 555 0170",
      message: "Hi, following up on the roofing quote for our warehouse.",
      contact_type: "business",
      client_ip: "198.51.100.70",
    }),
  ];
  const verdicts = classifyLead(leads);
  for (const id of ["human-1", "human-2"]) {
    const v = verdicts.get(id)!;
    assert(v.reasons.includes("name-repeat:2"), `${id}: ${v.reasons}`);
    assertEquals(v.flagged, false, `${id} must stay ham (${v.score})`);
  }
});

Deno.test("classifyLead: a gibberish-handle name flags on velocity + handle", () => {
  // The belettersmail campaign: random uppercase-plus-digits names, same burner
  // email reused across rotating IPs. name-gibberish (+2) is what carries the
  // second-IP sibling that email velocity alone left one point short.
  const leads = [
    leadFromKvRecord({
      id: "gib-1",
      status: "new",
      received_at: "2026-10-09T08:00:00Z",
      name: "NARTYTRYUT911194NEWETREWT",
      email: "ericson44961@belettersmail.example",
      message: "MERTHYTJTJ911194MAMYJRTH",
      client_ip: "193.29.139.219",
    }),
    leadFromKvRecord({
      id: "gib-2",
      status: "new",
      received_at: "2026-10-09T08:05:00Z",
      name: "NARYTHY911194NEYRTHYT",
      email: "ericson44961@belettersmail.example", // same burner
      message: "MEYJTJ911194MAYTRYR",
      client_ip: "193.29.139.223", // rotated IP
    }),
  ];
  const verdicts = classifyLead(leads);
  for (const id of ["gib-1", "gib-2"]) {
    const v = verdicts.get(id)!;
    assert(v.reasons.includes("name-gibberish"), `${id}: ${v.reasons}`);
    assertEquals(v.flagged, true, `${id} should flag (${v.score})`);
  }
});

// --- push_leads confirm-gate (throws before any I/O) ------------------------

Deno.test("push_leads refuses a real run without confirm:true", async () => {
  const ctx = {
    globalArgs: {
      baseUrl: "https://crm.example.com",
      apiToken: "tok",
      opportunityStage: "NEW",
      emailDomainBlocklist: [...DEFAULT_EMAIL_DOMAIN_BLOCKLIST],
      emergencyRestrictedRole: "",
    },
    logger: {
      debug() {},
      info() {},
      warning() {},
      error() {},
    },
    writeResource: () => Promise.resolve({ name: "n" }),
  };
  await assertRejects(
    () =>
      model.methods.push_leads.execute(
        { leads: [baseLead], confirm: false, dryRun: false, maxBatch: 200 },
        ctx as never,
      ),
    Error,
    "confirm:true",
  );
});

// --- deleteNote -------------------------------------------------------------

function fakeDeleteCtx() {
  const written: Record<string, unknown>[] = [];
  return {
    globalArgs: {
      baseUrl: "https://crm.example.com",
      apiToken: "tok",
      opportunityStage: "NEW",
      emailDomainBlocklist: [...DEFAULT_EMAIL_DOMAIN_BLOCKLIST],
      emergencyRestrictedRole: "",
    },
    logger: { debug() {}, info() {}, warning() {}, error() {} },
    written,
    writeResource: (
      _spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      written.push(data);
      return Promise.resolve({ name });
    },
  };
}

Deno.test("deleteNote requires leadId or noteId (throws before any I/O)", async () => {
  const ctx = fakeDeleteCtx();
  await assertRejects(
    () =>
      model.methods.deleteNote.execute(
        { dryRun: false, confirm: false },
        ctx as never,
      ),
    Error,
    "requires leadId or noteId",
  );
});

Deno.test("deleteNote dryRun with an explicit noteId plans, no DELETE", async () => {
  const ctx = fakeDeleteCtx();
  const orig = globalThis.fetch;
  let called = false;
  globalThis.fetch = (() => {
    called = true;
    return Promise.resolve(new Response("{}", { status: 200 }));
  }) as never;
  try {
    await model.methods.deleteNote.execute(
      { noteId: "n-1", dryRun: true, confirm: false },
      ctx as never,
    );
    const rec = ctx.written.at(-1)!;
    assertEquals(rec.found, true);
    assertEquals(rec.deleted, false);
    assertEquals(rec.resolvedVia, "noteId");
    assert(!called, "dryRun must not call the API");
  } finally {
    globalThis.fetch = orig;
  }
});

Deno.test("deleteNote with a noteId refuses a real delete without confirm:true", async () => {
  const ctx = fakeDeleteCtx();
  await assertRejects(
    () =>
      model.methods.deleteNote.execute(
        { noteId: "n-1", dryRun: false, confirm: false },
        ctx as never,
      ),
    Error,
    "confirm:true",
  );
});

Deno.test("deleteNote confirm: DELETEs /rest/notes/{id} and records deleted:true", async () => {
  const ctx = fakeDeleteCtx();
  const orig = globalThis.fetch;
  const calls: { method?: string; url: string }[] = [];
  globalThis.fetch = ((url: string | URL, init?: RequestInit) => {
    calls.push({ method: init?.method, url: String(url) });
    return Promise.resolve(new Response("{}", { status: 200 }));
  }) as never;
  try {
    await model.methods.deleteNote.execute(
      { noteId: "n-9", dryRun: false, confirm: true },
      ctx as never,
    );
    assertEquals(calls.length, 1);
    assertEquals(calls[0].method, "DELETE");
    assert(calls[0].url.includes("/rest/notes/n-9"), calls[0].url);
    assertEquals(ctx.written.at(-1)!.deleted, true);
  } finally {
    globalThis.fetch = orig;
  }
});

// --- upsertOpportunity helpers ----------------------------------------------

Deno.test("toCurrency converts whole units to integer micros", () => {
  assertEquals(toCurrency(50000, "USD"), {
    amountMicros: 50_000_000_000,
    currencyCode: "USD",
  });
  // No float drift on fractional amounts.
  assertEquals(toCurrency(19.99, "USD").amountMicros, 19_990_000);
  assertEquals(Number.isInteger(toCurrency(19.99, "USD").amountMicros), true);
});

Deno.test("normalizeCloseDate anchors a bare date and passes through ISO", () => {
  assertEquals(normalizeCloseDate("2026-09-30"), "2026-09-30T00:00:00.000Z");
  assertEquals(
    normalizeCloseDate("2026-09-30T12:34:56Z"),
    "2026-09-30T12:34:56.000Z",
  );
  for (const bad of ["", "   ", "not-a-date", null]) {
    assertEquals(normalizeCloseDate(bad), null);
  }
});

Deno.test("isFilterSafe rejects Twenty filter metacharacters", () => {
  assert(isFilterSafe("Acme Corp"));
  assert(isFilterSafe("Acme & Co - West"));
  for (const bad of ["", "a[eq]:b", "a,b", "a(b)", "a;b", "a:b"]) {
    assertEquals(isFilterSafe(bad), false);
  }
});

Deno.test("upsertOpportunity refuses a real run without confirm:true", async () => {
  const ctx = {
    globalArgs: {
      baseUrl: "https://crm.example.com",
      apiToken: "tok",
      opportunityStage: "NEW",
      emailDomainBlocklist: [...DEFAULT_EMAIL_DOMAIN_BLOCKLIST],
      emergencyRestrictedRole: "",
    },
    logger: { debug() {}, info() {}, warning() {}, error() {} },
    writeResource: () => Promise.resolve({ name: "n" }),
  };
  await assertRejects(
    () =>
      model.methods.upsertOpportunity.execute(
        {
          leadId: "acme-q1-renewal-2026",
          name: "Test",
          currencyCode: "USD",
          closeDate: "",
          companyName: "",
          companyDomain: "",
          pointOfContactName: "",
          pointOfContactEmail: "",
          channelPartnerName: "",
          noteBody: "",
          confirm: false,
          dryRun: false,
        },
        ctx as never,
      ),
    Error,
    "confirm:true",
  );
});

Deno.test("upsertOpportunity rejects an invalid leadId before any I/O", async () => {
  const ctx = {
    globalArgs: {
      baseUrl: "https://crm.example.com",
      apiToken: "tok",
      opportunityStage: "NEW",
      emailDomainBlocklist: [...DEFAULT_EMAIL_DOMAIN_BLOCKLIST],
      emergencyRestrictedRole: "",
    },
    logger: { debug() {}, info() {}, warning() {}, error() {} },
    writeResource: () => Promise.resolve({ name: "n" }),
  };
  await assertRejects(
    () =>
      model.methods.upsertOpportunity.execute(
        {
          leadId: "bad id with spaces!",
          name: "Test",
          currencyCode: "USD",
          closeDate: "",
          companyName: "",
          companyDomain: "",
          pointOfContactName: "",
          pointOfContactEmail: "",
          channelPartnerName: "",
          noteBody: "",
          confirm: true,
          dryRun: true,
        },
        ctx as never,
      ),
    Error,
    "Invalid leadId",
  );
});

// A fetch stub for upsertOpportunity write-path tests. Routes by method+path
// and records every call so assertions can inspect the request bodies.
function stubTwentyFetch(
  handlers: (method: string, path: string, body: unknown) => unknown,
): {
  calls: Array<{ method: string; path: string; body: unknown }>;
  restore: () => void;
} {
  const calls: Array<{ method: string; path: string; body: unknown }> = [];
  const orig = globalThis.fetch;
  globalThis.fetch = ((url: string | URL, init?: RequestInit) => {
    const path = String(url).replace("https://crm.example.com", "");
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path, body });
    const payload = handlers(method, path, body) ?? {};
    return Promise.resolve(
      {
        ok: true,
        status: 200,
        statusText: "OK",
        text: () => Promise.resolve(JSON.stringify(payload)),
      } as Response,
    );
  }) as typeof fetch;
  return { calls, restore: () => (globalThis.fetch = orig) };
}

const UPSERT_CTX = {
  globalArgs: {
    baseUrl: "https://crm.example.com",
    apiToken: "tok",
    opportunityStage: "NEW",
    emailDomainBlocklist: [...DEFAULT_EMAIL_DOMAIN_BLOCKLIST],
    emergencyRestrictedRole: "",
  },
  logger: { debug() {}, info() {}, warning() {}, error() {} },
  writeResource: () => Promise.resolve({ name: "n" }),
};

const OPP_META = {
  data: [{
    nameSingular: "opportunity",
    fields: [
      {
        name: "stage",
        options: [{ value: "NEW" }, { value: "PROPOSAL" }, {
          value: "CUSTOMER",
        }],
      },
      {
        name: "lineOfBusiness",
        options: [{ value: "CONSULTING" }, { value: "HOSTING" }, {
          value: "GAMES",
        }],
      },
      {
        name: "sourceChannel",
        options: [{ value: "DIRECT" }, { value: "REFERRAL" }, {
          value: "CONSULTING_HANDOFF",
        }],
      },
      // Provider-pipeline fields (TWENTY-OPP-FIELDS).
      {
        name: "qualStatus",
        type: "SELECT",
        options: [{ value: "RESEARCH" }, { value: "CONTACT_IDENTIFIED" }, {
          value: "TECH_QUALIFICATION_NEEDED",
        }, { value: "FUTURE" }],
      },
      { name: "asn", type: "TEXT" },
      {
        name: "offering",
        type: "SELECT",
        options: [
          { value: "MANAGED" },
          { value: "SUBSTRATE" },
          {
            value: "PROJECT",
          },
          { value: "RETAINER" },
          { value: "LOCAL_IT" },
          { value: "PEERING" },
        ],
      },
      // Generic-scalar fixtures for customFields tests: a plain TEXT field, a
      // non-reserved SELECT, and a composite (CURRENCY) that must be rejected.
      { name: "region", type: "TEXT" },
      {
        name: "tier",
        type: "SELECT",
        options: [{ value: "STANDARD" }, { value: "PRIORITY" }],
      },
      { name: "priorityScore", type: "NUMBER" },
      { name: "annualRevenue", type: "CURRENCY" },
      { name: "closeDate", type: "DATE_TIME" },
    ],
  }],
};

Deno.test("upsertOpportunity does NOT clobber stage/currency on an amount-only update", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return {
        data: {
          opportunities: [{
            id: "opp1",
            stage: "PROPOSAL",
            amount: { amountMicros: 1_000_000, currencyCode: "EUR" },
          }],
        },
      };
    }
    if (method === "PATCH") {
      return { data: { updateOpportunity: { id: "opp1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "acme-q1-renewal-2026",
        name: "Acme",
        amount: 999, // no stage, no currencyCode supplied
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH to the existing opportunity");
    const body = patch!.body as Record<string, unknown>;
    // stage omitted => existing PROPOSAL preserved (the regression).
    assertEquals("stage" in body, false);
    // currency preserved from the existing record, not forced to USD.
    assertEquals(
      (body.amount as Record<string, unknown>).currencyCode,
      "EUR",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity applies the default stage on create", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } }; // none exists => create
    }
    if (method === "POST") {
      return { data: { createOpportunity: { id: "new1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "brand-new-2026",
        name: "New Deal",
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a POST to create the opportunity");
    const body = post!.body as Record<string, unknown>;
    assertEquals(body.stage, "NEW");
    assertEquals(body.leadId, "brand-new-2026");
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity writes BOTH segmentation fields on create", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } }; // none exists => create
    }
    if (method === "POST") {
      return { data: { createOpportunity: { id: "new1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "seg-both-2026",
        name: "Segmented Deal",
        lineOfBusiness: "CONSULTING",
        sourceChannel: "REFERRAL",
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a POST to create the opportunity");
    const body = post!.body as Record<string, unknown>;
    assertEquals(body.lineOfBusiness, "CONSULTING");
    assertEquals(body.sourceChannel, "REFERRAL");
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity writes ONLY the segmentation field that was set (update path)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [{ id: "opp1", stage: "PROPOSAL" }] } };
    }
    if (method === "PATCH") {
      return { data: { updateOpportunity: { id: "opp1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "seg-one-2026",
        name: "One Segment",
        lineOfBusiness: "HOSTING", // sourceChannel deliberately omitted
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH to the existing opportunity");
    const body = patch!.body as Record<string, unknown>;
    assertEquals(body.lineOfBusiness, "HOSTING");
    // Unset field is omitted from the body, never nulled.
    assertEquals("sourceChannel" in body, false);
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity omits BOTH segmentation fields when neither is set", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [{ id: "opp1", stage: "PROPOSAL" }] } };
    }
    if (method === "PATCH") {
      return { data: { updateOpportunity: { id: "opp1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "seg-none-2026",
        name: "No Segments",
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH to the existing opportunity");
    const body = patch!.body as Record<string, unknown>;
    assertEquals("lineOfBusiness" in body, false);
    assertEquals("sourceChannel" in body, false);
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity treats an empty-string segmentation token as unset (never nulled)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [{ id: "opp1", stage: "PROPOSAL" }] } };
    }
    if (method === "PATCH") {
      return { data: { updateOpportunity: { id: "opp1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "seg-empty-2026",
        name: "Empty Segment",
        lineOfBusiness: "", // unresolved CEL fallback => leave unchanged
        sourceChannel: "",
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH to the existing opportunity");
    const body = patch!.body as Record<string, unknown>;
    // "" is coerced to unset: omitted from the body, not written as "".
    assertEquals("lineOfBusiness" in body, false);
    assertEquals("sourceChannel" in body, false);
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity rejects a segmentation token not in the live enum", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    return {};
  });
  try {
    await assertRejects(
      () =>
        model.methods.upsertOpportunity.execute(
          {
            leadId: "seg-bad-2026",
            name: "Bad Segment",
            lineOfBusiness: "AEROSPACE", // not a provisioned option
            closeDate: "",
            companyName: "",
            companyDomain: "",
            pointOfContactName: "",
            pointOfContactEmail: "",
            noteBody: "",
            confirm: true,
            dryRun: false,
          } as never,
          UPSERT_CTX as never,
        ),
      Error,
      "Invalid lineOfBusiness",
    );
    // Failed validation => no write was attempted.
    assertEquals(calls.some((c) => c.method === "POST"), false);
  } finally {
    restore();
  }
});

// --- upsertOpportunity: asn / qualStatus / customFields (TWENTY-OPP-FIELDS) --

Deno.test("upsertOpportunity writes asn (uppercased) + qualStatus on create", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    if (method === "POST") {
      return { data: { createOpportunity: { id: "new1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "brand-net-example-2026",
        name: "Provider Deal",
        asn: "as64496", // lowercase input => uppercased on store
        qualStatus: "TECH_QUALIFICATION_NEEDED",
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a POST to create the opportunity");
    const body = post!.body as Record<string, unknown>;
    assertEquals(body.asn, "AS64496");
    assertEquals(body.qualStatus, "TECH_QUALIFICATION_NEEDED");
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity rejects a qualStatus token not in the live enum", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    return {};
  });
  try {
    await assertRejects(
      () =>
        model.methods.upsertOpportunity.execute(
          {
            leadId: "qs-bad-2026",
            name: "Bad Qual",
            qualStatus: "NOT_A_STATUS",
            closeDate: "",
            companyName: "",
            companyDomain: "",
            pointOfContactName: "",
            pointOfContactEmail: "",
            noteBody: "",
            confirm: true,
            dryRun: false,
          } as never,
          UPSERT_CTX as never,
        ),
      Error,
      "Invalid qualStatus",
    );
    assertEquals(calls.some((c) => c.method === "POST"), false);
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity rejects a malformed asn (^AS<digits>$ guard)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    return {};
  });
  try {
    // Bare digits (no AS prefix), junk, AS-with-no-digits, and >10 digits (over
    // the 32-bit ASN bound — also the truncate-before-guard guard) all fail.
    for (
      const bad of [
        "64249",
        "AS64496; DROP",
        "ASN-64249",
        "AS",
        "AS12345678901",
      ]
    ) {
      await assertRejects(
        () =>
          model.methods.upsertOpportunity.execute(
            {
              leadId: "asn-bad-2026",
              name: "Bad ASN",
              asn: bad,
              closeDate: "",
              companyName: "",
              companyDomain: "",
              pointOfContactName: "",
              pointOfContactEmail: "",
              noteBody: "",
              confirm: true,
              dryRun: false,
            } as never,
            UPSERT_CTX as never,
          ),
        Error,
        "Invalid asn",
      );
    }
    assertEquals(calls.some((c) => c.method === "POST"), false);
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity omits asn/qualStatus when empty or unset (update path, never nulled)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [{ id: "opp1", stage: "PROPOSAL" }] } };
    }
    if (method === "PATCH") {
      return { data: { updateOpportunity: { id: "opp1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "asn-empty-2026",
        name: "Empty ASN",
        asn: "", // empty => leave unchanged
        // qualStatus deliberately unset
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH to the existing opportunity");
    const body = patch!.body as Record<string, unknown>;
    assertEquals("asn" in body, false);
    assertEquals("qualStatus" in body, false);
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity customFields: scalar TEXT + valid SELECT pass through to the body", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    if (method === "POST") {
      return { data: { createOpportunity: { id: "new1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "cf-ok-2026",
        name: "Custom Fields",
        customFields: { region: "us-east", tier: "PRIORITY" },
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a POST to create the opportunity");
    const body = post!.body as Record<string, unknown>;
    assertEquals(body.region, "us-east");
    assertEquals(body.tier, "PRIORITY");
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity customFields: unknown key, composite type, and bad SELECT are rejected", async () => {
  const cases: Array<[Record<string, unknown>, string]> = [
    [{ notAField: "x" }, "Unknown customFields key"],
    [{ annualRevenue: 100 }, "non-scalar type"],
    [{ tier: "NOPE" }, "Valid options"],
  ];
  for (const [customFields, needle] of cases) {
    const { calls, restore } = stubTwentyFetch((method, path) => {
      if (path.startsWith("/rest/metadata/objects")) return OPP_META;
      if (method === "GET" && path.startsWith("/rest/opportunities")) {
        return { data: { opportunities: [] } };
      }
      return {};
    });
    try {
      await assertRejects(
        () =>
          model.methods.upsertOpportunity.execute(
            {
              leadId: "cf-bad-2026",
              name: "Bad CF",
              customFields,
              closeDate: "",
              companyName: "",
              companyDomain: "",
              pointOfContactName: "",
              pointOfContactEmail: "",
              noteBody: "",
              confirm: true,
              dryRun: false,
            } as never,
            UPSERT_CTX as never,
          ),
        Error,
        needle,
      );
      assertEquals(calls.some((c) => c.method === "POST"), false);
    } finally {
      restore();
    }
  }
});

Deno.test("upsertOpportunity customFields: reserved keys and null are rejected", async () => {
  const cases: Array<[Record<string, unknown>, string]> = [
    [{ leadId: "hijack" }, "reserved"],
    [{ lineOfBusiness: "HOSTING" }, "reserved"],
    [{ asn: "AS1" }, "reserved"],
    [{ region: null }, "null is not permitted"],
  ];
  for (const [customFields, needle] of cases) {
    const { calls, restore } = stubTwentyFetch((method, path) => {
      if (path.startsWith("/rest/metadata/objects")) return OPP_META;
      if (method === "GET" && path.startsWith("/rest/opportunities")) {
        return { data: { opportunities: [] } };
      }
      return {};
    });
    try {
      await assertRejects(
        () =>
          model.methods.upsertOpportunity.execute(
            {
              leadId: "cf-reserved-2026",
              name: "Reserved CF",
              customFields,
              closeDate: "",
              companyName: "",
              companyDomain: "",
              pointOfContactName: "",
              pointOfContactEmail: "",
              noteBody: "",
              confirm: true,
              dryRun: false,
            } as never,
            UPSERT_CTX as never,
          ),
        Error,
        needle,
      );
      assertEquals(calls.some((c) => c.method === "POST"), false);
    } finally {
      restore();
    }
  }
});

Deno.test("upsertOpportunity customFields: empty-string value is omitted (not written)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [{ id: "opp1", stage: "PROPOSAL" }] } };
    }
    if (method === "PATCH") {
      return { data: { updateOpportunity: { id: "opp1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "cf-empty-2026",
        name: "Empty CF",
        customFields: { region: "", tier: "STANDARD" },
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH to the existing opportunity");
    const body = patch!.body as Record<string, unknown>;
    assertEquals("region" in body, false); // empty-string => omitted
    assertEquals(body.tier, "STANDARD");
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity customFields: fail-closed when opportunity metadata is unreadable", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { status: 500, body: { messages: ["boom"] } };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { body: { data: { opportunities: [] } } };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertOpportunity.execute(
          {
            leadId: "cf-failclosed-2026",
            name: "Fail Closed",
            customFields: { region: "us-east" },
            closeDate: "",
            companyName: "",
            companyDomain: "",
            pointOfContactName: "",
            pointOfContactEmail: "",
            noteBody: "",
            confirm: true,
            dryRun: false,
          } as never,
          ctx as never,
        ),
      Error,
      "fail-closed",
    );
    // No create attempted.
    assertEquals(calls.some((c) => c.method === "POST"), false);
  } finally {
    restore();
  }
});

// --- upsertOpportunity code-review-rework (cycle 2) hardening ----------------

Deno.test("OpportunityUpsertSchema round-trips asn/qualStatus/customFields (F6 no-strip)", () => {
  const parsed = OpportunityUpsertSchema.parse({
    baseUrl: "https://crm.example.com",
    action: "created",
    dryRun: false,
    leadId: "L1",
    name: "X",
    stage: "NEW",
    asn: "AS64496",
    qualStatus: "FUTURE",
    customFields: { region: "us-east", tier: "PRIORITY" },
    companyLinked: false,
    noteEnsured: false,
    retrievedAt: "2026-09-16T00:00:00.000Z",
  });
  // If a field had been omitted from the schema, zod would strip it here and
  // read-back verification would silently pass on a value that never persisted.
  assertEquals(parsed.asn, "AS64496");
  assertEquals(parsed.qualStatus, "FUTURE");
  assertEquals(parsed.customFields, { region: "us-east", tier: "PRIORITY" });
});

Deno.test("OppViewSchema + OpportunityRefSchema round-trip asn/qualStatus (F6 no-strip)", () => {
  const v = OppViewSchema.parse({
    id: "o1",
    name: "X",
    stage: "NEW",
    asn: "AS1",
    qualStatus: "RESEARCH",
  });
  assertEquals(v.asn, "AS1");
  assertEquals(v.qualStatus, "RESEARCH");
  const r = OpportunityRefSchema.parse({
    baseUrl: "b",
    found: true,
    asn: "AS2",
    qualStatus: "FUTURE",
    retrievedAt: "2026-09-16T00:00:00.000Z",
  });
  assertEquals(r.asn, "AS2");
  assertEquals(r.qualStatus, "FUTURE");
});

Deno.test("upsertOpportunity opportunityUpsert snapshot carries asn/qualStatus/customFields (F10 content)", async () => {
  const { restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    if (method === "POST") {
      return { data: { createOpportunity: { id: "new1" } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "snap-2026",
        name: "Snap",
        asn: "AS64496",
        qualStatus: "FUTURE",
        customFields: { region: "us-east" },
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "opportunityUpsert");
    assert(snap, "expected an opportunityUpsert snapshot write");
    assertEquals(snap!.data.asn, "AS64496");
    assertEquals(snap!.data.qualStatus, "FUTURE");
    assertEquals(snap!.data.customFields, { region: "us-east" });
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity writes asn (uppercased) + qualStatus on the UPDATE (PATCH) path", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [{ id: "opp1", stage: "PROPOSAL" }] } };
    }
    if (method === "PATCH") {
      return { data: { updateOpportunity: { id: "opp1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "asn-update-2026",
        name: "Upd",
        asn: "as64496",
        qualStatus: "CONTACT_IDENTIFIED",
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH");
    const body = patch!.body as Record<string, unknown>;
    assertEquals(body.asn, "AS64496");
    assertEquals(body.qualStatus, "CONTACT_IDENTIFIED");
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity customFields: a non-finite NUMBER (Infinity) is rejected (null-forbidden invariant)", async () => {
  // Infinity passes z.number() and the `v === null` check, but JSON.stringify
  // would serialize it to null and silently clear the field — the exact outcome
  // the null-forbidden contract prevents. Must be rejected pre-write.
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    return {};
  });
  try {
    await assertRejects(
      () =>
        model.methods.upsertOpportunity.execute(
          {
            leadId: "cf-inf-2026",
            name: "Inf CF",
            customFields: { priorityScore: Infinity },
            closeDate: "",
            companyName: "",
            companyDomain: "",
            pointOfContactName: "",
            pointOfContactEmail: "",
            noteBody: "",
            confirm: true,
            dryRun: false,
          } as never,
          UPSERT_CTX as never,
        ),
      Error,
      "non-finite",
    );
    assertEquals(calls.some((c) => c.method === "POST"), false);
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity customFields: a finite NUMBER passes through to the body", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    if (method === "POST") {
      return { data: { createOpportunity: { id: "new1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "cf-num-2026",
        name: "Num CF",
        customFields: { priorityScore: 42 },
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a POST");
    assertEquals((post!.body as Record<string, unknown>).priorityScore, 42);
  } finally {
    restore();
  }
});

Deno.test("buildOpportunityBody drops a reserved customFields key (defense-in-depth, both paths)", () => {
  // Even if a reserved key somehow reached buildOpportunityBody (execute rejects
  // it upstream), the body-assembly layer must never emit it — so the immutable
  // leadId marker cannot be overwritten via the escape hatch on the PATCH path.
  const body = buildOpportunityBody({
    name: "X",
    customFields: {
      leadId: "hijack",
      lineOfBusiness: "HOSTING",
      region: "us-east",
    } as Record<string, string | number | boolean>,
  });
  assertEquals("leadId" in body, false);
  assertEquals("lineOfBusiness" in body, false);
  assertEquals(body.region, "us-east");
  assertEquals(body.name, "X");
});

// --- upsertOpportunity: offering segmentation SELECT (TWENTY-OPP-OFFERING) ---

Deno.test("upsertOpportunity writes offering on create", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    if (method === "POST") {
      return { data: { createOpportunity: { id: "new1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "offering-create-2026",
        name: "Offering Deal",
        offering: "SUBSTRATE",
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a POST");
    assertEquals((post!.body as Record<string, unknown>).offering, "SUBSTRATE");
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity rejects an offering token not in the live enum", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    return {};
  });
  try {
    await assertRejects(
      () =>
        model.methods.upsertOpportunity.execute(
          {
            leadId: "offering-bad-2026",
            name: "Bad Offering",
            offering: "NOPE",
            closeDate: "",
            companyName: "",
            companyDomain: "",
            pointOfContactName: "",
            pointOfContactEmail: "",
            noteBody: "",
            confirm: true,
            dryRun: false,
          } as never,
          UPSERT_CTX as never,
        ),
      Error,
      "Invalid offering",
    );
    assertEquals(calls.some((c) => c.method === "POST"), false);
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity writes offering on the UPDATE (PATCH) path; empty => omitted", async () => {
  // First call: set offering on an existing opp. Second: empty offering => omit.
  for (
    const [val, expectPresent] of [["PROJECT", true], ["", false]] as Array<
      [string, boolean]
    >
  ) {
    const { calls, restore } = stubTwentyFetch((method, path) => {
      if (path.startsWith("/rest/metadata/objects")) return OPP_META;
      if (method === "GET" && path.startsWith("/rest/opportunities")) {
        return { data: { opportunities: [{ id: "opp1", stage: "PROPOSAL" }] } };
      }
      if (method === "PATCH") {
        return { data: { updateOpportunity: { id: "opp1" } } };
      }
      return {};
    });
    try {
      await model.methods.upsertOpportunity.execute(
        {
          leadId: "offering-update-2026",
          name: "Upd Offering",
          offering: val,
          closeDate: "",
          companyName: "",
          companyDomain: "",
          pointOfContactName: "",
          pointOfContactEmail: "",
          noteBody: "",
          confirm: true,
          dryRun: false,
        } as never,
        UPSERT_CTX as never,
      );
      const patch = calls.find((c) => c.method === "PATCH");
      assert(patch, "expected a PATCH");
      const body = patch!.body as Record<string, unknown>;
      assertEquals("offering" in body, expectPresent);
      if (expectPresent) assertEquals(body.offering, "PROJECT");
    } finally {
      restore();
    }
  }
});

Deno.test("upsertOpportunity: customFields.offering is rejected (reserved — typed arg is authoritative)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    return {};
  });
  try {
    await assertRejects(
      () =>
        model.methods.upsertOpportunity.execute(
          {
            leadId: "offering-reserved-2026",
            name: "Reserved Offering",
            offering: "SUBSTRATE",
            customFields: { offering: "PROJECT" },
            closeDate: "",
            companyName: "",
            companyDomain: "",
            pointOfContactName: "",
            pointOfContactEmail: "",
            noteBody: "",
            confirm: true,
            dryRun: false,
          } as never,
          UPSERT_CTX as never,
        ),
      Error,
      "reserved",
    );
    assertEquals(calls.some((c) => c.method === "POST"), false);
  } finally {
    restore();
  }
});

Deno.test("OpportunityUpsertSchema/OppViewSchema/OpportunityRefSchema round-trip offering (no strip)", () => {
  const u = OpportunityUpsertSchema.parse({
    baseUrl: "b",
    action: "created",
    dryRun: false,
    leadId: "L1",
    name: "X",
    stage: "NEW",
    offering: "MANAGED",
    companyLinked: false,
    noteEnsured: false,
    retrievedAt: "2026-09-16T00:00:00.000Z",
  });
  assertEquals(u.offering, "MANAGED");
  const v = OppViewSchema.parse({
    id: "o1",
    name: "X",
    stage: "NEW",
    offering: "PEERING",
  });
  assertEquals(v.offering, "PEERING");
  const r = OpportunityRefSchema.parse({
    baseUrl: "b",
    found: true,
    offering: "RETAINER",
    retrievedAt: "2026-09-16T00:00:00.000Z",
  });
  assertEquals(r.offering, "RETAINER");
});

// --- upsertOpportunity: channelPartner linking (TWENTY-OPP-CHANNEL) ----------

const CP_UUID = "11111111-1111-1111-1111-111111111111";

Deno.test("upsertOpportunity writes channelPartnerId (UUID) on create", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    if (method === "POST") {
      return { data: { createOpportunity: { id: "new1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "cp-id-2026",
        name: "Partner Deal",
        channelPartnerId: CP_UUID,
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        channelPartnerName: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a POST");
    assertEquals(
      (post!.body as Record<string, unknown>).channelPartnerId,
      CP_UUID,
    );
    // A UUID id must NOT trigger a channelPartners name lookup.
    assertEquals(
      calls.some((c) => c.path.startsWith("/rest/channelPartners")),
      false,
    );
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity rejects a non-UUID channelPartnerId pre-write (even dryRun)", async () => {
  const { calls, restore } = stubTwentyFetch(() => ({}));
  try {
    await assertRejects(
      () =>
        model.methods.upsertOpportunity.execute(
          {
            leadId: "cp-bad-2026",
            name: "Bad Partner",
            channelPartnerId: "not-a-uuid",
            closeDate: "",
            companyName: "",
            companyDomain: "",
            pointOfContactName: "",
            pointOfContactEmail: "",
            channelPartnerName: "",
            noteBody: "",
            confirm: false,
            dryRun: true,
          } as never,
          UPSERT_CTX as never,
        ),
      Error,
      "Invalid channelPartnerId",
    );
    // Fails before any I/O.
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity resolves channelPartnerName -> id (link-only)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/channelPartners")) {
      return { data: { channelPartners: [{ id: "cp-globex" }] } };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    if (method === "POST") {
      return { data: { createOpportunity: { id: "new1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "cp-name-2026",
        name: "Globex Deal",
        channelPartnerName: "Globex",
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a POST");
    assertEquals(
      (post!.body as Record<string, unknown>).channelPartnerId,
      "cp-globex",
    );
    // Queried the name filter.
    assert(
      calls.some((c) =>
        c.path.startsWith("/rest/channelPartners") &&
        c.path.includes("Globex")
      ),
    );
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity: channelPartnerName with no match => skipped, no link", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/channelPartners")) {
      return { data: { channelPartners: [] } }; // no match
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    if (method === "POST") {
      return { data: { createOpportunity: { id: "new1" } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "cp-miss-2026",
        name: "Unknown Partner",
        channelPartnerName: "Nonexistent",
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a POST");
    // No link written; a skip note recorded — never blind-creates a partner.
    assertEquals(
      "channelPartnerId" in (post!.body as Record<string, unknown>),
      false,
    );
    const snap = writes.find((w) => w.type === "opportunityUpsert");
    assert(snap, "expected snapshot");
    assert(
      String(snap!.data.channelPartnerSkipped ?? "").includes("no existing"),
    );
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity: channelPartnerId wins over channelPartnerName (no name lookup)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    if (method === "POST") {
      return { data: { createOpportunity: { id: "new1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "cp-both-2026",
        name: "Both Partner",
        channelPartnerId: CP_UUID,
        channelPartnerName: "Globex",
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const post = calls.find((c) => c.method === "POST");
    assertEquals(
      (post!.body as Record<string, unknown>).channelPartnerId,
      CP_UUID,
    );
    // channelPartnerId set => name resolver is never consulted.
    assertEquals(
      calls.some((c) => c.path.startsWith("/rest/channelPartners")),
      false,
    );
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity: customFields.channelPartnerId is rejected (reserved)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    return {};
  });
  try {
    await assertRejects(
      () =>
        model.methods.upsertOpportunity.execute(
          {
            leadId: "cp-reserved-2026",
            name: "Reserved CP",
            customFields: { channelPartnerId: CP_UUID },
            closeDate: "",
            companyName: "",
            companyDomain: "",
            pointOfContactName: "",
            pointOfContactEmail: "",
            channelPartnerName: "",
            noteBody: "",
            confirm: true,
            dryRun: false,
          } as never,
          UPSERT_CTX as never,
        ),
      Error,
      "reserved",
    );
    assertEquals(calls.some((c) => c.method === "POST"), false);
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity writes channelPartnerId on the UPDATE (PATCH) path", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [{ id: "opp1", stage: "PROPOSAL" }] } };
    }
    if (method === "PATCH") {
      return { data: { updateOpportunity: { id: "opp1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "cp-update-2026",
        name: "Partner Update",
        channelPartnerId: CP_UUID,
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        channelPartnerName: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH");
    assertEquals(
      (patch!.body as Record<string, unknown>).channelPartnerId,
      CP_UUID,
    );
  } finally {
    restore();
  }
});

Deno.test("upsertOpportunity: empty channelPartnerId/Name omitted from body (never nulled), update path", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return OPP_META;
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [{ id: "opp1", stage: "PROPOSAL" }] } };
    }
    if (method === "PATCH") {
      return { data: { updateOpportunity: { id: "opp1" } } };
    }
    return {};
  });
  try {
    await model.methods.upsertOpportunity.execute(
      {
        leadId: "cp-empty-2026",
        name: "Empty Partner",
        channelPartnerId: "",
        channelPartnerName: "",
        closeDate: "",
        companyName: "",
        companyDomain: "",
        pointOfContactName: "",
        pointOfContactEmail: "",
        noteBody: "",
        confirm: true,
        dryRun: false,
      } as never,
      UPSERT_CTX as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH");
    assertEquals(
      "channelPartnerId" in (patch!.body as Record<string, unknown>),
      false,
    );
    // Empty name => no channelPartners lookup either.
    assertEquals(
      calls.some((c) => c.path.startsWith("/rest/channelPartners")),
      false,
    );
  } finally {
    restore();
  }
});

Deno.test("OpportunityUpsertSchema/OppViewSchema/OpportunityRefSchema round-trip channelPartnerId (no strip)", () => {
  const u = OpportunityUpsertSchema.parse({
    baseUrl: "b",
    action: "created",
    dryRun: false,
    leadId: "L1",
    name: "X",
    stage: "NEW",
    channelPartnerId: CP_UUID,
    companyLinked: false,
    noteEnsured: false,
    retrievedAt: "2026-09-16T00:00:00.000Z",
  });
  assertEquals(u.channelPartnerId, CP_UUID);
  const v = OppViewSchema.parse({
    id: "o1",
    name: "X",
    stage: "NEW",
    channelPartnerId: CP_UUID,
  });
  assertEquals(v.channelPartnerId, CP_UUID);
  const r = OpportunityRefSchema.parse({
    baseUrl: "b",
    found: true,
    channelPartnerId: CP_UUID,
    retrievedAt: "2026-09-16T00:00:00.000Z",
  });
  assertEquals(r.channelPartnerId, CP_UUID);
});

// --- getNoteBody + listNotesByOpportunity (TWENTY-NOTE-BODY-READ) -----------

const NOTE_UUID = "22222222-2222-2222-2222-222222222222";
const OPP_UUID = "33333333-3333-3333-3333-333333333333";

Deno.test("getNoteBody refuses without confirm:true (SR-1 boundary, before any I/O)", async () => {
  const { calls, restore } = stubTwentyFetch(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.getNoteBody.execute(
          { noteId: NOTE_UUID, confirm: false } as never,
          ctx as never,
        ),
      Error,
      "confirm:true",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("getNoteBody rejects a non-UUID noteId (with confirm) before any I/O", async () => {
  const { calls, restore } = stubTwentyFetch(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.getNoteBody.execute(
          { noteId: "not-a-uuid", confirm: true } as never,
          ctx as never,
        ),
      Error,
      "Invalid noteId",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("getNoteBody returns the body + title (verbatim) on a hit", async () => {
  const { restore } = stubTwentyFetch((method, path) => {
    if (method === "GET" && path.startsWith("/rest/notes/")) {
      return {
        data: {
          note: {
            id: NOTE_UUID,
            leadId: "L1",
            title: "My private note",
            bodyV2: { markdown: "secret **body** text" },
            createdAt: "2026-09-01T00:00:00.000Z",
          },
        },
      };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.getNoteBody.execute(
      { noteId: NOTE_UUID, confirm: true } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "noteBodyRead");
    assert(snap, "expected a noteBodyRead snapshot");
    assertEquals(snap!.name, `note-body-${NOTE_UUID}`);
    assertEquals(snap!.data.found, true);
    assertEquals(snap!.data.body, "secret **body** text");
    // Title is verbatim here (the SR-1 listNotes title guard does NOT apply).
    assertEquals(snap!.data.title, "My private note");
    assertEquals(snap!.data.leadId, "L1");
    assertEquals("bodyMissing" in snap!.data, false);
  } finally {
    restore();
  }
});

Deno.test("getNoteBody: found but no markdown => bodyMissing, no body", async () => {
  const { restore } = stubTwentyFetch((method, path) => {
    if (method === "GET" && path.startsWith("/rest/notes/")) {
      return { data: { note: { id: NOTE_UUID, bodyV2: null } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.getNoteBody.execute(
      { noteId: NOTE_UUID, confirm: true } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "noteBodyRead");
    assert(snap, "expected snapshot");
    assertEquals(snap!.data.found, true);
    assertEquals(snap!.data.bodyMissing, true);
    assertEquals("body" in snap!.data, false);
  } finally {
    restore();
  }
});

Deno.test("getNoteBody: 404 => found:false, no body, no throw", async () => {
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/notes/")) {
      return { status: 404, body: { messages: ["not found"] } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.getNoteBody.execute(
      { noteId: NOTE_UUID, confirm: true } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "noteBodyRead");
    assert(snap, "expected snapshot");
    assertEquals(snap!.data.found, false);
    assertEquals("body" in snap!.data, false);
  } finally {
    restore();
  }
});

Deno.test("listNotesByOpportunity resolves noteTargets => body-free note views", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (method === "GET" && path.startsWith("/rest/noteTargets")) {
      return {
        data: {
          noteTargets: [
            { id: "nt1", noteId: "n1" },
            { id: "nt2", noteId: "n2" },
          ],
        },
        pageInfo: { hasNextPage: false },
      };
    }
    if (method === "GET" && path.startsWith("/rest/notes/n1")) {
      return {
        data: {
          note: {
            id: "n1",
            leadId: "L1",
            title: "Inbound lead L1",
            bodyV2: { markdown: "should NOT surface" },
          },
        },
      };
    }
    if (method === "GET" && path.startsWith("/rest/notes/n2")) {
      return { data: { note: { id: "n2", title: "hand-authored" } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listNotesByOpportunity.execute(
      { opportunityId: OPP_UUID, limit: 60 } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "noteList");
    assert(snap, "expected a noteList snapshot");
    assertEquals(snap!.name, `note-list-opp-${OPP_UUID}`);
    assertEquals(snap!.data.count, 2);
    const items = snap!.data.items as Array<Record<string, unknown>>;
    // Body-free (SR-1): no item carries a body.
    assert(items.every((it) => !("body" in it)));
    assertEquals(items.map((it) => it.id), ["n1", "n2"]);
    // mapNoteView title guard applies here: only the machine 'Inbound lead' title surfaces.
    assertEquals(items[0].title, "Inbound lead L1");
    assertEquals("title" in items[1], false);
    // Queried noteTargets by the opportunity FK.
    assert(
      calls.some((c) =>
        c.path.startsWith("/rest/noteTargets") &&
        c.path.includes("targetOpportunityId")
      ),
    );
  } finally {
    restore();
  }
});

Deno.test("listNotesByOpportunity rejects a non-UUID opportunityId before any I/O", async () => {
  const { calls, restore } = stubTwentyFetch(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.listNotesByOpportunity.execute(
          { opportunityId: "nope", limit: 60 } as never,
          ctx as never,
        ),
      Error,
      "Invalid opportunityId",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

// --- Read surface (TWENTY-READ-SURFACE) -------------------------------------

Deno.test("validateUuid accepts a UUID, rejects junk / path-injection", () => {
  assertEquals(
    validateUuid("11111111-1111-1111-1111-111111111111"),
    "11111111-1111-1111-1111-111111111111",
  );
  // Lowercased.
  assertEquals(
    validateUuid("ABCDEF01-2345-6789-ABCD-EF0123456789"),
    "abcdef01-2345-6789-abcd-ef0123456789",
  );
  for (
    const bad of ["", "not-a-uuid", "../people", "1/2", "x".repeat(36), null]
  ) {
    assertEquals(validateUuid(bad), null);
  }
});

Deno.test("amountFromMicros is the inverse of toCurrency", () => {
  assertEquals(amountFromMicros(50_000_000_000), 50000);
  assertAlmostEquals(amountFromMicros(42_000_000_000), 42000.00, 1e-6);
  // Round-trip.
  assertEquals(amountFromMicros(toCurrency(19.99, "USD").amountMicros), 19.99);
});

Deno.test("mapOppView extracts the compact view incl. micros->units", () => {
  const v = mapOppView({
    id: "opp1",
    leadId: "L1",
    name: "Acme Renewal",
    stage: "PROPOSAL",
    amount: { amountMicros: 42_000_000_000, currencyCode: "USD" },
    closeDate: "2026-12-31T00:00:00.000Z",
    companyId: "co1",
    pointOfContactId: "poc1",
    channelPartnerId: "cp1",
    lineOfBusiness: "HOSTING",
    sourceChannel: "REFERRAL",
    asn: "AS64496",
    qualStatus: "TECH_QUALIFICATION_NEEDED",
    offering: "SUBSTRATE",
    isEmergency: false,
  });
  assertEquals(v.id, "opp1");
  assertEquals(v.stage, "PROPOSAL");
  assertAlmostEquals(v.amount!, 42000.00, 1e-6);
  assertEquals(v.currencyCode, "USD");
  // Custom/segmentation SELECTs surfaced from flat scalars; isEmergency even when false.
  assertEquals(v.lineOfBusiness, "HOSTING");
  assertEquals(v.sourceChannel, "REFERRAL");
  assertEquals(v.asn, "AS64496");
  assertEquals(v.qualStatus, "TECH_QUALIFICATION_NEEDED");
  assertEquals(v.offering, "SUBSTRATE");
  assertEquals(v.channelPartnerId, "cp1");
  assertEquals(v.isEmergency, false);
  // A record with no amount composite omits amount/currencyCode; unset
  // segmentation SELECTs are omitted; absent isEmergency stays undefined.
  const bare = mapOppView({
    id: "opp2",
    name: "x",
    stage: "NEW",
    lineOfBusiness: "",
    sourceChannel: null,
    asn: "",
    qualStatus: null,
    offering: "",
  });
  assertEquals("amount" in bare, false);
  assertEquals("currencyCode" in bare, false);
  assertEquals("lineOfBusiness" in bare, false);
  assertEquals("sourceChannel" in bare, false);
  assertEquals("asn" in bare, false);
  assertEquals("qualStatus" in bare, false);
  assertEquals("offering" in bare, false);
  assertEquals("channelPartnerId" in bare, false);
  assertEquals("isEmergency" in bare, false);
});

Deno.test("titleCaseToken title-cases an option token", () => {
  assertEquals(titleCaseToken("CLOSED"), "Closed");
  assertEquals(titleCaseToken("CLOSED_WON"), "Closed Won");
  assertEquals(titleCaseToken("NEW"), "New");
});

// exactly-one refinements live on the arg schema (enforced before execute).
Deno.test("findPerson requires exactly one of email|leadId", () => {
  const s = model.methods.findPerson.arguments;
  assertEquals(s.safeParse({}).success, false);
  assertEquals(
    s.safeParse({ email: "a@b.com", leadId: "L1" }).success,
    false,
  );
  assertEquals(s.safeParse({ email: "a@b.com" }).success, true);
  assertEquals(s.safeParse({ leadId: "L1" }).success, true);
});

Deno.test("getOpportunity requires exactly one of leadId|id", () => {
  const s = model.methods.getOpportunity.arguments;
  assertEquals(s.safeParse({}).success, false);
  assertEquals(s.safeParse({ leadId: "L1", id: "x" }).success, false);
  assertEquals(s.safeParse({ leadId: "L1" }).success, true);
});

Deno.test("findCompany requires exactly one of domain|name", () => {
  const s = model.methods.findCompany.arguments;
  assertEquals(s.safeParse({}).success, false);
  assertEquals(
    s.safeParse({ domain: "a.com", name: "A" }).success,
    false,
  );
  assertEquals(s.safeParse({ domain: "a.com" }).success, true);
});

// A fetch stub that can return a chosen HTTP status (for 404 by-id paths) and
// records every call. `handler` returns { status?, body? }.
function stubFetchStatus(
  handler: (
    method: string,
    path: string,
    body: unknown,
  ) => { status?: number; body?: unknown } | undefined,
): {
  calls: Array<{ method: string; path: string; body: unknown }>;
  restore: () => void;
} {
  const calls: Array<{ method: string; path: string; body: unknown }> = [];
  const orig = globalThis.fetch;
  globalThis.fetch = ((url: string | URL, init?: RequestInit) => {
    const path = String(url).replace("https://crm.example.com", "");
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path, body });
    const r = handler(method, path, body) ?? {};
    const status = r.status ?? 200;
    const ok = status >= 200 && status < 300;
    return Promise.resolve(
      {
        ok,
        status,
        statusText: ok ? "OK" : "Error",
        text: () => Promise.resolve(JSON.stringify(r.body ?? {})),
      } as Response,
    );
  }) as typeof fetch;
  return { calls, restore: () => (globalThis.fetch = orig) };
}

function readCtx(): {
  writes: Array<{ type: string; name: string; data: Record<string, unknown> }>;
  ctx: unknown;
} {
  const writes: Array<
    { type: string; name: string; data: Record<string, unknown> }
  > = [];
  return {
    writes,
    ctx: {
      globalArgs: {
        baseUrl: "https://crm.example.com",
        apiToken: "tok",
        opportunityStage: "NEW",
        emailDomainBlocklist: [...DEFAULT_EMAIL_DOMAIN_BLOCKLIST],
        emergencyRestrictedRole: "",
      },
      logger: { debug() {}, info() {}, warning() {}, error() {} },
      writeResource: (
        type: string,
        name: string,
        data: Record<string, unknown>,
      ) => {
        writes.push({ type, name, data });
        return Promise.resolve({ name });
      },
    },
  };
}

Deno.test("findPerson by email: hit records found:true + id", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/people")) {
      return {
        body: {
          data: { people: [{ id: "p1", leadId: "L1", companyId: "c1" }] },
        },
      };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.findPerson.execute(
      { email: "ada@example.com" } as never,
      ctx as never,
    );
    assertEquals(writes[0].type, "personRef");
    assertEquals(writes[0].data.found, true);
    assertEquals(writes[0].data.id, "p1");
    assertEquals(writes[0].data.companyId, "c1");
    // Queried the email filter, URL-encoded.
    assert(
      calls.some((c) =>
        c.path.includes("emails.primaryEmail[eq]:ada%40example.com")
      ),
    );
  } finally {
    restore();
  }
});

Deno.test("findPerson by email: miss records found:false, no throw", async () => {
  const { restore } = stubFetchStatus(() => ({
    body: { data: { people: [] } },
  }));
  const { writes, ctx } = readCtx();
  try {
    await model.methods.findPerson.execute(
      { email: "absent@example.com" } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.found, false);
    assertEquals("id" in writes[0].data, false);
  } finally {
    restore();
  }
});

Deno.test("findPerson: ambiguous email throws with redacted PII", async () => {
  const { restore } = stubFetchStatus(() => ({
    body: { data: { people: [{ id: "a" }, { id: "b" }] } },
  }));
  const { ctx } = readCtx();
  try {
    const err = await assertRejects(
      () =>
        model.methods.findPerson.execute(
          { email: "dup@example.com" } as never,
          ctx as never,
        ),
      Error,
      "Ambiguous",
    );
    // Email is scrubbed from the surfaced error (RS-3).
    assert(!err.message.includes("dup@example.com"), err.message);
  } finally {
    restore();
  }
});

Deno.test("getPersonById: 404 records found:false", async () => {
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/people/")) {
      return { status: 404, body: { messages: ["not found"] } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.getPersonById.execute(
      { id: "11111111-1111-1111-1111-111111111111" } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.found, false);
  } finally {
    restore();
  }
});

Deno.test("getPersonById rejects a non-UUID id before any I/O", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.getPersonById.execute(
          { id: "../opportunities" } as never,
          ctx as never,
        ),
      Error,
      "Invalid person id",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("findCompany by domain: hit carries id/name/domain", async () => {
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/companies")) {
      return {
        body: {
          data: {
            companies: [{
              id: "co1",
              name: "Acme Corp",
              domainName: { primaryLinkUrl: "acme.com" },
            }],
          },
        },
      };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.findCompany.execute(
      { domain: "acme.com" } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.found, true);
    assertEquals(writes[0].data.id, "co1");
    assertEquals(writes[0].data.name, "Acme Corp");
    assertEquals(writes[0].data.domain, "acme.com");
  } finally {
    restore();
  }
});

Deno.test("findCompany by name: not filterable => found:false gracefully", async () => {
  // Simulate a non-filterable `name` field: the request errors, findOne* swallows
  // it and returns null rather than aborting.
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/companies")) {
      return { status: 400, body: { messages: ["name not filterable"] } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.findCompany.execute(
      { name: "Acme Corp" } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.found, false);
  } finally {
    restore();
  }
});

const ACME_OPP = {
  id: "opp-aap",
  leadId: "acme-q1-renewal-2026",
  name: "Acme Renewal",
  stage: "PROPOSAL",
  amount: { amountMicros: 42_000_000_000, currencyCode: "USD" },
  closeDate: "2026-12-31T00:00:00.000Z",
  companyId: "co1",
  pointOfContactId: "poc1",
};

Deno.test("getOpportunity by leadId: PROPOSAL + amount 42000.00", async () => {
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { body: { data: { opportunities: [ACME_OPP] } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.getOpportunity.execute(
      { leadId: "acme-q1-renewal-2026" } as never,
      ctx as never,
    );
    const d = writes[0].data;
    assertEquals(d.found, true);
    assertEquals(d.stage, "PROPOSAL");
    assertAlmostEquals(d.amount as number, 42000.00, 1e-6);
    assertEquals(d.currencyCode, "USD");
    assertEquals(d.pointOfContactId, "poc1");
  } finally {
    restore();
  }
});

Deno.test("getOpportunity by id: equivalent snapshot; 404 => found:false", async () => {
  const uuid = "22222222-2222-2222-2222-222222222222";
  {
    const { restore } = stubFetchStatus((method, path) => {
      if (method === "GET" && path === `/rest/opportunities/${uuid}`) {
        return { body: { data: { opportunity: ACME_OPP } } };
      }
      return {};
    });
    const { writes, ctx } = readCtx();
    try {
      await model.methods.getOpportunity.execute(
        { id: uuid } as never,
        ctx as never,
      );
      assertEquals(writes[0].data.found, true);
      assertEquals(writes[0].data.stage, "PROPOSAL");
    } finally {
      restore();
    }
  }
  {
    const { restore } = stubFetchStatus(() => ({
      status: 404,
      body: {},
    }));
    const { writes, ctx } = readCtx();
    try {
      await model.methods.getOpportunity.execute(
        { id: uuid } as never,
        ctx as never,
      );
      assertEquals(writes[0].data.found, false);
    } finally {
      restore();
    }
  }
});

Deno.test("listOpportunities: AND-composes filters and returns both Acme opps", async () => {
  const cid = "33333333-3333-3333-3333-333333333333";
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return {
        body: {
          data: {
            opportunities: [
              ACME_OPP,
              { id: "opp-sow", name: "SOW-001", stage: "CUSTOMER" },
            ],
          },
          pageInfo: { hasNextPage: false },
        },
      };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listOpportunities.execute(
      { companyId: cid, stage: "PROPOSAL", limit: 60 } as never,
      ctx as never,
    );
    // Single filter param, comma-joined AND clauses.
    const q = calls[0].path;
    assert(
      q.includes(`filter=companyId[eq]:${cid},stage[eq]:PROPOSAL`),
      q,
    );
    assertEquals(writes[0].data.count, 2);
    assertEquals(writes[0].data.truncated, false);
  } finally {
    restore();
  }
});

Deno.test("listOpportunities: pages past pageSize, then stops (hasNextPage:false)", async () => {
  const page1 = Array.from({ length: 60 }, (_, i) => ({
    id: `a${i}`,
    name: `n${i}`,
    stage: "NEW",
  }));
  const page2 = Array.from({ length: 5 }, (_, i) => ({
    id: `b${i}`,
    name: `m${i}`,
    stage: "NEW",
  }));
  const { calls, restore } = stubFetchStatus((_method, path) => {
    if (path.includes("starting_after=")) {
      return {
        body: {
          data: { opportunities: page2 },
          pageInfo: { hasNextPage: false },
        },
      };
    }
    return {
      body: {
        data: { opportunities: page1 },
        pageInfo: { hasNextPage: true, endCursor: "CURSOR1" },
      },
    };
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listOpportunities.execute(
      { limit: 200 } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.count, 65);
    assertEquals(writes[0].data.truncated, false);
    // Second page requested with the returned cursor.
    assert(calls.some((c) => c.path.includes("starting_after=CURSOR1")));
  } finally {
    restore();
  }
});

Deno.test("listOpportunities: soft cap rounds up to a whole page and flags truncated", async () => {
  // Whole-page capping: a full page (3 rows) is consumed even though limit=2,
  // and because more pages remain the call flags truncated with count=3 (the
  // soft floor rounded up to the page boundary — CR-A-1/CR-A-2).
  const { restore } = stubFetchStatus((_method, path) => {
    if (path.includes("starting_after=")) {
      return {
        body: {
          data: { opportunities: [{ id: "x4", name: "d", stage: "NEW" }] },
          pageInfo: { hasNextPage: false },
        },
      };
    }
    return {
      body: {
        data: {
          opportunities: [
            { id: "x1", name: "a", stage: "NEW" },
            { id: "x2", name: "b", stage: "NEW" },
            { id: "x3", name: "c", stage: "NEW" },
          ],
        },
        pageInfo: { hasNextPage: true, endCursor: "CURSOR1" },
      },
    };
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listOpportunities.execute(
      { limit: 2 } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.count, 3);
    assertEquals(writes[0].data.truncated, true);
  } finally {
    restore();
  }
});

Deno.test("listOpportunities: wrong cursor cannot infinite-loop (no-progress guard)", async () => {
  // Every page returns the SAME ids and always claims hasNextPage — a broken
  // cursor. The dedupe + no-progress guard must terminate after one useful page.
  let pages = 0;
  const { restore } = stubFetchStatus(() => {
    pages++;
    return {
      body: {
        data: {
          opportunities: [
            { id: "same1", name: "a", stage: "NEW" },
            { id: "same2", name: "b", stage: "NEW" },
          ],
        },
        pageInfo: { hasNextPage: true, endCursor: "STUCK" },
      },
    };
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listOpportunities.execute(
      { limit: 500 } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.count, 2);
    // Fetched page 1, then page 2 (all-seen => stop). Never runs away.
    assert(pages <= 2, `expected <=2 pages, got ${pages}`);
  } finally {
    restore();
  }
});

Deno.test("listOpportunities rejects a non-UUID companyId", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.listOpportunities.execute(
          { companyId: "not-a-uuid", limit: 60 } as never,
          ctx as never,
        ),
      Error,
      "Invalid companyId",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

// --- ensureStageOption (TWENTY-STAGE-OPTION) --------------------------------

const STAGE_OPTS = [
  { id: "o1", value: "NEW", label: "New", color: "blue", position: 0 },
  {
    id: "o2",
    value: "SCREENING",
    label: "Screening",
    color: "turquoise",
    position: 1,
  },
  { id: "o3", value: "MEETING", label: "Meeting", color: "sky", position: 2 },
  {
    id: "o4",
    value: "PROPOSAL",
    label: "Proposal",
    color: "purple",
    position: 3,
  },
  {
    id: "o5",
    value: "CUSTOMER",
    label: "Customer",
    color: "green",
    position: 4,
  },
];

function stageMeta(opts: unknown[] = STAGE_OPTS) {
  return {
    data: [{
      nameSingular: "opportunity",
      id: "obj1",
      fields: [{ name: "stage", id: "fld1", type: "SELECT", options: opts }],
    }],
  };
}

const STAGE_ARGS = {
  objectNameSingular: "opportunity",
  fieldName: "stage",
  color: "gray",
  confirm: false,
  dryRun: false,
};

Deno.test("ensureStageOption dryRun CLOSED: planned-create, no write, 5 preserved", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: stageMeta() };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureStageOption.execute(
      { ...STAGE_ARGS, value: "CLOSED", dryRun: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "planned-create");
    assert(
      !calls.some((c) => c.method === "PATCH"),
      "must not write on dryRun",
    );
    const opts = writes[0].data.options as Array<{ value: string }>;
    assertEquals(opts.length, 6);
    for (const v of ["NEW", "SCREENING", "MEETING", "PROPOSAL", "CUSTOMER"]) {
      assert(opts.some((o) => o.value === v), `missing ${v}`);
    }
    assert(opts.some((o) => o.value === "CLOSED"));
  } finally {
    restore();
  }
});

Deno.test("ensureStageOption confirm: PATCHes full array (options-only), 5 unchanged", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: stageMeta() };
    }
    if (method === "PATCH" && path === "/rest/metadata/fields/fld1") {
      return { body: { data: { updateField: { id: "fld1" } } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureStageOption.execute(
      { ...STAGE_ARGS, value: "CLOSED", confirm: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "created");
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH");
    const body = patch!.body as Record<string, unknown>;
    // Options-only body — no sibling attrs sent, so none can be clobbered.
    assertEquals(Object.keys(body), ["options"]);
    const opts = body.options as Array<
      { id?: string; value: string; label: string; color: string }
    >;
    assertEquals(opts.length, 6);
    // The 5 originals survive with the same ids/labels/colors.
    for (const orig of STAGE_OPTS) {
      const kept = opts.find((o) => o.value === orig.value);
      assert(kept, `dropped ${orig.value}`);
      assertEquals(kept!.id, orig.id);
      assertEquals(kept!.label, orig.label);
      assertEquals(kept!.color, orig.color);
    }
    const closed = opts.find((o) => o.value === "CLOSED");
    assertEquals(closed!.label, "Closed");
    assertEquals(closed!.color, "gray");
  } finally {
    restore();
  }
});

Deno.test("ensureStageOption re-run (value present): action present, no write", async () => {
  const withClosed = [...STAGE_OPTS, {
    id: "o6",
    value: "CLOSED",
    label: "Closed",
    color: "gray",
    position: 5,
  }];
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: stageMeta(withClosed) };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureStageOption.execute(
      { ...STAGE_ARGS, value: "CLOSED", confirm: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "present");
    assert(!calls.some((c) => c.method === "PATCH"));
    assertEquals("mismatchNote" in writes[0].data, false);
  } finally {
    restore();
  }
});

Deno.test("ensureStageOption present-with-mismatch: reports note, no mutation", async () => {
  const withClosed = [...STAGE_OPTS, {
    id: "o6",
    value: "CLOSED",
    label: "Done",
    color: "red",
    position: 5,
  }];
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: stageMeta(withClosed) };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureStageOption.execute(
      { ...STAGE_ARGS, value: "CLOSED", confirm: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "present");
    assert(String(writes[0].data.mismatchNote ?? "").includes("Done"));
    assert(!calls.some((c) => c.method === "PATCH"));
  } finally {
    restore();
  }
});

Deno.test("ensureStageOption reconcile: updates a drifted option in place, others preserved", async () => {
  const withClosed = [...STAGE_OPTS, {
    id: "o6",
    value: "CLOSED",
    label: "Done",
    color: "red",
    position: 5,
  }];
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: stageMeta(withClosed) };
    }
    if (method === "PATCH" && path === "/rest/metadata/fields/fld1") {
      return { body: { data: { updateField: { id: "fld1" } } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureStageOption.execute(
      {
        ...STAGE_ARGS,
        value: "CLOSED",
        label: "Closed",
        color: "gray",
        confirm: true,
        reconcile: true,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "updated");
    assertEquals("mismatchNote" in writes[0].data, false);
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH");
    const body = patch!.body as Record<string, unknown>;
    assertEquals(Object.keys(body), ["options"]); // options-only PATCH
    const opts = body.options as Array<
      { id?: string; value: string; label: string; color: string }
    >;
    assertEquals(opts.length, 6); // no add
    // The 5 originals survive verbatim.
    for (const orig of STAGE_OPTS) {
      const kept = opts.find((o) => o.value === orig.value);
      assert(kept, `dropped ${orig.value}`);
      assertEquals(kept!.id, orig.id);
      assertEquals(kept!.label, orig.label);
      assertEquals(kept!.color, orig.color);
    }
    // CLOSED reconciled in place: same id, new label+color.
    const closed = opts.find((o) => o.value === "CLOSED");
    assertEquals(closed!.id, "o6");
    assertEquals(closed!.label, "Closed");
    assertEquals(closed!.color, "gray");
  } finally {
    restore();
  }
});

Deno.test("ensureStageOption rejects a space/lowercase value before any I/O", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureStageOption.execute(
          { ...STAGE_ARGS, value: "clo sed", dryRun: true } as never,
          ctx as never,
        ),
      Error,
      "Invalid option value",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("ensureStageOption rejects an off-allowlist target before any I/O", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureStageOption.execute(
          {
            ...STAGE_ARGS,
            objectNameSingular: "person",
            fieldName: "status",
            value: "VIP",
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
      "allowlist",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("ensureStageOption rejects an invalid color before any I/O", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureStageOption.execute(
          {
            ...STAGE_ARGS,
            value: "CLOSED",
            color: "chartreuse",
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
      "Invalid color",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("ensureStageOption rejects MULTI_SELECT (SO-6, SELECT-only v1)", async () => {
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return {
        body: {
          data: [{
            nameSingular: "opportunity",
            id: "obj1",
            fields: [{
              name: "stage",
              id: "fld1",
              type: "MULTI_SELECT",
              options: STAGE_OPTS,
            }],
          }],
        },
      };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureStageOption.execute(
          { ...STAGE_ARGS, value: "CLOSED", confirm: true } as never,
          ctx as never,
        ),
      Error,
      "not SELECT",
    );
  } finally {
    restore();
  }
});

Deno.test("ensureStageOption HARD-stops on a lossy option (missing color) (SO-1)", async () => {
  const lossy = [
    { id: "o1", value: "NEW", label: "New", position: 0 }, // no color
  ];
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: stageMeta(lossy) };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureStageOption.execute(
          { ...STAGE_ARGS, value: "CLOSED", confirm: true } as never,
          ctx as never,
        ),
      Error,
      "lossy",
    );
    assert(!calls.some((c) => c.method === "PATCH"), "must not write");
  } finally {
    restore();
  }
});

Deno.test("ensureStageOption HARD-stops when the object is unreadable", async () => {
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: { data: [] } };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureStageOption.execute(
          { ...STAGE_ARGS, value: "CLOSED", confirm: true } as never,
          ctx as never,
        ),
      Error,
      "not found",
    );
  } finally {
    restore();
  }
});

Deno.test("ensureStageOption aborts on concurrent drift (SO-3)", async () => {
  let getCount = 0;
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      getCount++;
      // First read: 5 options. Second (pre-write) read: a drifted set.
      if (getCount === 1) return { body: stageMeta() };
      return { body: stageMeta(STAGE_OPTS.slice(0, 4)) };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureStageOption.execute(
          { ...STAGE_ARGS, value: "CLOSED", confirm: true } as never,
          ctx as never,
        ),
      Error,
      "changed between read and write",
    );
    assert(
      !calls.some((c) => c.method === "PATCH"),
      "must not write after drift",
    );
  } finally {
    restore();
  }
});

// --- removeSelectOption (TWENTY-OPTION-REMOVE) ------------------------------

const REMOVE_OPTS = [
  ...STAGE_OPTS,
  { id: "o6", value: "CLOSED", label: "Closed", color: "gray", position: 5 },
];

function selMeta(
  fieldName: string,
  opts: unknown[],
  defaultValue?: string,
): Record<string, unknown> {
  const field: Record<string, unknown> = {
    name: fieldName,
    id: "fld1",
    type: "SELECT",
    options: opts,
  };
  if (defaultValue !== undefined) field.defaultValue = defaultValue;
  return {
    data: [{ nameSingular: "opportunity", id: "obj1", fields: [field] }],
  };
}

const RM_ARGS = {
  objectNameSingular: "opportunity",
  fieldName: "stage",
  confirm: false,
  dryRun: true,
  force: false,
};

Deno.test("removeSelectOption dryRun: planned-remove, no write, survivors preserved", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: selMeta("stage", REMOVE_OPTS) };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { body: { totalCount: 0 } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.removeSelectOption.execute(
      { ...RM_ARGS, value: "CLOSED" } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "planned-remove");
    assertEquals(writes[0].data.refCount, 0);
    assert(
      !calls.some((c) => c.method === "PATCH"),
      "must not write on dryRun",
    );
    const opts = writes[0].data.options as Array<{ value: string }>;
    assertEquals(opts.length, 5);
    assert(!opts.some((o) => o.value === "CLOSED"), "CLOSED must be dropped");
    for (const v of ["NEW", "SCREENING", "MEETING", "PROPOSAL", "CUSTOMER"]) {
      assert(opts.some((o) => o.value === v), `dropped survivor ${v}`);
    }
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption confirm: options-only PATCH, survivors verbatim, target gone", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: selMeta("stage", REMOVE_OPTS) };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { body: { totalCount: 0 } };
    }
    if (method === "PATCH" && path === "/rest/metadata/fields/fld1") {
      return { body: { data: { updateField: { id: "fld1" } } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.removeSelectOption.execute(
      { ...RM_ARGS, value: "CLOSED", dryRun: false, confirm: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "removed");
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH");
    const body = patch!.body as Record<string, unknown>;
    assertEquals(Object.keys(body), ["options"]); // options-only
    const opts = body.options as Array<
      { id?: string; value: string; label: string; color: string }
    >;
    assertEquals(opts.length, 5);
    assert(!opts.some((o) => o.value === "CLOSED"), "CLOSED must be removed");
    for (const orig of STAGE_OPTS) {
      const kept = opts.find((o) => o.value === orig.value);
      assert(kept, `dropped survivor ${orig.value}`);
      assertEquals(kept!.id, orig.id); // id preserved verbatim
      assertEquals(kept!.label, orig.label);
      assertEquals(kept!.color, orig.color);
    }
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption absent value: idempotent no-op, no count, no write", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: selMeta("stage", REMOVE_OPTS) };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.removeSelectOption.execute(
      {
        ...RM_ARGS,
        value: "NONEXISTENT",
        dryRun: false,
        confirm: true,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "absent");
    assert(!calls.some((c) => c.method === "PATCH"));
    assert(
      !calls.some((c) => c.path.startsWith("/rest/opportunities")),
      "absent short-circuits before the count",
    );
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption refuses the field default (ADV-10 quote-stripped)", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      // Twenty returns the default as a quoted enum literal.
      return { body: selMeta("stage", REMOVE_OPTS, "'NEW'") };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.removeSelectOption.execute(
      { ...RM_ARGS, value: "NEW", dryRun: false, confirm: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "refused-default");
    assert(!calls.some((c) => c.method === "PATCH"));
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption refuses when the value is still in use (fail-closed)", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: selMeta("stage", REMOVE_OPTS) };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { body: { totalCount: 2 } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.removeSelectOption.execute(
      { ...RM_ARGS, value: "CLOSED", dryRun: false, confirm: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "refused-in-use");
    assertEquals(writes[0].data.refCount, 2);
    assert(
      !calls.some((c) => c.method === "PATCH"),
      "must not orphan a referenced option",
    );
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption refuses an untrusted (no-total) count", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: selMeta("stage", REMOVE_OPTS) };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { body: { data: [] } }; // no totalCount → untrusted
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.removeSelectOption.execute(
      { ...RM_ARGS, value: "CLOSED", dryRun: false, confirm: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "refused-untrusted-count");
    assertEquals(writes[0].data.countTrusted, false);
    assert(!calls.some((c) => c.method === "PATCH"));
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption re-count TOCTOU: races to in-use before the write", async () => {
  let oppCount = 0;
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: selMeta("stage", REMOVE_OPTS) };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      oppCount++;
      return { body: { totalCount: oppCount === 1 ? 0 : 1 } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.removeSelectOption.execute(
      { ...RM_ARGS, value: "CLOSED", dryRun: false, confirm: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "refused-in-use");
    assert(
      !calls.some((c) => c.method === "PATCH"),
      "re-count must block the write",
    );
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption aborts on concurrent option drift (strict check)", async () => {
  let getMeta = 0;
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      getMeta++;
      if (getMeta === 1) return { body: selMeta("stage", REMOVE_OPTS) };
      // pre-write re-read: a drifted set (an extra option appeared)
      return {
        body: selMeta("stage", [
          ...REMOVE_OPTS,
          {
            id: "o7",
            value: "EXTRA",
            label: "Extra",
            color: "gray",
            position: 6,
          },
        ]),
      };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { body: { totalCount: 0 } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.removeSelectOption.execute(
      { ...RM_ARGS, value: "CLOSED", dryRun: false, confirm: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "refused-drift");
    assert(
      !calls.some((c) => c.method === "PATCH"),
      "must not write after drift",
    );
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption force: removes an in-use option with a matching ack", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: selMeta("stage", REMOVE_OPTS) };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { body: { totalCount: 3 } };
    }
    if (method === "PATCH" && path === "/rest/metadata/fields/fld1") {
      return { body: { data: { updateField: { id: "fld1" } } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.removeSelectOption.execute(
      {
        ...RM_ARGS,
        value: "CLOSED",
        dryRun: false,
        confirm: true,
        force: true,
        expectedInUseCount: 3,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "removed");
    assertEquals(writes[0].data.forced, true);
    assert(calls.some((c) => c.method === "PATCH"), "force+ack should write");
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption force: aborts on a mismatched expectedInUseCount", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: selMeta("stage", REMOVE_OPTS) };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { body: { totalCount: 3 } };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.removeSelectOption.execute(
          {
            ...RM_ARGS,
            value: "CLOSED",
            dryRun: false,
            confirm: true,
            force: true,
            expectedInUseCount: 1,
          } as never,
          ctx as never,
        ),
      Error,
      "expectedInUseCount",
    );
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption rejects an off-allowlist target before any I/O", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.removeSelectOption.execute(
          { ...RM_ARGS, fieldName: "amount", value: "CLOSED" } as never,
          ctx as never,
        ),
      Error,
      "not on the removeSelectOption allowlist",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption allows the custom offering SELECT (allowlisted)", async () => {
  const OFFERING = [
    {
      id: "f1",
      value: "MANAGED_IT",
      label: "Managed IT",
      color: "blue",
      position: 0,
    },
    {
      id: "f2",
      value: "LEGACY_X",
      label: "Legacy X",
      color: "gray",
      position: 1,
    },
  ];
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: selMeta("offering", OFFERING) };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { body: { totalCount: 0 } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.removeSelectOption.execute(
      { ...RM_ARGS, fieldName: "offering", value: "LEGACY_X" } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "planned-remove");
    assert(!calls.some((c) => c.method === "PATCH"));
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption rejects a non-UPPER_SNAKE value before any I/O", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.removeSelectOption.execute(
          { ...RM_ARGS, value: "not snake" } as never,
          ctx as never,
        ),
      Error,
      "UPPER_SNAKE",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption refuses a real write without confirm", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.removeSelectOption.execute(
          {
            ...RM_ARGS,
            value: "CLOSED",
            dryRun: false,
            confirm: false,
          } as never,
          ctx as never,
        ),
      Error,
      "confirm",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption count applies the field[eq]:value filter with limit=1 (CR-3 positive control)", async () => {
  const cases: Array<[string, unknown[], string]> = [
    ["stage", REMOVE_OPTS, "CLOSED"],
    ["offering", [
      {
        id: "f1",
        value: "LEGACY_X",
        label: "Legacy X",
        color: "gray",
        position: 0,
      },
      { id: "f2", value: "KEEP", label: "Keep", color: "blue", position: 1 },
    ], "LEGACY_X"],
  ];
  for (const [fieldName, opts, value] of cases) {
    const { calls, restore } = stubFetchStatus((method, path) => {
      if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
        return { body: selMeta(fieldName, opts) };
      }
      if (method === "GET" && path.startsWith("/rest/opportunities")) {
        return { body: { totalCount: 0 } };
      }
      return {};
    });
    const { ctx } = readCtx();
    try {
      await model.methods.removeSelectOption.execute(
        { ...RM_ARGS, fieldName, value } as never,
        ctx as never,
      );
      const countGet = calls.find((c) =>
        c.method === "GET" && c.path.startsWith("/rest/opportunities")
      );
      assert(countGet, `expected a count GET for ${fieldName}`);
      // The count MUST filter on the target field/value — not count all opps.
      assert(
        countGet!.path.includes(`${fieldName}[eq]:${value}`),
        `count filter must target ${fieldName}[eq]:${value}; got ${
          countGet!.path
        }`,
      );
      assert(countGet!.path.includes("limit=1"), "count must use limit=1");
    } finally {
      restore();
    }
  }
});

Deno.test("removeSelectOption force: aborts when the re-count drifts from the ack at write (CR-4)", async () => {
  let opp = 0;
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: selMeta("stage", REMOVE_OPTS) };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      opp++;
      return { body: { totalCount: opp === 1 ? 3 : 2 } }; // drifts before the write
    }
    if (method === "PATCH") {
      return { body: { data: { updateField: { id: "fld1" } } } };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.removeSelectOption.execute(
          {
            ...RM_ARGS,
            value: "CLOSED",
            dryRun: false,
            confirm: true,
            force: true,
            expectedInUseCount: 3,
          } as never,
          ctx as never,
        ),
      Error,
      "changed",
    );
    assert(
      !calls.some((c) => c.method === "PATCH"),
      "must not write after re-count drift",
    );
  } finally {
    restore();
  }
});

Deno.test("removeSelectOption audit honesty: forced=false on non-force removal; false-audit on absent (CR-1/CR-2)", async () => {
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: selMeta("stage", REMOVE_OPTS) };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { body: { totalCount: 0 } };
    }
    if (method === "PATCH") {
      return { body: { data: { updateField: { id: "fld1" } } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.removeSelectOption.execute(
      { ...RM_ARGS, value: "CLOSED", dryRun: false, confirm: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "removed");
    assertEquals(writes[0].data.forced, false); // non-force removal
    await model.methods.removeSelectOption.execute(
      { ...RM_ARGS, value: "NONEXISTENT" } as never,
      ctx as never,
    );
    assertEquals(writes[1].data.action, "absent");
    assertEquals(writes[1].data.countTrusted, false); // no count ran
    assertEquals(writes[1].data.emergencyReadReliable, false);
    assertEquals(writes[1].data.forced, false);
  } finally {
    restore();
  }
});

// --- upsertPerson (TWENTY-PERSON-UPSERT) ------------------------------------

const PERSON_ARGS = {
  companyDomain: "",
  companyName: "",
  confirm: false,
  dryRun: false,
};

Deno.test("upsertPerson refuses a real run without confirm:true", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertPerson.execute(
          { ...PERSON_ARGS, email: "a@corp.com" } as never,
          ctx as never,
        ),
      Error,
      "confirm:true",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("upsertPerson dryRun create: planned-create, no write", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/people")) {
      return { body: { data: { people: [] } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.upsertPerson.execute(
      {
        ...PERSON_ARGS,
        email: "new@corp.com",
        firstName: "Ada",
        lastName: "Lovelace",
        phone: "781-555-0100",
        jobTitle: "CTO",
        dryRun: true,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "planned-create");
    assert(!calls.some((c) => c.method === "POST" || c.method === "PATCH"));
    const fs = writes[0].data.fieldsSet as string[];
    for (const f of ["name", "phone", "jobTitle"]) assert(fs.includes(f), f);
  } finally {
    restore();
  }
});

Deno.test("upsertPerson create: POSTs email+name+fields, NO leadId stamped", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/people")) {
      return { body: { data: { people: [] } } };
    }
    if (method === "POST" && path === "/rest/people") {
      return { body: { data: { createPerson: { id: "p1" } } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.upsertPerson.execute(
      {
        ...PERSON_ARGS,
        email: "ada@corp.com",
        firstName: "Ada",
        lastName: "Lovelace",
        phone: "781-555-0100",
        jobTitle: "CTO",
        confirm: true,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "created");
    assertEquals(writes[0].data.personId, "p1");
    const post = calls.find((c) => c.method === "POST");
    const body = post!.body as Record<string, unknown>;
    assertEquals(
      (body.emails as Record<string, unknown>).primaryEmail,
      "ada@corp.com",
    );
    assertEquals(body.name, { firstName: "Ada", lastName: "Lovelace" });
    assertEquals(body.jobTitle, "CTO");
    assertEquals(
      (body.phones as Record<string, unknown>).primaryPhoneNumber,
      "+17815550100",
    );
    // Curated contacts NEVER enter the leadId namespace.
    assertEquals("leadId" in body, false);
  } finally {
    restore();
  }
});

Deno.test("upsertPerson update jobTitle only: PATCH omits name/phone (PU-2)", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/people")) {
      return {
        body: {
          data: {
            people: [{
              id: "p1",
              name: { firstName: "Ada", lastName: "Lovelace" },
            }],
          },
        },
      };
    }
    if (method === "PATCH" && path === "/rest/people/p1") {
      return { body: { data: { updatePerson: { id: "p1" } } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.upsertPerson.execute(
      {
        ...PERSON_ARGS,
        email: "ada@corp.com",
        jobTitle: "VP Eng",
        confirm: true,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "updated");
    const patch = calls.find((c) => c.method === "PATCH");
    const body = patch!.body as Record<string, unknown>;
    assertEquals(body.jobTitle, "VP Eng");
    assertEquals("name" in body, false);
    assertEquals("phones" in body, false);
    assertEquals(writes[0].data.fieldsSet, ["jobTitle"]);
  } finally {
    restore();
  }
});

Deno.test("upsertPerson update firstName only: merges existing lastName (PU-2)", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/people")) {
      return {
        body: {
          data: {
            people: [{
              id: "p1",
              name: { firstName: "Ada", lastName: "Lovelace" },
            }],
          },
        },
      };
    }
    if (method === "PATCH") {
      return { body: { data: { updatePerson: { id: "p1" } } } };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    await model.methods.upsertPerson.execute(
      {
        ...PERSON_ARGS,
        email: "ada@corp.com",
        firstName: "Augusta",
        confirm: true,
      } as never,
      ctx as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    const body = patch!.body as Record<string, unknown>;
    // firstName updated, lastName preserved from the existing record.
    assertEquals(body.name, { firstName: "Augusta", lastName: "Lovelace" });
  } finally {
    restore();
  }
});

Deno.test("upsertPerson: companyDomain absent => creates + links company", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/people")) {
      return { body: { data: { people: [] } } };
    }
    if (method === "GET" && path.startsWith("/rest/companies")) {
      return { body: { data: { companies: [] } } };
    }
    if (method === "POST" && path === "/rest/companies") {
      return { body: { data: { createCompany: { id: "co9" } } } };
    }
    if (method === "POST" && path === "/rest/people") {
      return { body: { data: { createPerson: { id: "p2" } } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.upsertPerson.execute(
      {
        ...PERSON_ARGS,
        email: "sue@corp.com",
        companyDomain: "corp.com",
        confirm: true,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.companyLinked, true);
    assertEquals(writes[0].data.companyId, "co9");
    const post = calls.find((c) =>
      c.method === "POST" && c.path === "/rest/people"
    );
    assertEquals((post!.body as Record<string, unknown>).companyId, "co9");
  } finally {
    restore();
  }
});

Deno.test("upsertPerson: name-only company miss => unlinked + companyNote", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/people")) {
      return { body: { data: { people: [] } } };
    }
    if (method === "GET" && path.startsWith("/rest/companies")) {
      return { body: { data: { companies: [] } } };
    }
    if (method === "POST" && path === "/rest/people") {
      return { body: { data: { createPerson: { id: "p3" } } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.upsertPerson.execute(
      {
        ...PERSON_ARGS,
        email: "sue@corp.com",
        companyName: "Acme Inc",
        confirm: true,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.companyLinked, false);
    assert(String(writes[0].data.companyNote ?? "").includes("name-only"));
    // A company is NEVER blind-created from a name.
    assert(
      !calls.some((c) => c.method === "POST" && c.path === "/rest/companies"),
    );
  } finally {
    restore();
  }
});

Deno.test("upsertPerson: bad phone => person still created without phone", async () => {
  const { calls, restore } = stubFetchStatus((method, path, body) => {
    if (method === "GET" && path.startsWith("/rest/people")) {
      return { body: { data: { people: [] } } };
    }
    if (method === "POST" && path === "/rest/people") {
      // First attempt carries phones and is rejected; retry without it succeeds.
      if ((body as Record<string, unknown>)?.phones) {
        return { status: 400, body: { messages: ["phone number is invalid"] } };
      }
      return { body: { data: { createPerson: { id: "p4" } } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.upsertPerson.execute(
      {
        ...PERSON_ARGS,
        email: "x@corp.com",
        firstName: "X",
        phone: "+123",
        confirm: true,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "created");
    assertEquals(writes[0].data.personId, "p4");
    const posts = calls.filter((c) =>
      c.method === "POST" && c.path === "/rest/people"
    );
    assertEquals(posts.length, 2);
    // The successful (second) POST dropped phones but kept the name.
    const ok = posts[1].body as Record<string, unknown>;
    assertEquals("phones" in ok, false);
    assertEquals(ok.name, { firstName: "X", lastName: "" });
    // fieldsSet must report what was ACTUALLY written — phone was dropped, so it
    // must NOT be listed (the snapshot can't claim a phone it didn't store).
    assertEquals(
      (writes[0].data.fieldsSet as string[]).includes("phone"),
      false,
    );
    assert((writes[0].data.fieldsSet as string[]).includes("name"));
  } finally {
    restore();
  }
});

Deno.test("upsertPerson: single-token name on UPDATE preserves existing firstName (PU-2)", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/people")) {
      return {
        body: {
          data: {
            people: [{
              id: "p9",
              name: { firstName: "Robert", lastName: "Smith" },
            }],
          },
        },
      };
    }
    if (method === "PATCH") {
      return { body: { data: { updatePerson: { id: "p9" } } } };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    // A display-name-only integration sends name:"Bono" (splitName => firstName:"").
    await model.methods.upsertPerson.execute(
      {
        ...PERSON_ARGS,
        email: "r@corp.com",
        name: "Bono",
        confirm: true,
      } as never,
      ctx as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    const body = patch!.body as Record<string, unknown>;
    // firstName must NOT be nulled — the empty split half falls back to existing.
    assertEquals(body.name, { firstName: "Robert", lastName: "Bono" });
  } finally {
    restore();
  }
});

Deno.test("ensureStageOption HARD-stops on an option missing its id (SO-1)", async () => {
  const noId = [
    { value: "NEW", label: "New", color: "blue", position: 0 }, // no id
  ];
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: stageMeta(noId) };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureStageOption.execute(
          { ...STAGE_ARGS, value: "CLOSED", confirm: true } as never,
          ctx as never,
        ),
      Error,
      "missing id",
    );
    assert(!calls.some((c) => c.method === "PATCH"), "must not write");
  } finally {
    restore();
  }
});

Deno.test("upsertPerson: create->conflict->refind->update converges (PU-1)", async () => {
  let peopleGets = 0;
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/people")) {
      peopleGets++;
      // First lookup: absent. Post-conflict refind: a racing create landed.
      if (peopleGets === 1) return { body: { data: { people: [] } } };
      return {
        body: {
          data: {
            people: [{ id: "praced", name: { firstName: "", lastName: "" } }],
          },
        },
      };
    }
    if (method === "POST" && path === "/rest/people") {
      return { status: 409, body: { messages: ["duplicate"] } };
    }
    if (method === "PATCH" && path === "/rest/people/praced") {
      return { body: { data: { updatePerson: { id: "praced" } } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.upsertPerson.execute(
      {
        ...PERSON_ARGS,
        email: "race@corp.com",
        jobTitle: "Eng",
        confirm: true,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "updated");
    assertEquals(writes[0].data.personId, "praced");
    assert(
      calls.some((c) =>
        c.method === "PATCH" && c.path === "/rest/people/praced"
      ),
    );
  } finally {
    restore();
  }
});

Deno.test("upsertPerson: ambiguous email throws with redacted PII (PU-5)", async () => {
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/people")) {
      return { body: { data: { people: [{ id: "a" }, { id: "b" }] } } };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    const err = await assertRejects(
      () =>
        model.methods.upsertPerson.execute(
          { ...PERSON_ARGS, email: "dup@corp.com", confirm: true } as never,
          ctx as never,
        ),
      Error,
      "Ambiguous",
    );
    assert(!err.message.includes("dup@corp.com"), err.message);
  } finally {
    restore();
  }
});

// --- TWENTY-SNAPSHOT-READS: bulk-list reads ---------------------------------

const LF_CFG = { baseUrl: "https://crm.example.com", apiToken: "tok" };

// Serve a scripted sequence of REST pages keyed by the starting_after cursor:
// page 0 is served with no cursor; a request carrying starting_after=<endCursor
// of page n> serves page n+1. Attaches totalCount when provided.
function servePages(
  plural: string,
  pages: Array<
    {
      items: Array<Record<string, unknown>>;
      endCursor?: string;
      hasNextPage: boolean;
    }
  >,
  totalCount?: number,
) {
  return stubFetchStatus((_method, path) => {
    const m = path.match(/starting_after=([^&]+)/);
    let idx = 0;
    if (m) {
      const cur = decodeURIComponent(m[1]);
      idx = pages.findIndex((p) => p.endCursor === cur) + 1;
    }
    const pg = pages[idx] ?? { items: [], hasNextPage: false };
    const body: Record<string, unknown> = {
      data: { [plural]: pg.items },
      pageInfo: { hasNextPage: pg.hasNextPage, endCursor: pg.endCursor },
    };
    if (totalCount !== undefined) body.totalCount = totalCount;
    return { body };
  });
}

Deno.test("listFiltered pages + continues, dedups by id, reconciles => complete", async () => {
  const { restore } = servePages(
    "people",
    [
      { items: [{ id: "a" }, { id: "b" }], endCursor: "c0", hasNextPage: true },
      // 'b' repeats across the page boundary — must be deduped, not counted.
      {
        items: [{ id: "b" }, { id: "c" }],
        endCursor: "c1",
        hasNextPage: false,
      },
    ],
    3,
  );
  try {
    const p = await listFiltered(LF_CFG, "people", [], 60, "createdAt,id");
    assertEquals(p.items.map((r) => r.id), ["a", "b", "c"]);
    assertEquals(p.totalCount, 3);
    assertEquals(p.stopReason, "complete");
    assertEquals(p.incomplete, false);
    assertEquals(p.truncated, false);
    assertEquals(p.hasMore, false);
    assertEquals(p.nextCursor, undefined);
  } finally {
    restore();
  }
});

Deno.test("listFiltered cap-reached => whole page, truncated + hasMore + boundary nextCursor, NOT incomplete", async () => {
  const { restore } = servePages(
    "people",
    [
      { items: [{ id: "a" }, { id: "b" }], endCursor: "c0", hasNextPage: true },
      { items: [{ id: "c" }, { id: "d" }], endCursor: "c1", hasNextPage: true },
    ],
    99,
  );
  try {
    const p = await listFiltered(LF_CFG, "people", [], 2, "createdAt,id");
    assertEquals(p.items.length, 2);
    assertEquals(p.truncated, true);
    assertEquals(p.hasMore, true);
    // nextCursor is the endCursor of the LAST fully-fetched page (a boundary).
    assertEquals(p.nextCursor, "c0");
    assertEquals(p.stopReason, "cap-reached");
    // Continuation is available => NOT incomplete (CR-A-3).
    assertEquals(p.incomplete, false);
  } finally {
    restore();
  }
});

// Serve scripted metadata pages: /rest/metadata/objects returns `data` as a
// FLAT object array (not `{[plural]: items}` like record lists) plus a top-level
// pageInfo. page 0 has no cursor; starting_after=<endCursor of page n> => page n+1.
// `omitPageInfo` models an instance that does not paginate metadata at all.
function serveMetaPages(
  pages: Array<
    {
      objects: Array<Record<string, unknown>>;
      endCursor?: string;
      hasNextPage: boolean;
    }
  >,
  omitPageInfo = false,
) {
  return stubFetchStatus((_method, path) => {
    const m = path.match(/starting_after=([^&]+)/);
    let idx = 0;
    if (m) {
      const cur = decodeURIComponent(m[1]);
      idx = pages.findIndex((p) => p.endCursor === cur) + 1;
    }
    const pg = pages[idx] ?? { objects: [], hasNextPage: false };
    const body: Record<string, unknown> = { data: pg.objects };
    if (!omitPageInfo) {
      body.pageInfo = { hasNextPage: pg.hasNextPage, endCursor: pg.endCursor };
    }
    return { body };
  });
}

Deno.test("fetchObjectsMeta assembles ALL metadata pages, deduped by id", async () => {
  const { calls, restore } = serveMetaPages([
    {
      objects: [{ id: "o1", nameSingular: "person" }, {
        id: "o2",
        nameSingular: "company",
      }],
      endCursor: "m0",
      hasNextPage: true,
    },
    // 'o2' repeats across the boundary — must be deduped, not double-counted.
    {
      objects: [{ id: "o2", nameSingular: "company" }, {
        id: "o3",
        nameSingular: "opportunity",
      }],
      endCursor: "m1",
      hasNextPage: false,
    },
  ]);
  try {
    const objs = await fetchObjectsMeta(LF_CFG);
    assertEquals(objs.map((o) => o.nameSingular), [
      "person",
      "company",
      "opportunity",
    ]);
    // Two pages fetched (page 0 + the continuation).
    assertEquals(calls.length, 2);
    // The continuation carried the first page's endCursor.
    assert(calls[1].path.includes("starting_after=m0"));
  } finally {
    restore();
  }
});

Deno.test("fetchObjectsMeta single page (no pageInfo) => one GET, no regression", async () => {
  const { calls, restore } = serveMetaPages(
    [{
      objects: [{ id: "o1", nameSingular: "person" }],
      hasNextPage: false,
    }],
    true, // omit pageInfo entirely — the pre-pagination server shape
  );
  try {
    const objs = await fetchObjectsMeta(LF_CFG);
    assertEquals(objs.map((o) => o.nameSingular), ["person"]);
    assertEquals(calls.length, 1);
  } finally {
    restore();
  }
});

Deno.test("fetchObjectsMeta stops on a repeated cursor (no infinite loop)", async () => {
  const { calls, restore } = serveMetaPages([
    { objects: [{ id: "o1" }], endCursor: "same", hasNextPage: true },
    { objects: [{ id: "o2" }], endCursor: "same", hasNextPage: true },
  ]);
  try {
    const objs = await fetchObjectsMeta(LF_CFG);
    // page 0 consumed; page 1 fetched but its repeated cursor halts advance.
    assertEquals(objs.map((o) => o.id), ["o1", "o2"]);
    assertEquals(calls.length, 2);
  } finally {
    restore();
  }
});

Deno.test("listFiltered cursor-repeat guard => incomplete + cursor-repeat", async () => {
  const { restore } = servePages("people", [
    { items: [{ id: "a" }], endCursor: "same", hasNextPage: true },
    { items: [{ id: "b" }], endCursor: "same", hasNextPage: true },
  ]);
  try {
    const p = await listFiltered(LF_CFG, "people", [], 60, "createdAt,id");
    assertEquals(p.stopReason, "cursor-repeat");
    assertEquals(p.incomplete, true);
    assertEquals(p.hasMore, false);
    assertEquals(p.nextCursor, undefined);
  } finally {
    restore();
  }
});

Deno.test("listFiltered no-progress guard (all dup ids) => incomplete + no-progress", async () => {
  const { restore } = servePages("people", [
    { items: [{ id: "a" }, { id: "b" }], endCursor: "c0", hasNextPage: true },
    { items: [{ id: "a" }, { id: "b" }], endCursor: "c1", hasNextPage: true },
  ]);
  try {
    const p = await listFiltered(LF_CFG, "people", [], 60, "createdAt,id");
    assertEquals(p.stopReason, "no-progress");
    assertEquals(p.incomplete, true);
  } finally {
    restore();
  }
});

Deno.test("listFiltered max-pages backstop => continuable (hasMore + nextCursor), NOT incomplete (CR-A-6)", async () => {
  const { restore } = servePages("people", [
    { items: [{ id: "a" }], endCursor: "c0", hasNextPage: true },
    { items: [{ id: "b" }], endCursor: "c1", hasNextPage: true },
    { items: [{ id: "c" }], endCursor: "c2", hasNextPage: true },
    { items: [{ id: "d" }], endCursor: "c3", hasNextPage: true },
  ]);
  try {
    // cap 60 => maxPages = ceil(60/60)+2 = 3 iterations before the backstop.
    const p = await listFiltered(LF_CFG, "people", [], 60, "createdAt,id");
    assertEquals(p.stopReason, "max-pages");
    // Cursor is a consumed page boundary => don't strand the workflow (CR-A-6).
    assertEquals(p.hasMore, true);
    assertEquals(p.nextCursor, "c2");
    assertEquals(p.incomplete, false);
  } finally {
    restore();
  }
});

Deno.test("listFiltered clean end but missing totalCount => no-total (never 'complete')", async () => {
  const { restore } = servePages("people", [
    { items: [{ id: "a" }, { id: "b" }], hasNextPage: false },
  ]); // no totalCount
  try {
    const p = await listFiltered(LF_CFG, "people", [], 60, "createdAt,id");
    assertEquals(p.stopReason, "no-total");
    assertEquals(p.incomplete, true);
  } finally {
    restore();
  }
});

Deno.test("listFiltered clean end but count != totalCount => count-mismatch", async () => {
  const { restore } = servePages(
    "people",
    [{ items: [{ id: "a" }, { id: "b" }], hasNextPage: false }],
    99,
  );
  try {
    const p = await listFiltered(LF_CFG, "people", [], 60, "createdAt,id");
    assertEquals(p.stopReason, "count-mismatch");
    assertEquals(p.incomplete, true);
  } finally {
    restore();
  }
});

Deno.test("listFiltered sends order_by=createdAt,id + filter + starting_after passthrough", async () => {
  const { calls, restore } = servePages(
    "people",
    [{ items: [{ id: "a" }], hasNextPage: false }],
    1,
  );
  try {
    await listFiltered(
      LF_CFG,
      "people",
      ["leadId[eq]:L1"],
      60,
      "createdAt,id",
      "CUR",
    );
    const path = calls[0].path;
    assert(path.includes("order_by=createdAt,id"), path);
    assert(path.includes("filter=leadId[eq]:L1"), path);
    assert(path.includes("starting_after=CUR"), path);
  } finally {
    restore();
  }
});

// --- CR-A: whole-page capping correctness (these FAIL on mid-page slicing) ---

Deno.test("CR-A-1: cap not a page multiple, chained across two calls => NO duplicate ids", async () => {
  // Pages of 2; cap 3 is not a multiple of the page size. Whole-page capping
  // must hand back a boundary cursor so call 2 does not re-emit a sliced row.
  const pages = [
    { items: [{ id: "a" }, { id: "b" }], endCursor: "c0", hasNextPage: true },
    { items: [{ id: "c" }, { id: "d" }], endCursor: "c1", hasNextPage: true },
    { items: [{ id: "e" }, { id: "f" }], endCursor: "c2", hasNextPage: false },
  ];
  const { restore } = servePages("people", pages, 6);
  try {
    const call1 = await listFiltered(LF_CFG, "people", [], 3, "createdAt,id");
    assertEquals(call1.stopReason, "cap-reached");
    assert(call1.hasMore);
    assert(call1.nextCursor !== undefined);
    const call2 = await listFiltered(
      LF_CFG,
      "people",
      [],
      3,
      "createdAt,id",
      call1.nextCursor,
    );
    const union = [
      ...call1.items.map((r) => String(r.id)),
      ...call2.items.map((r) => String(r.id)),
    ];
    assertEquals(new Set(union).size, union.length); // no duplicate ids
    assertEquals(new Set(union), new Set(["a", "b", "c", "d", "e", "f"]));
  } finally {
    restore();
  }
});

Deno.test("CR-A-2: limit < page size with more rows on page 0, chained => NO skipped row", async () => {
  const pages = [
    { items: [{ id: "a" }, { id: "b" }], endCursor: "c0", hasNextPage: true },
    { items: [{ id: "c" }, { id: "d" }], endCursor: "c1", hasNextPage: false },
  ];
  const { restore } = servePages("people", pages, 4);
  try {
    const call1 = await listFiltered(LF_CFG, "people", [], 1, "createdAt,id");
    // Sub-page cap returns the FIRST FULL page (both a and b), then stops.
    assertEquals(call1.items.map((r) => String(r.id)), ["a", "b"]);
    assertEquals(call1.stopReason, "cap-reached");
    assert(call1.hasMore);
    const call2 = await listFiltered(
      LF_CFG,
      "people",
      [],
      1,
      "createdAt,id",
      call1.nextCursor,
    );
    const union = [
      ...call1.items.map((r) => String(r.id)),
      ...call2.items.map((r) => String(r.id)),
    ];
    // Every row is present exactly once — nothing skipped.
    assertEquals(new Set(union), new Set(["a", "b", "c", "d"]));
    assertEquals(new Set(union).size, union.length);
  } finally {
    restore();
  }
});

Deno.test("CR-A-3: continuation call reaching hasNextPage=false => complete + NOT incomplete (even if totalCount differs)", async () => {
  // idx from cursor "c0" resolves to page 1 (the tail), which ends cleanly.
  const pages = [
    { items: [{ id: "a" }], endCursor: "c0", hasNextPage: true },
    { items: [{ id: "b" }], endCursor: "c1", hasNextPage: false },
  ];
  const { restore } = servePages("people", pages, 99); // total != window count
  try {
    const p = await listFiltered(
      LF_CFG,
      "people",
      [],
      60,
      "createdAt,id",
      "c0",
    );
    assertEquals(p.stopReason, "complete");
    assertEquals(p.incomplete, false);
    assertEquals(p.hasMore, false);
  } finally {
    restore();
  }
});

Deno.test("CR-A-6: max-pages/short-page case stays continuable (hasMore + nextCursor)", async () => {
  const { restore } = servePages("people", [
    { items: [{ id: "a" }], endCursor: "c0", hasNextPage: true },
    { items: [{ id: "b" }], endCursor: "c1", hasNextPage: true },
    { items: [{ id: "c" }], endCursor: "c2", hasNextPage: true },
    { items: [{ id: "d" }], endCursor: "c3", hasNextPage: true },
  ]);
  try {
    const p = await listFiltered(LF_CFG, "people", [], 60, "createdAt,id");
    assertEquals(p.stopReason, "max-pages");
    assert(p.hasMore);
    assert(p.nextCursor !== undefined);
    assertEquals(p.incomplete, false);
  } finally {
    restore();
  }
});

// --- compact view mappers ---------------------------------------------------

Deno.test("mapPersonView keeps only join keys (no name/email/phone)", () => {
  const v = mapPersonView({
    id: "p1",
    leadId: "L1",
    companyId: "co1",
    isEmergency: false,
    createdAt: "2026-09-01T00:00:00.000Z",
    name: { firstName: "Ada", lastName: "L" },
    emails: { primaryEmail: "ada@x.com" },
  });
  assertEquals(v, {
    id: "p1",
    leadId: "L1",
    companyId: "co1",
    isEmergency: false, // surfaced even when false (AR-5)
    createdAt: "2026-09-01T00:00:00.000Z",
  });
  assert(!("name" in v) && !("emails" in v));
});

Deno.test("mapCompanyView normalizes domainName.primaryLinkUrl to a bare host", () => {
  const v = mapCompanyView({
    id: "co1",
    name: "Acme",
    domainName: { primaryLinkUrl: "https://acme.com/contact" },
    createdAt: "2026-09-01T00:00:00.000Z",
  });
  assertEquals(v, {
    id: "co1",
    name: "Acme",
    domain: "acme.com",
    createdAt: "2026-09-01T00:00:00.000Z",
  });
});

Deno.test("mapNoteView redacts free-text titles, keeps the machine 'Inbound lead ' title, drops body", () => {
  const kept = mapNoteView({
    id: "n1",
    title: "Inbound lead L1",
    leadId: "L1",
    bodyV2: { markdown: "secret body" },
  });
  assertEquals(kept.title, "Inbound lead L1");
  assert(!("bodyV2" in kept));
  const dropped = mapNoteView({ id: "n2", title: "Private client meeting" });
  assertEquals(dropped.title, undefined);
  // CR-A-5: anchored guard drops a free-text tail after a real leadId prefix.
  const tampered = mapNoteView({
    id: "n3",
    title: "Inbound lead L1 and here are my private notes",
  });
  assertEquals(tampered.title, undefined);
  // ...and a prefix followed by a non-leadId token.
  const badSuffix = mapNoteView({ id: "n4", title: "Inbound lead <script>" });
  assertEquals(badSuffix.title, undefined);
});

Deno.test("normalizeDomainHost strips scheme/path/port/userinfo/trailing dot", () => {
  assertEquals(normalizeDomainHost("https://Acme.COM/contact"), "acme.com");
  assertEquals(normalizeDomainHost("http://user@acme.com:8443/x"), "acme.com");
  assertEquals(normalizeDomainHost("acme.com."), "acme.com");
  assertEquals(normalizeDomainHost("  ACME.com  "), "acme.com");
  assertEquals(normalizeDomainHost(""), null);
  assertEquals(normalizeDomainHost(null), null);
});

// --- instance-key determinism (AR-7) ----------------------------------------

Deno.test("canonicalJson sorts keys and drops undefined", () => {
  assertEquals(canonicalJson({ b: 1, a: 2, c: undefined }), '{"a":2,"b":1}');
  assertEquals(
    canonicalJson({ f: { z: undefined, a: null }, after: null }),
    '{"after":null,"f":{"a":null}}',
  );
});

Deno.test("listInstanceHash is deterministic and collision-resistant across filters", async () => {
  const empty = await listInstanceHash({
    f: { includeEmergency: false },
    after: null,
  });
  const empty2 = await listInstanceHash({
    f: { includeEmergency: false },
    after: null,
  });
  assertEquals(empty, empty2);
  assertEquals(empty.length, 16);
  // Empty-filter snapshot cannot collide with a literal filter value 'all'.
  const asAll = await listInstanceHash({
    f: { companyId: "all", includeEmergency: false },
    after: null,
  });
  assert(empty !== asAll);
  // A cursor page differs from the first page.
  const paged = await listInstanceHash({
    f: { includeEmergency: false },
    after: "CUR",
  });
  assert(empty !== paged);
});

// --- method-level: filter construction, rejection, keys, views --------------

Deno.test("listPeople default excludes emergency with the NULL-safe OR clause", async () => {
  const { calls, restore } = servePages(
    "people",
    [{ items: [{ id: "a" }], hasNextPage: false }],
    1,
  );
  const { ctx } = readCtx();
  try {
    await model.methods.listPeople.execute(
      { includeEmergency: false, limit: 60 } as never,
      ctx as never,
    );
    assert(
      calls[0].path.includes("or(isEmergency[eq]:false,isEmergency[is]:NULL)"),
      calls[0].path,
    );
  } finally {
    restore();
  }
});

Deno.test("listPeople includeEmergency:true omits the isEmergency clause", async () => {
  const { calls, restore } = servePages(
    "people",
    [{ items: [{ id: "a" }], hasNextPage: false }],
    1,
  );
  const { ctx } = readCtx();
  try {
    await model.methods.listPeople.execute(
      { includeEmergency: true, limit: 60 } as never,
      ctx as never,
    );
    assert(!calls[0].path.includes("isEmergency"), calls[0].path);
  } finally {
    restore();
  }
});

Deno.test("listPeople bounded-rejects a reserved-char leadId with NO request", async () => {
  const { calls, restore } = servePages("people", []);
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listPeople.execute(
      { leadId: "a,b(c)", includeEmergency: false, limit: 60 } as never,
      ctx as never,
    );
    assertEquals(calls.length, 0); // never issued a corrupted clause
    assertEquals(writes[0].type, "peopleList");
    assertEquals(writes[0].data.stopReason, "unsupported-filter-value");
    assertEquals(writes[0].data.incomplete, true);
    assertEquals(writes[0].data.count, 0);
  } finally {
    restore();
  }
});

Deno.test("listPeople instance key is deterministic per (filter, cursor) and varies by filter", async () => {
  const { restore } = servePages(
    "people",
    [{ items: [], hasNextPage: false }],
    0,
  );
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listPeople.execute(
      { includeEmergency: false, limit: 60 } as never,
      ctx as never,
    );
    await model.methods.listPeople.execute(
      { includeEmergency: false, limit: 60 } as never,
      ctx as never,
    );
    await model.methods.listPeople.execute(
      {
        companyId: "11111111-1111-1111-1111-111111111111",
        includeEmergency: false,
        limit: 60,
      } as never,
      ctx as never,
    );
    assert(writes[0].name.startsWith("people-"));
    assertEquals(writes[0].name, writes[1].name); // identical inputs => same key
    assert(writes[0].name !== writes[2].name); // different filter => different key
  } finally {
    restore();
  }
});

Deno.test("listPeople rejects an invalid companyId (redacted)", async () => {
  const { ctx } = readCtx();
  await assertRejects(
    () =>
      model.methods.listPeople.execute(
        {
          companyId: "not-a-uuid",
          includeEmergency: false,
          limit: 60,
        } as never,
        ctx as never,
      ),
    Error,
    "Invalid companyId",
  );
});

Deno.test("listCompanies normalizes the domain filter and the view domain", async () => {
  const { calls, restore } = servePages(
    "companies",
    [{
      items: [{
        id: "co1",
        name: "Acme",
        domainName: { primaryLinkUrl: "https://acme.com/" },
      }],
      hasNextPage: false,
    }],
    1,
  );
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listCompanies.execute(
      { domain: "https://Acme.COM/path", limit: 60 } as never,
      ctx as never,
    );
    assert(
      calls[0].path.includes("domainName.primaryLinkUrl[eq]:acme.com"),
      calls[0].path,
    );
    const items = writes[0].data.items as Array<Record<string, unknown>>;
    assertEquals(items[0].domain, "acme.com");
  } finally {
    restore();
  }
});

Deno.test("listCompanies bounded-rejects a reserved-char name", async () => {
  const { calls, restore } = servePages("companies", []);
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listCompanies.execute(
      { name: "Acme, Inc.", limit: 60 } as never,
      ctx as never,
    );
    assertEquals(calls.length, 0);
    assertEquals(writes[0].data.stopReason, "unsupported-filter-value");
    assertEquals(writes[0].data.incomplete, true);
  } finally {
    restore();
  }
});

Deno.test("listNotes drops free-text titles + body end-to-end, filters leadId", async () => {
  const { calls, restore } = servePages(
    "notes",
    [{
      items: [
        {
          id: "n1",
          title: "Inbound lead L1",
          leadId: "L1",
          bodyV2: { markdown: "x" },
        },
        { id: "n2", title: "Private meeting", leadId: "L1" },
      ],
      hasNextPage: false,
    }],
    2,
  );
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listNotes.execute(
      { leadId: "L1", limit: 60 } as never,
      ctx as never,
    );
    assert(calls[0].path.includes("leadId[eq]:L1"), calls[0].path);
    const items = writes[0].data.items as Array<Record<string, unknown>>;
    assertEquals(items[0].title, "Inbound lead L1");
    assertEquals(items[1].title, undefined);
    assert(!("bodyV2" in items[0]));
    assertEquals(writes[0].data.stopReason, "complete");
  } finally {
    restore();
  }
});

Deno.test("listNotes never sends an isEmergency clause (Note has no such field)", async () => {
  const { calls, restore } = servePages(
    "notes",
    [{ items: [{ id: "n1" }], hasNextPage: false }],
    1,
  );
  const { ctx } = readCtx();
  try {
    await model.methods.listNotes.execute(
      { limit: 60 } as never,
      ctx as never,
    );
    assert(!calls[0].path.includes("isEmergency"), calls[0].path);
  } finally {
    restore();
  }
});

Deno.test("redactError scrubs filter= and starting_after= query values (SR-2)", () => {
  const s = redactError(
    "Twenty GET /rest/people?filter=leadId[eq]:topsecret&starting_after=CURSOR123 failed: 400 Bad Request",
  );
  assert(s.includes("filter=[redacted]"), s);
  assert(s.includes("starting_after=[redacted]"), s);
  assert(!s.includes("topsecret"), s);
  assert(!s.includes("CURSOR123"), s);
});

Deno.test("redactError scrubs the bearer token and an exact literal token (SR-2/CR-S-1)", () => {
  const tok = "sk_live_abc123.DEF-456~789";
  const s = redactError(
    `fetch failed for Authorization: Bearer ${tok} against host; token ${tok} echoed`,
    300,
    tok,
  );
  assert(!s.includes(tok), s);
  assert(s.includes("Bearer [redacted]"), s);
  assert(s.includes("[redacted]"), s);
});

// --- ensureField: normalizeRequestedOption (pure) ---------------------------

Deno.test("normalizeRequestedOption defaults label + color and keeps position", () => {
  assertEquals(normalizeRequestedOption({ value: "CLOSED_WON" }, 3), {
    value: "CLOSED_WON",
    label: "Closed Won",
    color: "gray",
    position: 3,
  });
});

Deno.test("normalizeRequestedOption honors an explicit label + color", () => {
  assertEquals(
    normalizeRequestedOption(
      { value: "HOSTING", label: "Hosting", color: "green" },
      0,
    ),
    { value: "HOSTING", label: "Hosting", color: "green", position: 0 },
  );
});

Deno.test("normalizeRequestedOption rejects a non-UPPER_SNAKE value", () => {
  for (const bad of ["hosting", "Has Space", "1LEADING", "kebab-case", ""]) {
    assertThrows(
      () => normalizeRequestedOption({ value: bad }, 0),
      Error,
      "option value",
    );
  }
});

Deno.test("normalizeRequestedOption rejects an off-palette color", () => {
  assertThrows(
    () =>
      normalizeRequestedOption({ value: "HOSTING", color: "chartreuse" }, 0),
    Error,
    "color",
  );
});

// --- ensureField: planSelectOptions (pure, append-only) ---------------------

const existingOpts = [
  {
    id: "id-a",
    value: "CONSULTING",
    label: "Consulting",
    color: "blue",
    position: 0,
  },
  {
    id: "id-b",
    value: "HOSTING",
    label: "Hosting",
    color: "green",
    position: 1,
  },
];

Deno.test("planSelectOptions appends only new options, preserving existing verbatim", () => {
  const plan = planSelectOptions(existingOpts, [
    { value: "HOSTING", label: "Hosting", color: "green" },
    { value: "GAMES", label: "Games", color: "purple" },
  ]);
  // Existing entries untouched (id/label/color/position all preserved).
  assertEquals(plan.merged.slice(0, 2), existingOpts);
  assertEquals(plan.present, ["HOSTING"]);
  assertEquals(plan.added.length, 1);
  assertEquals(plan.added[0], {
    value: "GAMES",
    label: "Games",
    color: "purple",
    position: 2,
  });
  // The appended option carries no id (the impure caller mints one).
  assertEquals((plan.merged[2] as { id?: string }).id, undefined);
});

Deno.test("planSelectOptions is a no-op when every requested option is present", () => {
  const plan = planSelectOptions(existingOpts, [
    { value: "CONSULTING", label: "Consulting", color: "blue" },
    { value: "HOSTING", label: "Hosting", color: "green" },
  ]);
  assertEquals(plan.added, []);
  assertEquals(plan.merged, existingOpts);
  assertEquals(plan.mismatches, []);
});

Deno.test("planSelectOptions reconciles a drifted option in place by default (id/position preserved)", () => {
  const plan = planSelectOptions(existingOpts, [
    { value: "HOSTING", label: "Hosting Plans", color: "red" },
  ]);
  assertEquals(plan.added, []);
  assertEquals(plan.mismatches, []); // reconciled, not reported
  assertEquals(plan.updated.length, 1);
  assertEquals(plan.updated[0], {
    id: "id-b", // id preserved
    value: "HOSTING",
    label: "Hosting Plans", // new label
    color: "red", // new color
    position: 1, // position preserved
  });
  // merged reflects the reconciled option in place, CONSULTING untouched.
  assertEquals(plan.merged[0], existingOpts[0]);
  assertEquals(plan.merged[1], {
    id: "id-b",
    value: "HOSTING",
    label: "Hosting Plans",
    color: "red",
    position: 1,
  });
  assertEquals(plan.merged.length, 2); // no append
});

Deno.test("planSelectOptions reconcile:false reports a label/color mismatch but never mutates it", () => {
  const plan = planSelectOptions(existingOpts, [
    { value: "HOSTING", label: "Hosting Plans", color: "red" },
  ], { reconcile: false });
  assertEquals(plan.added, []);
  assertEquals(plan.updated, []);
  assertEquals(plan.merged, existingOpts); // unchanged
  assertEquals(plan.mismatches.length, 1);
  assert(plan.mismatches[0].includes("HOSTING"));
});

Deno.test("planSelectOptions reconciles a drift AND appends a new option together", () => {
  const plan = planSelectOptions(existingOpts, [
    { value: "HOSTING", label: "Hosting", color: "red" }, // color drift
    { value: "GAMES", label: "Games", color: "purple" }, // new
  ]);
  assertEquals(plan.updated.map((o) => o.value), ["HOSTING"]);
  assertEquals(plan.added.map((o) => o.value), ["GAMES"]);
  assertEquals(plan.added[0].position, 2); // appended after max
  assertEquals(plan.mismatches, []);
  // merged: existing (HOSTING recolored) + appended GAMES (id-less).
  assertEquals(plan.merged.length, 3);
  assertEquals((plan.merged[1] as { color: string }).color, "red");
  assertEquals((plan.merged[2] as { id?: string }).id, undefined);
});

Deno.test("planSelectOptions creates all options from an empty field, positions 0..n", () => {
  const plan = planSelectOptions([], [
    { value: "DIRECT" },
    { value: "REFERRAL" },
  ]);
  assertEquals(plan.added.map((o) => [o.value, o.position]), [
    ["DIRECT", 0],
    ["REFERRAL", 1],
  ]);
  assertEquals(plan.present, []);
});

Deno.test("planSelectOptions collapses duplicate requested values", () => {
  const plan = planSelectOptions([], [
    { value: "DIRECT" },
    { value: "DIRECT", label: "Direct Again" },
  ]);
  assertEquals(plan.added.length, 1);
  assertEquals(plan.added[0].value, "DIRECT");
});

Deno.test("planSelectOptions appends after the current max position (not array length)", () => {
  const sparse = [
    { id: "x", value: "A", label: "A", color: "gray", position: 5 },
  ];
  const plan = planSelectOptions(sparse, [{ value: "B" }]);
  assertEquals(plan.added[0].position, 6);
});

Deno.test("planSelectOptions throws on an invalid requested option (no partial plan)", () => {
  assertThrows(
    () => planSelectOptions(existingOpts, [{ value: "bad lower" }]),
    Error,
    "option value",
  );
});

// --- Opportunity segmentation field specs (TWENTY-OPP-SEGMENTATION) ----------

Deno.test("OPPORTUNITY_SEGMENTATION_FIELDS declares the three Opportunity SELECTs", () => {
  assertEquals(OPPORTUNITY_SEGMENTATION_FIELDS.length, 3);
  const byName = new Map(
    OPPORTUNITY_SEGMENTATION_FIELDS.map((f) => [f.name, f]),
  );
  const lob = byName.get("lineOfBusiness");
  const src = byName.get("sourceChannel");
  const off = byName.get("offering");
  assert(lob && src && off);
  for (const f of OPPORTUNITY_SEGMENTATION_FIELDS) {
    assertEquals(f.objectNameSingular, "opportunity");
    assertEquals(f.type, "SELECT");
  }
  assertEquals(
    lob!.options!.map((o) => o.value),
    ["CONSULTING", "HOSTING", "GAMES"],
  );
  assertEquals(
    src!.options!.map((o) => o.value),
    [
      "DIRECT",
      "REFERRAL",
      "CONSULTING_HANDOFF",
    ],
  );
  // CONSULTING_HANDOFF carries a deliberate (non-default) color.
  assertEquals(
    src!.options!.find((o) => o.value === "CONSULTING_HANDOFF")!.color,
    "purple",
  );
  // offering: all 6 options with their deliberate colors (TWENTY-OPP-OFFERING).
  assertEquals(
    off!.options!.map((o) => o.value),
    ["MANAGED", "SUBSTRATE", "PROJECT", "RETAINER", "LOCAL_IT", "PEERING"],
  );
  assertEquals(
    off!.options!.map((o) => o.color),
    ["blue", "turquoise", "orange", "green", "sky", "pink"],
  );
});

Deno.test("segmentation field specs are all valid per normalizeRequestedOption", () => {
  // Every declared option must pass the same validation the writer enforces.
  for (const f of OPPORTUNITY_SEGMENTATION_FIELDS) {
    const plan = planSelectOptions([], f.options ?? []);
    assertEquals(plan.added.length, (f.options ?? []).length);
  }
});

// --- ensureField / ensureOpportunitySegmentation confirm-gates ---------------

const gateCtx = {
  globalArgs: {
    baseUrl: "https://crm.example.com",
    apiToken: "tok",
    opportunityStage: "NEW",
    emailDomainBlocklist: [...DEFAULT_EMAIL_DOMAIN_BLOCKLIST],
    emergencyRestrictedRole: "",
    leadSourceChannel: "",
  },
  logger: { debug() {}, info() {}, warning() {}, error() {} },
  writeResource: () => Promise.resolve({ name: "n" }),
};

Deno.test("ensureField refuses a real run without confirm:true", async () => {
  await assertRejects(
    () =>
      model.methods.ensureField.execute(
        {
          objectNameSingular: "opportunity",
          name: "lineOfBusiness",
          type: "SELECT",
          options: [{ value: "HOSTING" }],
          confirm: false,
          dryRun: false,
          reconcile: true,
        },
        gateCtx as never,
      ),
    Error,
    "confirm:true",
  );
});

Deno.test("ensureOpportunitySegmentation refuses a real run without confirm:true", async () => {
  await assertRejects(
    () =>
      model.methods.ensureOpportunitySegmentation.execute(
        { confirm: false, dryRun: false, reconcile: true },
        gateCtx as never,
      ),
    Error,
    "confirm:true",
  );
});

// --- ensureObject (TWENTY-ENSURE-OBJECT) ------------------------------------

// GET /rest/metadata/objects fixture: the workspace objects (name/id only).
function objectsMeta(objs: Array<Record<string, unknown>> = []) {
  return { data: objs };
}

const ENSURE_OBJECT_ARGS = {
  nameSingular: "invoice",
  namePlural: "invoices",
  confirm: false,
  dryRun: true,
};

Deno.test("ensureObject refuses a real run without confirm:true", async () => {
  await assertRejects(
    () =>
      model.methods.ensureObject.execute(
        { ...ENSURE_OBJECT_ARGS, confirm: false, dryRun: false },
        gateCtx as never,
      ),
    Error,
    "confirm:true",
  );
});

Deno.test("ensureObject dryRun MISSING: planned-create, no write, payload preview", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: objectsMeta([{ nameSingular: "opportunity", id: "o1" }]) };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureObject.execute(
      { ...ENSURE_OBJECT_ARGS, dryRun: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].type, "objectEnsured");
    assertEquals(writes[0].data.action, "planned-create");
    assertEquals(writes[0].data.dryRun, true);
    // Labels default via titleCaseToken (same helper ensureField uses): a
    // single lowercase camelCase token passes through unchanged.
    assertEquals(writes[0].data.labelSingular, "invoice");
    assertEquals(writes[0].data.labelPlural, "invoices");
    // No objectId on a planned create; the payload previews what WOULD POST.
    assertEquals("objectId" in writes[0].data, false);
    const payload = writes[0].data.payload as Record<string, unknown>;
    assertEquals(payload.nameSingular, "invoice");
    assertEquals(payload.namePlural, "invoices");
    assertEquals(payload.labelSingular, "invoice");
    assertEquals(payload.labelPlural, "invoices");
    assert(
      !calls.some((c) => c.method === "POST"),
      "must not write on dryRun",
    );
  } finally {
    restore();
  }
});

Deno.test("ensureObject already-exists (by nameSingular): present, no POST", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return {
        body: objectsMeta([
          { nameSingular: "invoice", namePlural: "invoices", id: "obj-inv" },
        ]),
      };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureObject.execute(
      { ...ENSURE_OBJECT_ARGS, confirm: true, dryRun: false } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "present");
    assertEquals(writes[0].data.objectId, "obj-inv");
    // Present is a no-op: no create payload, no write.
    assertEquals("payload" in writes[0].data, false);
    assert(!calls.some((c) => c.method === "POST"), "present must not POST");
  } finally {
    restore();
  }
});

Deno.test("ensureObject already-exists (by namePlural collision): present, no POST", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      // Different singular, but the plural collides with an existing object.
      return {
        body: objectsMeta([
          { nameSingular: "bill", namePlural: "invoices", id: "obj-bill" },
        ]),
      };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureObject.execute(
      { ...ENSURE_OBJECT_ARGS, confirm: true, dryRun: false } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "present");
    assertEquals(writes[0].data.objectId, "obj-bill");
    assert(!calls.some((c) => c.method === "POST"));
  } finally {
    restore();
  }
});

Deno.test("ensureObject confirm create: POSTs the object body, records created + new id", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: objectsMeta([{ nameSingular: "opportunity", id: "o1" }]) };
    }
    if (method === "POST" && path === "/rest/metadata/objects") {
      return { body: { data: { id: "obj-new" } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureObject.execute(
      {
        nameSingular: "invoice",
        namePlural: "invoices",
        labelSingular: "Invoice",
        labelPlural: "Invoices",
        description: "Customer invoices",
        icon: "IconFileInvoice",
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "created");
    assertEquals(writes[0].data.objectId, "obj-new");
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a POST to create the object");
    const body = post!.body as Record<string, unknown>;
    assertEquals(body.nameSingular, "invoice");
    assertEquals(body.namePlural, "invoices");
    assertEquals(body.labelSingular, "Invoice");
    assertEquals(body.labelPlural, "Invoices");
    assertEquals(body.description, "Customer invoices");
    assertEquals(body.icon, "IconFileInvoice");
  } finally {
    restore();
  }
});

Deno.test("ensureObject confirm create: POST response lacks id => objectId resolved via post-create re-GET", async () => {
  // Regression for the v2.38.x envelope: the create POST returns a shape whose
  // id our best-effort extraction MISSES, so objectId must come from the
  // authoritative objects-list re-GET (matched by nameSingular). The GET is
  // stateful: the idempotency read (1st) does NOT contain the object (so we take
  // the create path); the post-create read-back (2nd) DOES, carrying its id.
  let getCount = 0;
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      getCount += 1;
      if (getCount === 1) {
        return {
          body: objectsMeta([{ nameSingular: "opportunity", id: "o1" }]),
        };
      }
      return {
        body: objectsMeta([
          { nameSingular: "opportunity", id: "o1" },
          {
            nameSingular: "invoice",
            namePlural: "invoices",
            id: "obj-readback",
          },
        ]),
      };
    }
    if (method === "POST" && path === "/rest/metadata/objects") {
      // Envelope our data.id / createOneObject.id / createObject.id guesses miss.
      return { body: { data: { object: { id: "unread-nested" } } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureObject.execute(
      {
        nameSingular: "invoice",
        namePlural: "invoices",
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "created");
    // objectId comes from the re-GET-by-name, NOT the (unrecognized) envelope.
    assertEquals(writes[0].data.objectId, "obj-readback");
    assert(
      calls.some((c) => c.method === "POST"),
      "expected a POST to create the object",
    );
    assertEquals(getCount, 2, "expected a post-create read-back GET");
  } finally {
    restore();
  }
});

Deno.test("ensureObject rejects a non-camelCase nameSingular before any I/O", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureObject.execute(
          { ...ENSURE_OBJECT_ARGS, nameSingular: "Invoice_Line" } as never,
          ctx as never,
        ),
      Error,
      "Invalid nameSingular",
    );
    assertEquals(calls.length, 0, "must reject before any request");
  } finally {
    restore();
  }
});

Deno.test("ensureObject rejects identical singular/plural before any I/O", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureObject.execute(
          { ...ENSURE_OBJECT_ARGS, namePlural: "invoice" } as never,
          ctx as never,
        ),
      Error,
      "must differ",
    );
    assertEquals(calls.length, 0, "must reject before any request");
  } finally {
    restore();
  }
});

// --- ensureRelation (TWENTY-ENSURE-RELATION) --------------------------------

Deno.test("computeMetadataNameFromLabel derives camelCase like Twenty", () => {
  assertEquals(computeMetadataNameFromLabel("Opportunities"), "opportunities");
  assertEquals(computeMetadataNameFromLabel("Line Items"), "lineItems");
  assertEquals(
    computeMetadataNameFromLabel("Purchase Orders"),
    "purchaseOrders",
  );
  assertEquals(
    computeMetadataNameFromLabel("  Purchase Orders 2  "),
    "purchaseOrders2",
  );
  // Punctuation and diacritics are dropped/normalized.
  assertEquals(computeMetadataNameFromLabel("Réunions"), "reunions");
  assertEquals(
    computeMetadataNameFromLabel("Customer / Vendor"),
    "customerVendor",
  );
  assertEquals(computeMetadataNameFromLabel("invoice"), "invoice");
  assertEquals(computeMetadataNameFromLabel(""), "");
});

// Two objects present, no relevant fields. `oppFields`/`invFields` override.
function relMeta(
  oppFields: unknown[] = [],
  invFields: unknown[] = [],
) {
  return objectsMeta([
    { nameSingular: "opportunity", id: "obj-opp", fields: oppFields },
    { nameSingular: "invoice", id: "obj-inv", fields: invFields },
  ]);
}

const ENSURE_RELATION_ARGS = {
  fromObjectNameSingular: "opportunity",
  toObjectNameSingular: "invoice",
  relationType: "MANY_TO_ONE",
  fromFieldName: "invoice",
  targetFieldLabel: "Opportunities",
  targetFieldIcon: "IconListOpportunity",
  confirm: false,
  dryRun: true,
};

Deno.test("ensureRelation refuses a real run without confirm:true", async () => {
  await assertRejects(
    () =>
      model.methods.ensureRelation.execute(
        { ...ENSURE_RELATION_ARGS, confirm: false, dryRun: false } as never,
        gateCtx as never,
      ),
    Error,
    "confirm:true",
  );
});

Deno.test("ensureRelation dryRun MISSING: planned-create, no write, relationCreationPayload preview", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: relMeta() };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureRelation.execute(
      { ...ENSURE_RELATION_ARGS, dryRun: true } as never,
      ctx as never,
    );
    assertEquals(writes[0].type, "relationEnsured");
    assertEquals(writes[0].data.action, "planned-create");
    assertEquals(writes[0].data.dryRun, true);
    assertEquals(writes[0].data.objectMetadataId, "obj-opp");
    assertEquals(writes[0].data.targetObjectMetadataId, "obj-inv");
    // fromFieldName is the instance-name key component the sibling workflow
    // asserts on (instance = relation-<fromObject>-<fromFieldName>).
    assertEquals(writes[0].data.name, "invoice");
    assertEquals(writes[0].data.fromFieldName, "invoice");
    // Reverse field name derived from targetFieldLabel.
    assertEquals(writes[0].data.reverseFieldName, "opportunities");
    // Source label defaults via titleCaseToken (single lowercase token unchanged).
    assertEquals(writes[0].data.label, "invoice");
    const payload = writes[0].data.payload as Record<string, unknown>;
    assertEquals(payload.name, "invoice");
    assertEquals(payload.label, "invoice");
    assertEquals(payload.type, "RELATION");
    assertEquals(payload.objectMetadataId, "obj-opp");
    const rcp = payload.relationCreationPayload as Record<string, unknown>;
    assertEquals(rcp.type, "MANY_TO_ONE");
    assertEquals(rcp.targetObjectMetadataId, "obj-inv");
    assertEquals(rcp.targetFieldLabel, "Opportunities");
    assertEquals(rcp.targetFieldIcon, "IconListOpportunity");
    assert(!calls.some((c) => c.method === "POST"), "must not write on dryRun");
  } finally {
    restore();
  }
});

Deno.test("ensureRelation already-exists (source RELATION): present, no POST, read-back", async () => {
  const oppField = {
    name: "invoice",
    type: "RELATION",
    id: "f1",
    settings: {
      relationType: "MANY_TO_ONE",
      onDelete: "SET_NULL",
      joinColumnName: "invoiceId",
    },
    relation: {
      targetObjectMetadata: { id: "obj-inv", nameSingular: "invoice" },
      sourceFieldMetadata: { id: "f1", name: "invoice" },
      targetFieldMetadata: { id: "f2", name: "opportunities" },
    },
  };
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: relMeta([oppField]) };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureRelation.execute(
      { ...ENSURE_RELATION_ARGS, confirm: true, dryRun: false } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "present");
    assertEquals(writes[0].data.fieldId, "f1");
    assertEquals(writes[0].data.relationType, "MANY_TO_ONE");
    assertEquals(writes[0].data.joinColumnName, "invoiceId");
    const rel = writes[0].data.relation as Record<string, unknown>;
    const tgt = rel.targetObjectMetadata as Record<string, unknown>;
    assertEquals(tgt.id, "obj-inv");
    // Matches intent -> no drift note, no create body.
    assertEquals("targetMismatch" in writes[0].data, false);
    assertEquals("payload" in writes[0].data, false);
    assert(!calls.some((c) => c.method === "POST"), "present must not POST");
  } finally {
    restore();
  }
});

Deno.test("ensureRelation present-but-points-elsewhere: reports targetMismatch, no mutation", async () => {
  const oppField = {
    name: "invoice",
    type: "RELATION",
    id: "f1",
    settings: { relationType: "MANY_TO_ONE" },
    relation: {
      targetObjectMetadata: { id: "obj-OTHER", nameSingular: "receipt" },
      sourceFieldMetadata: { id: "f1", name: "invoice" },
    },
  };
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: relMeta([oppField]) };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureRelation.execute(
      { ...ENSURE_RELATION_ARGS, confirm: true, dryRun: false } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "present");
    assert(String(writes[0].data.targetMismatch ?? "").includes("obj-OTHER"));
    assert(!calls.some((c) => c.method === "POST"));
  } finally {
    restore();
  }
});

Deno.test("ensureRelation type-mismatch (source field is TEXT): reported, no POST", async () => {
  const oppField = { name: "invoice", type: "TEXT", id: "f9" };
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: relMeta([oppField]) };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureRelation.execute(
      { ...ENSURE_RELATION_ARGS, confirm: true, dryRun: false } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "type-mismatch");
    assertEquals(writes[0].data.type, "TEXT");
    assert(String(writes[0].data.typeMismatch ?? "").includes("TEXT"));
    assert(!calls.some((c) => c.method === "POST"));
  } finally {
    restore();
  }
});

Deno.test("ensureRelation reverse-name collision on target: hard-fails before POST", async () => {
  const invField = { name: "opportunities", type: "RELATION", id: "x1" };
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: relMeta([], [invField]) };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureRelation.execute(
          { ...ENSURE_RELATION_ARGS, confirm: true, dryRun: false } as never,
          ctx as never,
        ),
      Error,
      "already exists on target",
    );
    assert(!calls.some((c) => c.method === "POST"), "collision must not POST");
  } finally {
    restore();
  }
});

Deno.test("ensureRelation rejects MANY_TO_MANY before any I/O", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureRelation.execute(
          { ...ENSURE_RELATION_ARGS, relationType: "MANY_TO_MANY" } as never,
          ctx as never,
        ),
      Error,
      "Unsupported relationType",
    );
    assertEquals(calls.length, 0, "must reject before any request");
  } finally {
    restore();
  }
});

Deno.test("ensureRelation rejects a non-camelCase fromFieldName before any I/O", async () => {
  const { calls, restore } = stubFetchStatus(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureRelation.execute(
          { ...ENSURE_RELATION_ARGS, fromFieldName: "Invoice_Bad" } as never,
          ctx as never,
        ),
      Error,
      "Invalid fromFieldName",
    );
    assertEquals(calls.length, 0, "must reject before any request");
  } finally {
    restore();
  }
});

Deno.test("ensureRelation confirm create: POSTs RELATION field body, records created + read-back", async () => {
  let created = false;
  const relField = {
    name: "invoice",
    type: "RELATION",
    id: "f1",
    settings: {
      relationType: "MANY_TO_ONE",
      onDelete: "SET_NULL",
      joinColumnName: "invoiceId",
    },
    relation: {
      targetObjectMetadata: { id: "obj-inv", nameSingular: "invoice" },
      sourceFieldMetadata: { id: "f1", name: "invoice" },
      targetFieldMetadata: { id: "f2", name: "opportunities" },
    },
  };
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "POST" && path === "/rest/metadata/fields") {
      created = true;
      return { body: {} };
    }
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return {
        body: created
          ? relMeta([relField], [{ name: "opportunities", type: "RELATION" }])
          : relMeta(),
      };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.ensureRelation.execute(
      {
        ...ENSURE_RELATION_ARGS,
        fromLabel: "Invoice",
        fromIcon: "IconFileInvoice",
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.action, "created");
    // fromFieldName present on the created path too (workflow assert key).
    assertEquals(writes[0].data.name, "invoice");
    assertEquals(writes[0].data.fromFieldName, "invoice");
    // Read-back from the re-GET, not the (empty) create response.
    assertEquals(writes[0].data.fieldId, "f1");
    assertEquals(writes[0].data.relationType, "MANY_TO_ONE");
    assertEquals(writes[0].data.onDelete, "SET_NULL");
    assertEquals(writes[0].data.joinColumnName, "invoiceId");
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a POST to create the relation field");
    const body = post!.body as Record<string, unknown>;
    assertEquals(body.name, "invoice");
    assertEquals(body.label, "Invoice");
    assertEquals(body.type, "RELATION");
    assertEquals(body.objectMetadataId, "obj-opp");
    assertEquals(body.icon, "IconFileInvoice");
    const rcp = body.relationCreationPayload as Record<string, unknown>;
    assertEquals(rcp.type, "MANY_TO_ONE");
    assertEquals(rcp.targetObjectMetadataId, "obj-inv");
    assertEquals(rcp.targetFieldLabel, "Opportunities");
    assertEquals(rcp.targetFieldIcon, "IconListOpportunity");
  } finally {
    restore();
  }
});

Deno.test("ensureRelation hard-stops when the target object is absent", async () => {
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return {
        body: objectsMeta([
          { nameSingular: "opportunity", id: "obj-opp", fields: [] },
        ]),
      };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.ensureRelation.execute(
          { ...ENSURE_RELATION_ARGS, dryRun: true } as never,
          ctx as never,
        ),
      Error,
      "Object 'invoice' not found",
    );
    assert(!calls.some((c) => c.method === "POST"));
  } finally {
    restore();
  }
});

Deno.test("push_leads fails fast on a non-UPPER_SNAKE leadSourceChannel (before any I/O)", async () => {
  const badCtx = {
    ...gateCtx,
    globalArgs: { ...gateCtx.globalArgs, leadSourceChannel: "direct channel" },
  };
  // dryRun:true clears the confirm-gate, so the throw we catch is the config
  // validation — which runs before any network call.
  await assertRejects(
    () =>
      model.methods.push_leads.execute(
        {
          leads: [],
          kvEntries: [],
          confirm: false,
          dryRun: true,
          maxBatch: 200,
        },
        badCtx as never,
      ),
    Error,
    "leadSourceChannel must be UPPER_SNAKE",
  );
});

// --- upsertRecord (generic custom-object create-or-update) -------------------
// All exercised via the injected-fetch harness (stubTwentyFetch / bespoke
// stubs) — no live Twenty. Metadata mirrors the LIVE shape of the two
// allowlisted objects (verified against crm.brandmail.example 2026-09-16): scalar
// TEXT/NUMBER/SELECT fields + reserved id/createdAt/deletedAt/position + real
// composite types (RELATION), plus a synthetic CURRENCY field for the
// composite-rejection case.

const REC_META = {
  data: [{
    nameSingular: "subscription",
    namePlural: "subscriptions",
    fields: [
      { name: "id", type: "UUID" },
      { name: "createdAt", type: "DATE_TIME" },
      { name: "updatedAt", type: "DATE_TIME" },
      { name: "deletedAt", type: "DATE_TIME" },
      { name: "position", type: "POSITION" },
      { name: "name", type: "TEXT" },
      { name: "invoiceNinjaClientRef", type: "TEXT" },
      { name: "mrr", type: "NUMBER" },
      { name: "renewalDate", type: "DATE_TIME" },
      {
        name: "status",
        type: "SELECT",
        options: [{ value: "DRAFT" }, { value: "ACTIVE" }, {
          value: "CHURNED",
        }],
      },
      { name: "monthlyValue", type: "CURRENCY" }, // composite (rejection test)
      { name: "company", type: "RELATION" }, // composite
    ],
  }],
};

// A capturing execute-context: records the last writeResource call so a test
// can assert on the snapshot spec/name/attributes.
function makeRecCtx() {
  const captured: {
    spec?: string;
    name?: string;
    data?: Record<string, unknown>;
  } = {};
  const ctx = {
    globalArgs: {
      baseUrl: "https://crm.example.com",
      apiToken: "tok",
      opportunityStage: "NEW",
      emailDomainBlocklist: [...DEFAULT_EMAIL_DOMAIN_BLOCKLIST],
      emergencyRestrictedRole: "",
    },
    logger: { debug() {}, info() {}, warning() {}, error() {} },
    writeResource: (
      spec: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      captured.spec = spec;
      captured.name = name;
      captured.data = data;
      return Promise.resolve({ name });
    },
  };
  return { ctx, captured };
}

// A fetch stub that returns a chosen non-2xx for a matched (method,path) and
// 2xx otherwise — for the create-race and redaction paths.
function stubTwentyFetchStatus(
  handlers: (
    method: string,
    path: string,
    body: unknown,
  ) => { status?: number; payload?: unknown },
): {
  calls: Array<{ method: string; path: string; body: unknown }>;
  restore: () => void;
} {
  const calls: Array<{ method: string; path: string; body: unknown }> = [];
  const orig = globalThis.fetch;
  globalThis.fetch = ((url: string | URL, init?: RequestInit) => {
    const path = String(url).replace("https://crm.example.com", "");
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path, body });
    const { status = 200, payload = {} } = handlers(method, path, body) ?? {};
    const ok = status >= 200 && status < 300;
    const text = typeof payload === "string"
      ? payload
      : JSON.stringify(payload);
    return Promise.resolve(
      {
        ok,
        status,
        statusText: ok ? "OK" : "Error",
        text: () => Promise.resolve(text),
      } as Response,
    );
  }) as typeof fetch;
  return { calls, restore: () => (globalThis.fetch = orig) };
}

const REC_BASE = {
  objectNameSingular: "subscription",
  matchField: "invoiceNinjaClientRef",
  matchValue: "client-abc-123",
};

// (T1) both dryRun+confirm omitted => throw, nothing resolved (no fetch calls).
Deno.test("upsertRecord: no dryRun + no confirm throws before any I/O", async () => {
  const { calls, restore } = stubTwentyFetch(() => ({}));
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          { ...REC_BASE, fields: {}, confirm: false, dryRun: false } as never,
          ctx as never,
        ),
      Error,
      "confirm:true",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

// (T2) dryRun, MISSING target => planned-create, no POST, payload has matchField.
Deno.test("upsertRecord: dryRun on a missing target plans a create (no POST)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      return { data: { subscriptions: [] } };
    }
    return {};
  });
  const { ctx, captured } = makeRecCtx();
  try {
    await model.methods.upsertRecord.execute(
      {
        ...REC_BASE,
        fields: { name: "Acme Sub", mrr: 100 },
        confirm: false,
        dryRun: true,
      } as never,
      ctx as never,
    );
    assertEquals(calls.find((c) => c.method === "POST"), undefined);
    assertEquals(captured.data!.action, "planned-create");
    const payload = captured.data!.creationPayload as Record<string, unknown>;
    // The persisted payload carries the matchField as a HASH placeholder, never
    // the raw natural key (finding #1); scalar field values remain as submitted.
    assertEquals(
      String(payload.invoiceNinjaClientRef).startsWith("[hashed:"),
      true,
    );
    assertEquals(
      payload.invoiceNinjaClientRef,
      `[hashed:${captured.data!.matchValueHash}]`,
    );
    assertEquals(payload.name, "Acme Sub");
  } finally {
    restore();
  }
});

// (T3) dryRun, PRESENT target => planned-update, no PATCH.
Deno.test("upsertRecord: dryRun on an existing target plans an update (no PATCH)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      return { data: { subscriptions: [{ id: "sub1" }] } };
    }
    return {};
  });
  const { ctx, captured } = makeRecCtx();
  try {
    await model.methods.upsertRecord.execute(
      {
        ...REC_BASE,
        fields: { mrr: 200 },
        confirm: false,
        dryRun: true,
      } as never,
      ctx as never,
    );
    assertEquals(calls.find((c) => c.method === "PATCH"), undefined);
    assertEquals(captured.data!.action, "planned-update");
  } finally {
    restore();
  }
});

// (T4) confirm create => POST /rest/<plural> with matchField injected, id back.
Deno.test("upsertRecord: confirm create POSTs with matchField injected", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      return { data: { subscriptions: [] } };
    }
    if (method === "POST") {
      return { data: { createSubscription: { id: "sub-new" } } };
    }
    return {};
  });
  const { ctx, captured } = makeRecCtx();
  try {
    await model.methods.upsertRecord.execute(
      {
        ...REC_BASE,
        fields: { name: "Acme", mrr: 50 },
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a POST to create the subscription");
    assertEquals(post!.path, "/rest/subscriptions");
    const body = post!.body as Record<string, unknown>;
    assertEquals(body.invoiceNinjaClientRef, "client-abc-123");
    assertEquals(body.name, "Acme");
    assertEquals(captured.data!.action, "created");
    assertEquals(captured.data!.recordId, "sub-new");
  } finally {
    restore();
  }
});

// (T5) confirm update single hit => PATCH /rest/<plural>/<id>, matchField NOT in body.
Deno.test("upsertRecord: confirm update PATCHes by id, matchField excluded from body", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      return { data: { subscriptions: [{ id: "sub1" }] } };
    }
    if (method === "PATCH") {
      return { data: { updateSubscription: { id: "sub1" } } };
    }
    return {};
  });
  const { ctx, captured } = makeRecCtx();
  try {
    await model.methods.upsertRecord.execute(
      {
        ...REC_BASE,
        fields: { mrr: 250, status: "ACTIVE" },
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH to the existing subscription");
    assertEquals(patch!.path, "/rest/subscriptions/sub1");
    const body = patch!.body as Record<string, unknown>;
    assertEquals("invoiceNinjaClientRef" in body, false);
    assertEquals(body.mrr, 250);
    assertEquals(body.status, "ACTIVE");
    assertEquals(captured.data!.action, "updated");
  } finally {
    restore();
  }
});

// (T6) POST fails => create-race fallback re-GET + PATCH => action=updated.
Deno.test("upsertRecord: POST failure triggers create-race fallback (re-GET + PATCH)", async () => {
  let getCount = 0;
  const { calls, restore } = stubTwentyFetchStatus((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return { payload: REC_META };
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      getCount++;
      // First find => empty (go to create); after the failed POST => 1 (raced).
      return {
        payload: {
          data: { subscriptions: getCount === 1 ? [] : [{ id: "raced1" }] },
        },
      };
    }
    if (method === "POST") {
      return { status: 409, payload: { error: "conflict" } };
    }
    if (method === "PATCH") {
      return { payload: { data: { updateSubscription: { id: "raced1" } } } };
    }
    return { payload: {} };
  });
  const { ctx, captured } = makeRecCtx();
  try {
    await model.methods.upsertRecord.execute(
      {
        ...REC_BASE,
        fields: { mrr: 10 },
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a fallback PATCH after the POST conflict");
    assertEquals(patch!.path, "/rest/subscriptions/raced1");
    assertEquals(captured.data!.action, "updated");
  } finally {
    restore();
  }
});

// (T7) re-GET returns 0 after a failed create => throws (unconfirmable).
Deno.test("upsertRecord: create failure with no raced record throws (unconfirmable)", async () => {
  const { restore } = stubTwentyFetchStatus((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return { payload: REC_META };
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      return { payload: { data: { subscriptions: [] } } };
    }
    if (method === "POST") return { status: 500, payload: { error: "boom" } };
    return { payload: {} };
  });
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            ...REC_BASE,
            fields: { mrr: 10 },
            confirm: true,
            dryRun: false,
          } as never,
          ctx as never,
        ),
      Error,
      "unconfirmable",
    );
  } finally {
    restore();
  }
});

// (T8) ambiguous 2 hits on the initial find => throws, no write.
Deno.test("upsertRecord: ambiguous natural key (2 hits) throws before any write", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      return { data: { subscriptions: [{ id: "a" }, { id: "b" }] } };
    }
    return {};
  });
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            ...REC_BASE,
            fields: { mrr: 10 },
            confirm: true,
            dryRun: false,
          } as never,
          ctx as never,
        ),
      Error,
      "Ambiguous natural key",
    );
    assertEquals(
      calls.find((c) => c.method === "POST" || c.method === "PATCH"),
      undefined,
    );
  } finally {
    restore();
  }
});

// (T9) standard / non-allowlisted object => throws before any I/O.
Deno.test("upsertRecord: a non-allowlisted object throws before any I/O", async () => {
  const { calls, restore } = stubTwentyFetch(() => ({}));
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            objectNameSingular: "person",
            matchField: "email",
            matchValue: "x@y.com",
            fields: {},
            confirm: true,
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
      "not upsertable",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

// (T10) matchField failing FIELD_NAME_RE => throws before any I/O.
Deno.test("upsertRecord: a malformed matchField throws before any I/O", async () => {
  const { calls, restore } = stubTwentyFetch(() => ({}));
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            ...REC_BASE,
            matchField: "bad-field!",
            fields: {},
            confirm: true,
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
      "Invalid matchField",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

// (T11) reserved field name (matchField or a fields key) => throws before I/O.
Deno.test("upsertRecord: reserved field names are rejected before any I/O", async () => {
  const { calls, restore } = stubTwentyFetch(() => ({}));
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            ...REC_BASE,
            matchField: "id",
            fields: {},
            confirm: true,
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
      "reserved",
    );
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            ...REC_BASE,
            fields: { deletedAt: "2020-01-01" },
            confirm: true,
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
      "reserved",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

// (T12) unknown field name => throws (fail-closed).
Deno.test("upsertRecord: an unknown field is rejected fail-closed", async () => {
  const { calls, restore } = stubTwentyFetch((_method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    return {};
  });
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            ...REC_BASE,
            fields: { totallyMadeUp: "x" },
            confirm: true,
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
      "Unknown field",
    );
    assertEquals(
      calls.find((c) => c.method === "POST" || c.method === "PATCH"),
      undefined,
    );
  } finally {
    restore();
  }
});

// (T13) composite field type (CURRENCY) => throws with a clear pre-write error.
Deno.test("upsertRecord: a composite field type is rejected pre-write", async () => {
  const { calls, restore } = stubTwentyFetch((_method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    return {};
  });
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            ...REC_BASE,
            fields: { monthlyValue: 5 },
            confirm: true,
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
      "non-scalar type 'CURRENCY'",
    );
    assertEquals(
      calls.find((c) => c.method === "POST" || c.method === "PATCH"),
      undefined,
    );
  } finally {
    restore();
  }
});

// (T14) filter-unsafe canonical matchValue => throws before any I/O.
Deno.test("upsertRecord: a filter-unsafe matchValue throws before any I/O", async () => {
  const { calls, restore } = stubTwentyFetch(() => ({}));
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            ...REC_BASE,
            matchValue: "a[eq]:b",
            fields: {},
            confirm: true,
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
      "filter-unsafe",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

// (T15) refuses a real run without confirm (redundant with T1, kept explicit).
Deno.test("upsertRecord: refuses a real run without confirm:true", async () => {
  const { ctx } = makeRecCtx();
  await assertRejects(
    () =>
      model.methods.upsertRecord.execute(
        {
          ...REC_BASE,
          fields: { mrr: 1 },
          confirm: false,
          dryRun: false,
        } as never,
        ctx as never,
      ),
    Error,
    "confirm:true",
  );
});

// (T16) string fields sanitized; stored matchValue == searched matchValue.
Deno.test("upsertRecord: string fields sanitized; stored value == searched value", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      return { data: { subscriptions: [] } };
    }
    if (method === "POST") {
      return { data: { createSubscription: { id: "s1" } } };
    }
    return {};
  });
  const { ctx } = makeRecCtx();
  try {
    await model.methods.upsertRecord.execute(
      {
        objectNameSingular: "subscription",
        matchField: "invoiceNinjaClientRef",
        matchValue: "  ref-<b>42</b>  ",
        fields: { name: "<i>Acme</i> Corp" },
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    // sanitizeText strips tags + collapses whitespace: "  ref-<b>42</b>  " -> "ref- 42".
    const canonical = "ref- 42";
    const find = calls.find((c) =>
      c.method === "GET" && c.path.startsWith("/rest/subscriptions")
    );
    const post = calls.find((c) => c.method === "POST");
    assert(find && post, "expected a find GET and a create POST");
    // The find filter encodes the SAME canonical bytes the create body stores.
    assert(find!.path.includes(encodeURIComponent(canonical)), find!.path);
    const body = post!.body as Record<string, unknown>;
    assertEquals(body.invoiceNinjaClientRef, canonical);
    assertEquals(body.name, "Acme Corp"); // tags stripped
  } finally {
    restore();
  }
});

// (T17) redactError applied to a thrown Twenty 4xx — no token/value leak.
Deno.test("upsertRecord: a thrown Twenty 4xx leaks neither the token nor submitted values", async () => {
  const secretToken = "tok"; // matches makeRecCtx apiToken
  const { restore } = stubTwentyFetchStatus((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return { payload: REC_META };
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      // 4xx whose body echoes both the bearer token and the submitted value.
      return {
        status: 400,
        payload:
          `duplicate for value client-abc-123 with Bearer ${secretToken} and user bob@example.com`,
      };
    }
    return { payload: {} };
  });
  const { ctx } = makeRecCtx();
  try {
    const err = await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            ...REC_BASE,
            fields: { mrr: 1 },
            confirm: true,
            dryRun: false,
          } as never,
          ctx as never,
        ),
      Error,
    );
    const msg = (err as Error).message;
    assertEquals(msg.includes("client-abc-123"), false); // submitted value scrubbed
    assertEquals(msg.includes("bob@example.com"), false); // echoed PII scrubbed
    assert(!/Bearer\s+tok\b/.test(msg), "bearer token must be redacted");
  } finally {
    restore();
  }
});

// (Extra A — resolution #3) snapshot name uses the hash, not the raw matchValue.
Deno.test("upsertRecord: snapshot instance name uses the hash, never the raw value", async () => {
  const { restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      return { data: { subscriptions: [] } };
    }
    return {};
  });
  const { ctx, captured } = makeRecCtx();
  try {
    // A distinctive raw value we can grep for across the WHOLE serialized
    // snapshot (finding #1: it must not appear anywhere, incl. creationPayload).
    const rawValue = "client-secret-natural-key-9x7z";
    await model.methods.upsertRecord.execute(
      {
        objectNameSingular: "subscription",
        matchField: "invoiceNinjaClientRef",
        matchValue: rawValue,
        fields: { mrr: 1 },
        confirm: false,
        dryRun: true,
      } as never,
      ctx as never,
    );
    const hash = await listInstanceHash({
      object: "subscription",
      matchField: "invoiceNinjaClientRef",
      matchValue: rawValue,
    });
    assertEquals(captured.spec, "recordUpserted");
    assertEquals(captured.name, `record-subscription-${hash}`);
    assertEquals(captured.data!.matchValueHash, hash);
    assertEquals(
      "matchValue" in (captured.data as Record<string, unknown>),
      false,
    );
    // creationPayload stores the matchField as the hash placeholder, not raw.
    const payload = captured.data!.creationPayload as Record<string, unknown>;
    assertEquals(payload.invoiceNinjaClientRef, `[hashed:${hash}]`);
    // The raw value must not appear ANYWHERE in the persisted attributes.
    const serialized = JSON.stringify(captured.data);
    assertEquals(serialized.includes(rawValue), false);
  } finally {
    restore();
  }
});

// (Extra B — resolution #1) matchField carried in `fields` never rewrites the key.
Deno.test("upsertRecord: matchField carried in fields is stripped (never rewrites the natural key)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      return { data: { subscriptions: [] } };
    }
    if (method === "POST") {
      return { data: { createSubscription: { id: "s1" } } };
    }
    return {};
  });
  const { ctx } = makeRecCtx();
  try {
    await model.methods.upsertRecord.execute(
      {
        ...REC_BASE,
        fields: { invoiceNinjaClientRef: "HIJACKED", mrr: 7 },
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    const post = calls.find((c) => c.method === "POST");
    assert(post, "expected a create POST");
    const body = post!.body as Record<string, unknown>;
    // The natural key is the canonical matchValue, NOT the value smuggled in fields.
    assertEquals(body.invoiceNinjaClientRef, "client-abc-123");
    assertEquals(body.mrr, 7);
  } finally {
    restore();
  }
});

// (Extra C — resolution #5) a SELECT value outside the live enum is rejected.
Deno.test("upsertRecord: a SELECT value outside the live enum is rejected", async () => {
  const { restore } = stubTwentyFetch((_method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    return {};
  });
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            ...REC_BASE,
            fields: { status: "BOGUS" },
            confirm: true,
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
      // The submitted value is scrubbed by the error redaction (resolution #2),
      // so assert on the stable field-name portion of the message.
      "for SELECT field 'status'. Valid options: DRAFT, ACTIVE, CHURNED",
    );
  } finally {
    restore();
  }
});

// (Extra D — resolution #4) a matchField that is not on the object is rejected.
Deno.test("upsertRecord: a matchField absent from the object metadata is rejected", async () => {
  const { restore } = stubTwentyFetch((_method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    return {};
  });
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            ...REC_BASE,
            matchField: "notARealField",
            fields: {},
            confirm: true,
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
      "does not exist on object",
    );
  } finally {
    restore();
  }
});

// (Finding #2) hostile identifiers are sanitized in pre-I/O error messages:
// control chars / ANSI escapes stripped and length hard-capped, so nothing
// unbounded or escape-laden lands in the durable method-summary report.
Deno.test("upsertRecord: hostile identifiers are sanitized (bounded, no control chars) in pre-I/O throws", async () => {
  const { calls, restore } = stubTwentyFetch(() => ({}));
  const { ctx } = makeRecCtx();
  const CONTROL = /[\x00-\x1f]/;
  try {
    // Hostile object name: ANSI escape + newline + a huge blob.
    const hostileObject = "\x1b[31mevil\npwn" + "A".repeat(5000);
    const objErr = await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            objectNameSingular: hostileObject,
            matchField: "invoiceNinjaClientRef",
            matchValue: "x-1",
            fields: {},
            confirm: true,
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
    );
    const m1 = (objErr as Error).message;
    assertEquals(CONTROL.test(m1), false); // no control chars / ESC
    assert(m1.length < 200, `message should be bounded, got ${m1.length}`);

    // Hostile fields key gets the same treatment (fails FIELD_NAME_RE, echoed).
    const keyErr = await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            objectNameSingular: "subscription",
            matchField: "invoiceNinjaClientRef",
            matchValue: "x-1",
            fields: { ["\x1b[0mbad\nkey" + "B".repeat(5000)]: "v" },
            confirm: true,
            dryRun: true,
          } as never,
          ctx as never,
        ),
      Error,
    );
    const m2 = (keyErr as Error).message;
    assertEquals(CONTROL.test(m2), false);
    assert(m2.length < 200, `message should be bounded, got ${m2.length}`);

    assertEquals(calls.length, 0); // rejected before any I/O
  } finally {
    restore();
  }
});

// (Finding #3) create succeeded but the response envelope carried no id, and the
// authoritative re-GET is ambiguous (2 rows) => throw, never 'created' w/o id.
Deno.test("upsertRecord: no-id create envelope with an ambiguous re-GET throws", async () => {
  let getCount = 0;
  const { restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      getCount++;
      // 1st find => empty (go create); the no-id re-GET => 2 rows (ambiguous).
      return {
        data: {
          subscriptions: getCount === 1 ? [] : [{ id: "a" }, { id: "b" }],
        },
      };
    }
    // POST succeeds but returns an envelope with NO id.
    if (method === "POST") return { data: { createSubscription: {} } };
    return {};
  });
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            ...REC_BASE,
            fields: { mrr: 1 },
            confirm: true,
            dryRun: false,
          } as never,
          ctx as never,
        ),
      Error,
      "refusing to guess the created record's id",
    );
  } finally {
    restore();
  }
});

// (Finding #4) a SELECT matchField whose matchValue is outside the live enum is
// rejected pre-write (same enum path used for `fields` SELECT values).
Deno.test("upsertRecord: a SELECT matchField with an out-of-enum matchValue throws before any write", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return REC_META;
    if (method === "GET" && path.startsWith("/rest/subscriptions")) {
      return { data: { subscriptions: [] } };
    }
    return {};
  });
  const { ctx } = makeRecCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertRecord.execute(
          {
            objectNameSingular: "subscription",
            matchField: "status",
            matchValue: "BOGUS",
            fields: {},
            confirm: true,
            dryRun: false,
          } as never,
          ctx as never,
        ),
      Error,
      "SELECT matchField 'status'. Valid options: DRAFT, ACTIVE, CHURNED",
    );
    assertEquals(
      calls.find((c) => c.method === "POST" || c.method === "PATCH"),
      undefined,
    );
  } finally {
    restore();
  }
});

// --- TWENTY-DASHBOARDS: aggregateOppViews + twentyGraphQL guard --------------

// Compact OppView factory for aggregation tests. `name` is set (and deliberately
// ignored by the aggregator) to prove the metrics are PII-free.
function ov(
  stage: string,
  extra: Partial<{
    amount: number;
    currencyCode: string;
    lineOfBusiness: string;
    sourceChannel: string;
    isEmergency: boolean;
  }> = {},
) {
  return { id: crypto.randomUUID(), name: "Ignored Co", stage, ...extra };
}

Deno.test("aggregateOppViews: win = CUSTOMER + CLOSED_WON, lost = CLOSED_LOST (AD1)", () => {
  const agg = aggregateOppViews([
    ov("CUSTOMER"),
    ov("CUSTOMER"),
    ov("CLOSED_WON"),
    ov("CLOSED_LOST"),
    ov("NEW"),
  ]);
  assertEquals(agg.winLoss.won, 3); // 2 CUSTOMER + 1 CLOSED_WON
  assertEquals(agg.winLoss.lost, 1);
  assertEquals(agg.winLoss.winRate, 0.75);
  assertEquals(agg.activeCustomers, 2);
});

Deno.test("aggregateOppViews: winRate is null on 0/0, never a crash (AD1)", () => {
  const agg = aggregateOppViews([ov("NEW"), ov("SCREENING")]);
  assertEquals(agg.winLoss.won, 0);
  assertEquals(agg.winLoss.lost, 0);
  assertEquals(agg.winLoss.winRate, null);
});

Deno.test("aggregateOppViews: legacy CLOSED gets its own bucket, not dropped (AD2)", () => {
  const agg = aggregateOppViews([ov("NEW"), ov("CLOSED"), ov("CUSTOMER")]);
  const closed = agg.byStage.find((b) => b.stage === "CLOSED");
  assert(closed, "legacy CLOSED must appear as its own observed bucket");
  assertEquals(closed?.count, 1);
  // ...and never counts toward open / won / lost.
  assertEquals(agg.openPipeline.count, 1); // only NEW
  assertEquals(agg.winLoss.won, 1); // only CUSTOMER
  assertEquals(agg.winLoss.lost, 0);
});

Deno.test("aggregateOppViews: null sourceChannel -> UNATTRIBUTED (AD3)", () => {
  const agg = aggregateOppViews([
    ov("NEW", { sourceChannel: "DIRECT" }),
    ov("NEW"),
    ov("NEW"),
  ]);
  const unattr = agg.bySourceChannel.find((b) =>
    b.sourceChannel === "UNATTRIBUTED"
  );
  assertEquals(unattr?.count, 2);
  assertEquals(
    agg.bySourceChannel.find((b) => b.sourceChannel === "DIRECT")?.count,
    1,
  );
});

Deno.test("aggregateOppViews: per-currency sums, no cross-currency add (AD11)", () => {
  const agg = aggregateOppViews([
    ov("NEW", { amount: 100, currencyCode: "USD" }),
    ov("SCREENING", { amount: 200, currencyCode: "USD" }),
    ov("PROPOSAL", { amount: 50, currencyCode: "EUR" }),
  ]);
  // sorted by currency: EUR then USD; never a single blended number.
  assertEquals(agg.openPipeline.count, 3);
  assertEquals(agg.openPipeline.amounts, [
    { currency: "EUR", amount: 50 },
    { currency: "USD", amount: 300 },
  ]);
  assertEquals(agg.currencies, ["EUR", "USD"]);
});

Deno.test("aggregateOppViews: isEmergency excluded by default, counted with flag (SE4)", () => {
  const views = [
    ov("NEW"),
    ov("NEW", { isEmergency: true }),
  ];
  const def = aggregateOppViews(views);
  assertEquals(def.totalOpps, 1);
  assertEquals(def.emergencyExcluded, 1);

  const incl = aggregateOppViews(views, { includeEmergency: true });
  assertEquals(incl.totalOpps, 2);
  assertEquals(incl.emergencyExcluded, 0);
});

Deno.test("aggregateOppViews: lineOfBusiness grouped by observed value incl UNSET (AD10)", () => {
  const agg = aggregateOppViews([
    ov("NEW", { lineOfBusiness: "CONSULTING" }),
    ov("NEW", { lineOfBusiness: "HOSTING" }),
    ov("NEW"), // no LOB -> UNSET
  ]);
  assertEquals(
    agg.byLineOfBusiness.find((b) => b.lineOfBusiness === "UNSET")?.count,
    1,
  );
  assertEquals(agg.byLineOfBusiness.length, 3);
});

Deno.test("OppAggregatesSchema round-trips an aggregate snapshot", () => {
  const agg = aggregateOppViews([
    ov("NEW", { amount: 100, currencyCode: "USD", sourceChannel: "DIRECT" }),
    ov("CLOSED_WON", { amount: 500, currencyCode: "USD" }),
  ]);
  const snap = {
    baseUrl: "https://crm.example.com",
    source: "rest" as const,
    truncated: false,
    includeEmergency: false,
    ...agg,
    graphqlProbe: {
      attempted: true,
      ok: true,
      serverSumMicros: 600000000,
      crossCheck: "match" as const,
    },
    retrievedAt: new Date().toISOString(),
  };
  const parsed = OppAggregatesSchema.parse(snap);
  assertEquals(parsed.totalOpps, 2);
  assertEquals(parsed.winLoss.won, 1);
  assertEquals(parsed.graphqlProbe.crossCheck, "match");
  assertEquals(parsed.source, "rest");
});

Deno.test("twentyGraphQL refuses mutation/subscription operations (read-only)", async () => {
  const cfg = { baseUrl: "https://crm.example.com", apiToken: "tok" };
  await assertRejects(
    () => twentyGraphQL(cfg, "mutation { createFoo(x: 1) { id } }"),
    Error,
    "read-only",
  );
  await assertRejects(
    () => twentyGraphQL(cfg, "  subscription { onFoo { id } }"),
    Error,
    "read-only",
  );
  // A leading comment must not smuggle a mutation past the guard.
  await assertRejects(
    () => twentyGraphQL(cfg, "# sneaky\nmutation { drop { id } }"),
    Error,
    "read-only",
  );
});

Deno.test("twentyGraphQL refuses a mutation in a multi-op document (CR-A-L2)", async () => {
  const cfg = { baseUrl: "https://crm.example.com", apiToken: "t" };
  await assertRejects(
    () =>
      twentyGraphQL(
        cfg,
        "query Q { opportunities { totalCount } } mutation M { deleteAll { id } }",
      ),
    Error,
    "read-only",
  );
});

Deno.test("parseMicros: number, bigint-string, and bad values (CR-A-L3)", () => {
  assertEquals(parseMicros(214470210000), 214470210000);
  assertEquals(parseMicros("214470210000"), 214470210000);
  assertEquals(parseMicros("-5"), -5);
  assertEquals(parseMicros("1.5"), null);
  assertEquals(parseMicros("abc"), null);
  assertEquals(parseMicros(Infinity), null);
  assertEquals(parseMicros(null), null);
});

Deno.test("aggregateOppViews: amount without currency -> UNKNOWN bucket, listed in currencies (CR-A-L4)", () => {
  const agg = aggregateOppViews([ov("NEW", { amount: 100 })]); // no currencyCode
  assert(agg.currencies.includes("UNKNOWN"));
  assertEquals(
    agg.openPipeline.amounts.find((a) => a.currency === "UNKNOWN")?.amount,
    100,
  );
});

Deno.test("acquireOppRowsGraphQL: dedups across pages + truncates on a repeat cursor (CR-A-H1/M1)", async () => {
  const { restore } = stubTwentyFetch((_m, _p, body) => {
    const after =
      (body as { variables?: { after?: string | null } })?.variables?.after ??
        null;
    if (after === null) {
      return {
        data: {
          opportunities: {
            totalCount: 3,
            sumAmountAmountMicros: 0,
            edges: [
              { node: { id: "a", stage: "NEW" } },
              { node: { id: "b", stage: "NEW" } },
            ],
            pageInfo: { hasNextPage: true, endCursor: "c1" },
          },
        },
      };
    }
    // Second page REPEATS endCursor c1 (broken cursor) and re-emits b.
    return {
      data: {
        opportunities: {
          totalCount: 3,
          sumAmountAmountMicros: 0,
          edges: [
            { node: { id: "b", stage: "NEW" } },
            { node: { id: "c", stage: "NEW" } },
          ],
          pageInfo: { hasNextPage: true, endCursor: "c1" },
        },
      },
    };
  });
  try {
    const r = await acquireOppRowsGraphQL({
      baseUrl: "https://crm.example.com",
      apiToken: "t",
    });
    assertEquals(r.rows.map((x) => x.id), ["a", "b", "c"]); // b deduped
    assertEquals(r.truncated, true); // stopped w/ hasNextPage still true
    assertEquals(r.serverTotalCount, 3);
  } finally {
    restore();
  }
});

Deno.test("acquireOppRowsGraphQL: full sweep reports truncated=false; tolerant micros (CR-A-H1/L3)", async () => {
  const { restore } = stubTwentyFetch(() => ({
    data: {
      opportunities: {
        totalCount: 2,
        sumAmountAmountMicros: "5", // BIGINT-as-string
        edges: [
          { node: { id: "a", stage: "NEW" } },
          { node: { id: "b", stage: "CUSTOMER" } },
        ],
        pageInfo: { hasNextPage: false },
      },
    },
  }));
  try {
    const r = await acquireOppRowsGraphQL({
      baseUrl: "https://crm.example.com",
      apiToken: "t",
    });
    assertEquals(r.rows.length, 2);
    assertEquals(r.truncated, false);
    assertEquals(r.serverSumMicros, 5);
  } finally {
    restore();
  }
});

// ===========================================================================
// TWENTY-VIEW-MGMT — opportunity view management (pure logic)
//
// Fixtures are depersonalized: fabricated UUIDs (never the live workspace ids),
// generic view names, and the product taxonomy enum tokens (stage / LOB) which
// are not counterparty data. The viewFilter shapes mirror the two forms observed
// live in Phase 0: a real JSON array value AND a stringified-array value.
// ===========================================================================

const VM_STAGE_FID = "11111111-1111-1111-1111-111111111111";
const VM_LOB_FID = "22222222-2222-2222-2222-222222222222";
const VM_STAGE_META = {
  fieldMetadataId: VM_STAGE_FID,
  options: [
    "NEW",
    "SCREENING",
    "MEETING",
    "PROPOSAL",
    "CUSTOMER",
    "CLOSED_WON",
    "CLOSED_LOST",
    "ON_HOLD",
  ],
};
const VM_LOB_META = {
  fieldMetadataId: VM_LOB_FID,
  options: ["CONSULTING", "HOSTING", "GAMES", "NETWORK_PROVIDER", "LOCAL_IT"],
};
const vmSalesTarget = OPP_VIEW_TARGETS.find((t) =>
  t.name === "Sales Pipeline"
)!;
const vmConsultingTarget = OPP_VIEW_TARGETS.find((t) =>
  t.name === "Consulting"
)!;

// deno-lint-ignore no-explicit-any
function vmView(over: Record<string, unknown>): any {
  return {
    id: "aaaaaaaa-0000-0000-0000-000000000000",
    name: "Sales Pipeline",
    key: null,
    isSystemSideEffect: false,
    isCustom: true,
    objectMetadataId: "9b39e87c-0000-0000-0000-000000000000",
    filters: [],
    ...over,
  };
}

Deno.test("VIEW-MGMT OPP_VIEW_TARGETS: Sales Pipeline enumerates open stages positively", () => {
  assertEquals(vmSalesTarget.field, "stage");
  assertEquals([...vmSalesTarget.values], [
    "NEW",
    "SCREENING",
    "MEETING",
    "PROPOSAL",
  ]);
  // No terminal / won / parked stage leaks into the pipeline board (A1/A2).
  for (
    const t of ["CUSTOMER", "CLOSED_WON", "CLOSED_LOST", "ON_HOLD", "CLOSED"]
  ) {
    assert(!vmSalesTarget.values.includes(t), `open set must exclude ${t}`);
  }
  // Exactly the four re-scoped views; no provider view (F7 void).
  assertEquals(OPP_VIEW_TARGETS.map((t) => t.name), [
    "Sales Pipeline",
    "Consulting",
    "Hosting",
    "Local IT",
  ]);
  assert(!OPP_VIEW_TARGETS.some((t) => t.values.includes("NETWORK_PROVIDER")));
});

Deno.test("VIEW-MGMT buildViewFilterValue: returns a fresh token array (single point of control)", () => {
  const v = buildViewFilterValue(["NEW", "SCREENING"]);
  assertEquals(v, ["NEW", "SCREENING"]);
  // A copy, not the caller's array.
  const src = ["A", "B"];
  assert(buildViewFilterValue(src) !== src);
});

Deno.test("VIEW-MGMT normalizeFilterValueTokens: handles both live-observed value forms", () => {
  // Real JSON array (UI-created reference filter).
  assertEquals(normalizeFilterValueTokens(["CUSTOMER"]), ["CUSTOMER"]);
  // Stringified array (the other live form).
  assertEquals(normalizeFilterValueTokens('["NETWORK_PROVIDER"]'), [
    "NETWORK_PROVIDER",
  ]);
  assertEquals(
    normalizeFilterValueTokens('["NEW","SCREENING","MEETING","PROPOSAL"]'),
    ["NEW", "SCREENING", "MEETING", "PROPOSAL"],
  );
  // Bare scalar string / empties.
  assertEquals(normalizeFilterValueTokens("CUSTOMER"), ["CUSTOMER"]);
  assertEquals(normalizeFilterValueTokens(""), []);
  assertEquals(normalizeFilterValueTokens(null), []);
  assertEquals(normalizeFilterValueTokens(undefined), []);
  // Malformed stringified array falls back to the raw string, not a throw.
  assertEquals(normalizeFilterValueTokens("[oops"), ["[oops"]);
});

Deno.test("VIEW-MGMT plan: absent name → create with resolved id + IS operand", () => {
  const p = planOpportunityView(vmSalesTarget, VM_STAGE_META, []);
  assertEquals(p.action, "create");
  assertEquals(p.fieldMetadataId, VM_STAGE_FID);
  assertEquals(p.operand, "IS");
  assertEquals(p.desiredValues, ["NEW", "SCREENING", "MEETING", "PROPOSAL"]);
});

Deno.test("VIEW-MGMT plan: present with matching filter (array form) → noop", () => {
  const existing = [vmView({
    filters: [{
      id: "f1",
      fieldMetadataId: VM_STAGE_FID,
      operand: "IS",
      value: ["NEW", "SCREENING", "MEETING", "PROPOSAL"],
    }],
  })];
  const p = planOpportunityView(vmSalesTarget, VM_STAGE_META, existing);
  assertEquals(p.action, "noop");
  assertEquals(p.viewId, "aaaaaaaa-0000-0000-0000-000000000000");
});

Deno.test("VIEW-MGMT plan: present with matching filter (stringified + reordered) → noop", () => {
  const existing = [vmView({
    filters: [{
      id: "f1",
      fieldMetadataId: VM_STAGE_FID,
      operand: "IS",
      // stringified AND out of order — set-equality is order-independent.
      value: '["PROPOSAL","NEW","MEETING","SCREENING"]',
    }],
  })];
  assertEquals(
    planOpportunityView(vmSalesTarget, VM_STAGE_META, existing).action,
    "noop",
  );
});

Deno.test("VIEW-MGMT plan: present with DIFFERENT filter → refuse, never mutate (F3/A6)", () => {
  const existing = [vmView({
    filters: [{
      id: "f1",
      fieldMetadataId: VM_STAGE_FID,
      operand: "IS",
      value: ["NEW"], // drifted / narrower
    }],
  })];
  const p = planOpportunityView(vmSalesTarget, VM_STAGE_META, existing);
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("not mutating a pre-existing view"));
});

Deno.test("VIEW-MGMT plan: locked/system views are refused (F2)", () => {
  // key === "INDEX" (default view marker).
  assertEquals(
    planOpportunityView(vmSalesTarget, VM_STAGE_META, [
      vmView({ key: "INDEX", isSystemSideEffect: true, isCustom: false }),
    ]).action,
    "refuse",
  );
  // isSystemSideEffect === true alone.
  assertEquals(
    planOpportunityView(vmSalesTarget, VM_STAGE_META, [
      vmView({ isSystemSideEffect: true }),
    ]).action,
    "refuse",
  );
  // isCustom === false alone.
  assertEquals(
    planOpportunityView(vmSalesTarget, VM_STAGE_META, [
      vmView({ isCustom: false }),
    ]).action,
    "refuse",
  );
});

Deno.test("VIEW-MGMT plan: >1 same-named view → refuse (ambiguous)", () => {
  const p = planOpportunityView(vmSalesTarget, VM_STAGE_META, [
    vmView({ id: "v1" }),
    vmView({ id: "v2" }),
  ]);
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("ambiguous"));
});

Deno.test("VIEW-MGMT plan: unresolved fieldMetadataId → refuse (F6)", () => {
  assertEquals(
    planOpportunityView(vmSalesTarget, { options: VM_STAGE_META.options }, [])
      .action,
    "refuse",
  );
  assertEquals(
    planOpportunityView(vmSalesTarget, undefined, []).action,
    "refuse",
  );
});

Deno.test("VIEW-MGMT plan: target option absent from live schema → refuse (A5/S1)", () => {
  // stage schema missing PROPOSAL → fail-closed.
  const p = planOpportunityView(vmSalesTarget, {
    fieldMetadataId: VM_STAGE_FID,
    options: ["NEW", "SCREENING", "MEETING"],
  }, []);
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("PROPOSAL"));
  assert(p.reason.includes("A5/S1"));
});

Deno.test("VIEW-MGMT plan: LOB targets resolve against live LOB options", () => {
  const p = planOpportunityView(vmConsultingTarget, VM_LOB_META, []);
  assertEquals(p.action, "create");
  assertEquals(p.desiredValues, ["CONSULTING"]);
  assertEquals(p.fieldMetadataId, VM_LOB_FID);
});

Deno.test("VIEW-MGMT plan: name outside target allowlist → refuse (F10)", () => {
  const p = planOpportunityView(
    { name: "Evil View", field: "stage", values: ["NEW"] },
    VM_STAGE_META,
    [],
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("allowlist"));
});

Deno.test("VIEW-MGMT ViewListSchema round-trips a depersonalized Phase-0 snapshot", () => {
  const snap = {
    baseUrl: "https://crm.example.test",
    probes: [{
      path: "/rest/metadata/views",
      status: 200,
      verdict: "ok" as const,
      count: 1,
      bodySample: "{...}",
    }],
    readPath: "/rest/metadata/views",
    writeEndpointCandidate:
      "POST /rest/metadata/views + POST /rest/metadata/viewFilters",
    opportunityObjectMetadataId: "9b39e87c-0000-0000-0000-000000000000",
    viewCount: 1,
    opportunityViews: [{
      id: "aaaaaaaa-0000-0000-0000-000000000000",
      name: "Open Pipeline",
      type: "TABLE",
      key: null,
      isSystemSideEffect: false,
      position: 0,
      objectMetadataId: "9b39e87c-0000-0000-0000-000000000000",
      filters: [{
        id: "f1",
        fieldMetadataId: VM_LOB_FID,
        operand: "IS_NOT",
        value: '["NETWORK_PROVIDER"]',
        subFieldName: null,
        viewFilterGroupId: null,
      }],
    }],
    lockFlagObserved: 'default/locked index view detected via key==="INDEX"',
    filterFields: {
      stage: {
        fieldMetadataId: VM_STAGE_FID,
        type: "SELECT",
        options: VM_STAGE_META.options,
      },
    },
    uncoveredStageOptions: ["CUSTOMER", "CLOSED_WON", "CLOSED_LOST", "ON_HOLD"],
    sample: "{...}",
    retrievedAt: "2026-09-17T07:00:00.000Z",
  };
  const parsed = ViewListSchema.parse(snap);
  assertEquals(parsed.readPath, "/rest/metadata/views");
  assertEquals(parsed.opportunityViews[0].filters?.[0].operand, "IS_NOT");
});

Deno.test("VIEW-MGMT ViewEnsuredSchema round-trips a dryRun plan snapshot", () => {
  const snap = {
    baseUrl: "https://crm.example.test",
    dryRun: true,
    confirm: false,
    reachable: true,
    objectMetadataId: "9b39e87c-0000-0000-0000-000000000000",
    results: [{
      target: "Sales Pipeline",
      field: "stage",
      fieldMetadataId: VM_STAGE_FID,
      desiredValues: ["NEW", "SCREENING", "MEETING", "PROPOSAL"],
      operand: "IS",
      action: "create" as const,
      reason: "no opportunity view with this name — create",
    }],
    createdCount: 0,
    refusedCount: 0,
    retrievedAt: "2026-09-17T07:00:00.000Z",
  };
  const parsed = ViewEnsuredSchema.parse(snap);
  assertEquals(parsed.results[0].action, "create");
  assertEquals(parsed.dryRun, true);
});

Deno.test("VIEW-MGMT plan: duplicate-token existing filter is NOT a false noop (L5)", () => {
  // Degenerate live value with dupes, same length as desired but only 1 distinct
  // token — must refuse (differs), not noop.
  const existing = [vmView({
    filters: [{
      id: "f1",
      fieldMetadataId: VM_STAGE_FID,
      operand: "IS",
      value: ["NEW", "NEW", "NEW", "NEW"],
    }],
  })];
  assertEquals(
    planOpportunityView(vmSalesTarget, VM_STAGE_META, existing).action,
    "refuse",
  );
});

Deno.test("VIEW-MGMT plan: empty-string key is treated as locked (L3, fail-closed)", () => {
  assertEquals(
    planOpportunityView(vmSalesTarget, VM_STAGE_META, [vmView({ key: "" })])
      .action,
    "refuse",
  );
});

Deno.test("VIEW-MGMT ensureOpportunityViews(confirm): filter-POST failure rolls back the created view (H1)", async () => {
  // Simulate the expected first-run failure: the view POST succeeds but the
  // filter POST (unconfirmed operand) fails. The method must DELETE the orphan
  // view it just created — never leave a filterless same-named view behind.
  const NEW_ID = "newview-0000-0000-0000-000000000000";
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return {
        data: [{
          nameSingular: "opportunity",
          namePlural: "opportunities",
          id: "opp-oid",
          fields: [
            {
              name: "stage",
              id: "stage-fid",
              type: "SELECT",
              options: [
                { value: "NEW" },
                { value: "SCREENING" },
                { value: "MEETING" },
                { value: "PROPOSAL" },
              ],
            },
            {
              name: "lineOfBusiness",
              id: "lob-fid",
              type: "SELECT",
              options: [{ value: "CONSULTING" }],
            },
          ],
        }],
        pageInfo: { hasNextPage: false },
      };
    }
    if (method === "GET") {
      // reachability probe + fetchMetadataList(views|viewFilters): empty.
      return { data: [], pageInfo: { hasNextPage: false } };
    }
    if (method === "POST" && path === "/rest/metadata/views") {
      return { data: { id: NEW_ID } };
    }
    if (method === "POST" && path === "/rest/metadata/viewFilters") {
      throw new Error("400 operand IS rejected"); // filter write fails
    }
    if (method === "DELETE") return {}; // rollback succeeds
    return {};
  });
  const written: Array<Record<string, unknown>> = [];
  const ctx = {
    globalArgs: { baseUrl: "https://crm.example.com", apiToken: "tok" },
    logger: { debug() {}, info() {}, warning() {}, error() {} },
    writeResource: (_s: string, _n: string, data: Record<string, unknown>) => {
      written.push(data);
      return Promise.resolve({ name: "n" });
    },
    // deno-lint-ignore no-explicit-any
  } as any;
  try {
    await model.methods.ensureOpportunityViews.execute(
      { confirm: true, names: ["Sales Pipeline"] },
      ctx as never,
    );
    // The view was created, then rolled back via DELETE on its exact id.
    const del = calls.find((c) => c.method === "DELETE");
    assert(del, "expected a rollback DELETE");
    assertEquals(del!.path, `/rest/metadata/views/${NEW_ID}`);
    const res = (written[0].results as Array<Record<string, unknown>>)[0];
    assertEquals(res.action, "failed");
    assertEquals(res.viewId, NEW_ID); // audit names the view even on failure
    assert(String(res.reason).includes("rolled back"));
    // Token never leaks into the persisted error (redactError).
    assert(!String(res.error ?? "").includes("tok"));
  } finally {
    restore();
  }
});

// ===========================================================================
// TWENTY-NOTE-MGMT + .17.1 remediation (R1 guard)
// ===========================================================================

// --- R1: isReadOnlyGraphQL (guard hardening) ---
Deno.test("R1 guard: a plain query is read-only", () => {
  assert(
    isReadOnlyGraphQL("query Q { opportunities { edges { node { id } } } }"),
  );
});
Deno.test("R1 guard: an anonymous { ... } selection is a query", () => {
  assert(isReadOnlyGraphQL("{ opportunities { edges { node { id } } } }"));
});
Deno.test("R1 guard: a leading mutation is refused", () => {
  assert(!isReadOnlyGraphQL('mutation M { deleteOpportunity(id:"x") { id } }'));
});
Deno.test("R1 guard: whitespace-separated multi-op mutation is refused", () => {
  assert(
    !isReadOnlyGraphQL("query A { id } mutation Evil { deleteAllData { id } }"),
  );
});
Deno.test("R1 guard: COMMA-separated multi-op mutation is refused (bypass 1)", () => {
  assert(
    !isReadOnlyGraphQL("query A { id },mutation Evil { deleteAllData { id } }"),
  );
});
Deno.test("R1 guard: a # inside a string does NOT hide a later mutation (bypass 2)", () => {
  assert(
    !isReadOnlyGraphQL(
      'query A { field(x: "#") }\nmutation Evil { deleteAllData { id } }',
    ),
  );
});
Deno.test("R1 guard: a block string cannot hide a mutation (bypass 3)", () => {
  assert(
    !isReadOnlyGraphQL(
      'query A { field(x: """ } mutation Hidden { x """) }\nmutation Evil { wipe { id } }',
    ),
  );
});
Deno.test("R1 guard: the word mutation inside a string is NOT a real op", () => {
  assert(isReadOnlyGraphQL('query A { field(note: "please mutation this") }'));
});

// --- note write test helpers ---
const NM_NOTE = "11111111-1111-1111-1111-111111111111";
const TARGET_UUID = "22222222-2222-2222-2222-222222222222";
const ROW_UUID = "33333333-3333-3333-3333-333333333333";

// --- createNote ---
Deno.test("createNote dryRun: planned-create, stable leadId instance, no writes", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus(() => ({}));
  try {
    await model.methods.createNote.execute(
      {
        title: "Kickoff call",
        body: "notes",
        targets: [{ personId: TARGET_UUID }],
        leadId: "L-1",
        dryRun: true,
        confirm: false,
      },
      ctx as never,
    );
    assertEquals(calls.length, 0, "dryRun writes nothing to Twenty");
    assertEquals(writes[0].name, "note-write-lead-L-1");
    assertEquals(writes[0].data.action, "planned-create");
    assertEquals(writes[0].data.bodyLength, 5);
    assert(!("body" in writes[0].data), "snapshot must not carry body text");
  } finally {
    restore();
  }
});

Deno.test("createNote confirm: creates the note + links the target (verified id)", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "POST" && path === "/rest/notes") {
      return { body: { data: { createNote: { id: NM_NOTE } } } };
    }
    if (method === "GET" && path.startsWith("/rest/noteTargets")) {
      return { body: { data: { noteTargets: [] } } };
    }
    if (method === "POST" && path === "/rest/noteTargets") {
      return {
        body: { data: { createNoteTarget: { targetPersonId: TARGET_UUID } } },
      };
    }
    return {};
  });
  try {
    await model.methods.createNote.execute(
      {
        title: "Kickoff",
        targets: [{ personId: TARGET_UUID }],
        dryRun: false,
        confirm: true,
      },
      ctx as never,
    );
    const snap = writes[writes.length - 1].data;
    assertEquals(snap.action, "created");
    assertEquals(snap.id, NM_NOTE);
    assertEquals(snap.targetsLinked, [TARGET_UUID]);
    assert(calls.some((c) => c.method === "POST" && c.path === "/rest/notes"));
  } finally {
    restore();
  }
});

Deno.test("createNote leadId dedup: reuse existing note, no create POST", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/notes?filter=leadId")) {
      return { body: { data: { notes: [{ id: NM_NOTE }] } } };
    }
    if (method === "GET" && path.startsWith("/rest/noteTargets")) {
      return { body: { data: { noteTargets: [] } } };
    }
    return {};
  });
  try {
    await model.methods.createNote.execute(
      { title: "x", leadId: "L-9", dryRun: false, confirm: true },
      ctx as never,
    );
    assertEquals(writes[writes.length - 1].data.action, "present");
    assert(
      !calls.some((c) => c.method === "POST" && c.path === "/rest/notes"),
      "must not POST a new note when leadId already exists",
    );
  } finally {
    restore();
  }
});

Deno.test("createNote: a target with two ids is rejected pre-write", async () => {
  const { ctx } = readCtx();
  const { restore } = stubFetchStatus(() => ({}));
  try {
    await assertRejects(
      () =>
        model.methods.createNote.execute(
          {
            title: "x",
            targets: [{ personId: TARGET_UUID, companyId: NM_NOTE }],
            dryRun: true,
            confirm: false,
          },
          ctx as never,
        ) as Promise<unknown>,
      Error,
      "EXACTLY one",
    );
  } finally {
    restore();
  }
});

// --- A3/S1: a body-echoing 4xx never leaks the submitted content ---
Deno.test("createNote: a 4xx echoing the body throws GENERIC, no body leak (A3/S1)", async () => {
  const { ctx } = readCtx();
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "POST" && path === "/rest/notes") {
      return { status: 400, body: { message: "bad value: SUPERSECRETBODY" } };
    }
    return {};
  });
  try {
    const err = await model.methods.createNote.execute(
      { title: "x", body: "SUPERSECRETBODY", dryRun: false, confirm: true },
      ctx as never,
    ).then(() => null).catch((e) => e as Error);
    assert(err instanceof Error);
    assert(
      !err.message.includes("SUPERSECRETBODY"),
      "submitted body must never appear in the thrown error",
    );
    assert(err.message.includes("status 400"));
  } finally {
    restore();
  }
});

// --- updateNote ---
Deno.test("updateNote: 404 → not-found, no PATCH", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus((method) => {
    if (method === "GET") return { status: 404, body: {} };
    return {};
  });
  try {
    await model.methods.updateNote.execute(
      { noteId: NM_NOTE, title: "new", dryRun: false, confirm: true },
      ctx as never,
    );
    assertEquals(writes[writes.length - 1].data.action, "not-found");
    assert(!calls.some((c) => c.method === "PATCH"));
  } finally {
    restore();
  }
});

// Probe (twenty-local, 2026-09-17): Twenty v2.38.1 RE-DERIVES bodyV2.blocknote
// from a markdown-only write on BOTH create and PATCH, so BODYV2_MARKDOWN_REDERIVES
// is true and updateNote/appendNote write the body even on a note that already
// carries a blocknote (no stale-blocknote lost-update). The refused-blocknote
// branch is a dormant fallback, re-armed only if a future Twenty version regresses
// (flip the flag to false).
Deno.test("updateNote: writes the body on a note carrying blocknote — Twenty re-derives (probe 2026-09-17)", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus((method) => {
    if (method === "GET") {
      return {
        body: {
          data: {
            note: {
              id: NM_NOTE,
              bodyV2: { markdown: "x", blocknote: "[{...}]" },
            },
          },
        },
      };
    }
    if (method === "PATCH") {
      return { body: { data: { updateNote: { id: NM_NOTE } } } };
    }
    return {};
  });
  try {
    await model.methods.updateNote.execute(
      { noteId: NM_NOTE, body: "new", dryRun: false, confirm: true },
      ctx as never,
    );
    assertEquals(writes[writes.length - 1].data.action, "updated");
    assert(
      calls.some((c) => c.method === "PATCH"),
      "must PATCH the body (Twenty re-derives blocknote)",
    );
  } finally {
    restore();
  }
});

Deno.test("updateNote: title+body on a markdown-only note → updated (PATCH sent)", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus((method) => {
    if (method === "GET") {
      return {
        body: {
          data: { note: { id: NM_NOTE, bodyV2: { markdown: "old" } } },
        },
      };
    }
    return {};
  });
  try {
    await model.methods.updateNote.execute(
      {
        noteId: NM_NOTE,
        title: "T",
        body: "B",
        dryRun: false,
        confirm: true,
      },
      ctx as never,
    );
    assertEquals(writes[writes.length - 1].data.action, "updated");
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "a PATCH is sent");
    assertEquals(
      (patch!.body as { bodyV2: { markdown: string } }).bodyV2.markdown,
      "B",
    );
  } finally {
    restore();
  }
});

Deno.test("updateNote: neither title nor body → refuse", async () => {
  const { ctx } = readCtx();
  const { restore } = stubFetchStatus(() => ({}));
  try {
    await assertRejects(
      () =>
        model.methods.updateNote.execute(
          { noteId: NM_NOTE, dryRun: true, confirm: false },
          ctx as never,
        ) as Promise<unknown>,
      Error,
      "title and/or body",
    );
  } finally {
    restore();
  }
});

// SR-1 parity: an unconfirmed / dryRun updateNote must NOT read the note body.
Deno.test("updateNote: dryRun/unconfirmed makes NO body-bearing GET (SR-1 parity)", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus(() => ({}));
  try {
    // dryRun with confirm — still not a real write, so still no read.
    await model.methods.updateNote.execute(
      { noteId: NM_NOTE, title: "T", body: "B", dryRun: true, confirm: true },
      ctx as never,
    );
    assertEquals(calls.length, 0, "a plan must not GET (or PATCH) the note");
    const snap = writes[writes.length - 1].data;
    assertEquals(snap.action, "planned-update");
    assert(!("found" in snap), "a plan does not pre-confirm existence");
  } finally {
    restore();
  }
});

// A3/S1: updateNote's PATCH failure must not echo the submitted body.
Deno.test("updateNote: a 4xx echoing the body throws GENERIC, no body leak (A3/S1)", async () => {
  const { ctx } = readCtx();
  const { restore } = stubFetchStatus((method) => {
    if (method === "GET") {
      return {
        body: { data: { note: { id: NM_NOTE, bodyV2: { markdown: "old" } } } },
      };
    }
    if (method === "PATCH") {
      return { status: 400, body: { message: "bad value: SUPERSECRETBODY" } };
    }
    return {};
  });
  try {
    const err = await model.methods.updateNote.execute(
      {
        noteId: NM_NOTE,
        body: "SUPERSECRETBODY",
        dryRun: false,
        confirm: true,
      },
      ctx as never,
    ).then(() => null).catch((e) => e as Error);
    assert(err instanceof Error);
    assert(
      !err.message.includes("SUPERSECRETBODY"),
      "submitted body must never appear in the thrown error",
    );
    assert(err.message.includes("status 400"));
  } finally {
    restore();
  }
});

// --- appendNote (SR-1) ---
Deno.test("appendNote: dryRun WITHOUT confirm makes NO body read (S2)", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus(() => ({}));
  try {
    await model.methods.appendNote.execute(
      { noteId: NM_NOTE, text: "hi", dryRun: true, confirm: false },
      ctx as never,
    );
    assertEquals(calls.length, 0, "must not GET the body without confirm");
    const snap = writes[writes.length - 1].data;
    assertEquals(snap.action, "planned-append");
    assert(!("bodyLength" in snap), "no bodyLength without a read");
  } finally {
    restore();
  }
});

Deno.test("appendNote: non-dry WITHOUT confirm refuses before any read (S2)", async () => {
  const { ctx } = readCtx();
  const { calls, restore } = stubFetchStatus(() => ({}));
  try {
    await assertRejects(
      () =>
        model.methods.appendNote.execute(
          { noteId: NM_NOTE, text: "hi", dryRun: false, confirm: false },
          ctx as never,
        ) as Promise<unknown>,
      Error,
      "SR-1",
    );
    assertEquals(calls.length, 0, "no read happens on refusal");
  } finally {
    restore();
  }
});

// A3/S1: appendNote's PATCH failure must leak NEITHER the appended text NOR the
// pre-existing (SR-1) body it read to build the merge.
Deno.test("appendNote: a 4xx echoing the merged body leaks neither the pre-existing body nor the append (A3/S1)", async () => {
  const { ctx } = readCtx();
  const { restore } = stubFetchStatus((method) => {
    if (method === "GET") {
      return {
        body: {
          data: {
            note: { id: NM_NOTE, bodyV2: { markdown: "PREEXISTINGSECRET" } },
          },
        },
      };
    }
    if (method === "PATCH") {
      return {
        status: 422,
        body: {
          message: "bad markdown: PREEXISTINGSECRET\n\nSUPERSECRETAPPEND",
        },
      };
    }
    return {};
  });
  try {
    const err = await model.methods.appendNote.execute(
      {
        noteId: NM_NOTE,
        text: "SUPERSECRETAPPEND",
        dryRun: false,
        confirm: true,
      },
      ctx as never,
    ).then(() => null).catch((e) => e as Error);
    assert(err instanceof Error);
    assert(
      !err.message.includes("PREEXISTINGSECRET"),
      "the pre-existing SR-1 body must never appear in the thrown error",
    );
    assert(
      !err.message.includes("SUPERSECRETAPPEND"),
      "the appended text must never appear in the thrown error",
    );
    assert(err.message.includes("status 422"));
  } finally {
    restore();
  }
});

Deno.test("appendNote confirm: merges old + new with a blank line", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus((method) => {
    if (method === "GET") {
      return {
        body: {
          data: { note: { id: NM_NOTE, bodyV2: { markdown: "AAA\n" } } },
        },
      };
    }
    return {};
  });
  try {
    await model.methods.appendNote.execute(
      { noteId: NM_NOTE, text: "BBB", dryRun: false, confirm: true },
      ctx as never,
    );
    assertEquals(writes[writes.length - 1].data.action, "appended");
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(
      (patch!.body as { bodyV2: { markdown: string } }).bodyV2.markdown,
      "AAA\n\nBBB",
    );
  } finally {
    restore();
  }
});

Deno.test("appendNote confirm: bodyMissing note → text alone, no separator", async () => {
  const { calls, restore } = stubFetchStatus((method) => {
    if (method === "GET") {
      return { body: { data: { note: { id: NM_NOTE, bodyV2: null } } } };
    }
    return {};
  });
  const { ctx } = readCtx();
  try {
    await model.methods.appendNote.execute(
      { noteId: NM_NOTE, text: "BBB", dryRun: false, confirm: true },
      ctx as never,
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assertEquals(
      (patch!.body as { bodyV2: { markdown: string } }).bodyV2.markdown,
      "BBB",
    );
  } finally {
    restore();
  }
});

// --- linkNote / unlinkNote (A4 exact match) ---
Deno.test("linkNote: already-linked (exact id) is an idempotent no-op", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/noteTargets")) {
      return {
        body: {
          data: {
            noteTargets: [{ id: ROW_UUID, targetPersonId: TARGET_UUID }],
          },
        },
      };
    }
    return {};
  });
  try {
    await model.methods.linkNote.execute(
      {
        noteId: NM_NOTE,
        target: { personId: TARGET_UUID },
        dryRun: false,
        confirm: true,
      },
      ctx as never,
    );
    assertEquals(writes[writes.length - 1].data.action, "already-linked");
    assert(
      !calls.some((c) => c.method === "POST"),
      "no POST when already linked",
    );
  } finally {
    restore();
  }
});

Deno.test("linkNote: a DIFFERENT person is linked (exact match, not any-of-kind — A4)", async () => {
  const { writes, ctx } = readCtx();
  const other = "44444444-4444-4444-4444-444444444444";
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/noteTargets")) {
      return {
        body: {
          data: { noteTargets: [{ id: ROW_UUID, targetPersonId: other }] },
        },
      };
    }
    if (method === "POST" && path === "/rest/noteTargets") {
      return {
        body: { data: { createNoteTarget: { targetPersonId: TARGET_UUID } } },
      };
    }
    return {};
  });
  try {
    await model.methods.linkNote.execute(
      {
        noteId: NM_NOTE,
        target: { personId: TARGET_UUID },
        dryRun: false,
        confirm: true,
      },
      ctx as never,
    );
    assertEquals(writes[writes.length - 1].data.action, "linked");
    assert(
      calls.some((c) => c.method === "POST" && c.path === "/rest/noteTargets"),
      "must POST — a different person being linked is not a no-op",
    );
  } finally {
    restore();
  }
});

Deno.test("unlinkNote: deletes ONLY the matching row", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/noteTargets")) {
      return {
        body: {
          data: {
            noteTargets: [{ id: ROW_UUID, targetPersonId: TARGET_UUID }],
          },
        },
      };
    }
    return {};
  });
  try {
    await model.methods.unlinkNote.execute(
      {
        noteId: NM_NOTE,
        target: { personId: TARGET_UUID },
        dryRun: false,
        confirm: true,
      },
      ctx as never,
    );
    assertEquals(writes[writes.length - 1].data.action, "unlinked");
    assert(
      calls.some((c) =>
        c.method === "DELETE" && c.path === `/rest/noteTargets/${ROW_UUID}`
      ),
      "DELETEs the exact matching row id",
    );
  } finally {
    restore();
  }
});

Deno.test("unlinkNote: target absent → not-linked, no DELETE", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/noteTargets")) {
      return { body: { data: { noteTargets: [] } } };
    }
    return {};
  });
  try {
    await model.methods.unlinkNote.execute(
      {
        noteId: NM_NOTE,
        target: { personId: TARGET_UUID },
        dryRun: false,
        confirm: true,
      },
      ctx as never,
    );
    assertEquals(writes[writes.length - 1].data.action, "not-linked");
    assert(!calls.some((c) => c.method === "DELETE"));
  } finally {
    restore();
  }
});

Deno.test("note methods: a non-UUID noteId is rejected pre-I/O", async () => {
  const { ctx } = readCtx();
  const { calls, restore } = stubFetchStatus(() => ({}));
  try {
    await assertRejects(
      () =>
        model.methods.appendNote.execute(
          { noteId: "not-a-uuid", text: "x", dryRun: false, confirm: true },
          ctx as never,
        ) as Promise<unknown>,
      Error,
      "valid UUID",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

// ===========================================================================
// R2 (.17.1 remediation): execute-level tests for aggregateOpportunities +
// listViews (previously helper-only) and the two ensureOpportunityViews
// fail-closed branches (existing-views-unloadable, endpoint-unreachable).
// ===========================================================================

Deno.test("R2 aggregateOpportunities: GraphQL-primary → oppAggregates, crossCheck match, PII-free", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "POST" && path === "/graphql") {
      return {
        body: {
          data: {
            opportunities: {
              totalCount: 2,
              sumAmountAmountMicros: 3000000,
              edges: [
                {
                  node: {
                    id: "PIIOPPID-AAA",
                    stage: "NEW",
                    amount: { amountMicros: 1000000, currencyCode: "USD" },
                    lineOfBusiness: "CONSULTING",
                    sourceChannel: "DIRECT",
                    isEmergency: false,
                  },
                },
                {
                  node: {
                    id: "PIIOPPID-BBB",
                    stage: "CUSTOMER",
                    amount: { amountMicros: 2000000, currencyCode: "USD" },
                    lineOfBusiness: "HOSTING",
                    sourceChannel: "REFERRAL",
                    isEmergency: false,
                  },
                },
              ],
              pageInfo: { hasNextPage: false },
            },
          },
        },
      };
    }
    return {};
  });
  try {
    await model.methods.aggregateOpportunities.execute(
      { includeEmergency: false },
      ctx as never,
    );
    const snap = writes[writes.length - 1];
    assertEquals(snap.type, "oppAggregates");
    assertEquals(snap.data.source, "graphql");
    assertEquals(
      (snap.data.graphqlProbe as { crossCheck: string }).crossCheck,
      "match",
    );
    // The GraphQL path was used (no REST fallback).
    assert(calls.some((c) => c.method === "POST" && c.path === "/graphql"));
    assert(!calls.some((c) => c.path.startsWith("/rest/opportunities")));
    // PII-free: no per-opportunity id may reach the durable snapshot.
    const json = JSON.stringify(snap.data);
    assert(
      !json.includes("PIIOPPID-AAA") && !json.includes("PIIOPPID-BBB"),
      "opp ids must never appear in the oppAggregates snapshot",
    );
  } finally {
    restore();
  }
});

Deno.test("R2 aggregateOpportunities: GraphQL failure → REST fallback (source=rest)", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "POST" && path === "/graphql") {
      return { status: 500, body: { errors: [{ message: "graphql down" }] } };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return {
        body: {
          data: {
            opportunities: [
              {
                id: "r1",
                stage: "NEW",
                amount: { amountMicros: 1000000, currencyCode: "USD" },
              },
            ],
          },
          pageInfo: { hasNextPage: false },
        },
      };
    }
    return {};
  });
  try {
    await model.methods.aggregateOpportunities.execute(
      { includeEmergency: false },
      ctx as never,
    );
    const snap = writes[writes.length - 1];
    assertEquals(snap.type, "oppAggregates");
    assertEquals(snap.data.source, "rest");
    assert(
      calls.some((c) => c.method === "POST" && c.path === "/graphql"),
      "GraphQL is attempted first",
    );
    assert(
      calls.some((c) =>
        c.method === "GET" && c.path.startsWith("/rest/opportunities")
      ),
      "falls back to the REST list",
    );
  } finally {
    restore();
  }
});

Deno.test("R2 listViews: viewList snapshot; sample is field-allowlisted, not a raw dump (R3)", async () => {
  const { writes, ctx } = readCtx();
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return {
        body: {
          data: [{
            nameSingular: "opportunity",
            id: "opp-oid",
            fields: [
              { name: "stage", id: "stage-fid", type: "SELECT", options: [] },
              {
                name: "lineOfBusiness",
                id: "lob-fid",
                type: "SELECT",
                options: [],
              },
            ],
          }],
          pageInfo: { hasNextPage: false },
        },
      };
    }
    if (method === "GET" && path.startsWith("/rest/metadata/views?limit=")) {
      return {
        body: {
          data: [{
            id: "v1",
            name: "Sales Pipeline",
            type: "TABLE",
            key: "INDEX",
            objectMetadataId: "opp-oid",
            // A non-allowlisted field carrying PII — must NOT reach the sample.
            createdBy: { name: "Jane PII Doe" },
          }],
          pageInfo: { hasNextPage: false },
        },
      };
    }
    if (
      method === "GET" && path.startsWith("/rest/metadata/viewFilters?limit=")
    ) {
      return { body: { data: [], pageInfo: { hasNextPage: false } } };
    }
    return { body: { data: [] } }; // reachability probes
  });
  try {
    await model.methods.listViews.execute({}, ctx as never);
    const snap = writes[writes.length - 1];
    assertEquals(snap.type, "viewList");
    const sample = String(snap.data.sample ?? "");
    assert(
      !sample.includes("Jane PII Doe"),
      "the R3 allowlist must keep a non-allowlisted PII value out of the sample",
    );
    assert(sample.includes("Sales Pipeline"), "allowlisted name is present");
    assert(sample.includes("keys"), "sample carries the key-name manifest");
  } finally {
    restore();
  }
});

// Shared opportunity-object metadata for the ensureOpportunityViews branches.
function oppMetaBody() {
  return {
    data: [{
      nameSingular: "opportunity",
      namePlural: "opportunities",
      id: "opp-oid",
      fields: [
        {
          name: "stage",
          id: "stage-fid",
          type: "SELECT",
          options: [
            { value: "NEW" },
            { value: "SCREENING" },
            { value: "MEETING" },
            { value: "PROPOSAL" },
          ],
        },
        {
          name: "lineOfBusiness",
          id: "lob-fid",
          type: "SELECT",
          options: [{ value: "CONSULTING" }],
        },
      ],
    }],
    pageInfo: { hasNextPage: false },
  };
}

Deno.test("R2 ensureOpportunityViews(confirm): existing views unloadable → refuse (fail-closed)", async () => {
  const { writes, ctx } = readCtx();
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: oppMetaBody() };
    }
    // Reachability probe succeeds...
    if (method === "GET" && path === "/rest/metadata/views?limit=1") {
      return { body: { data: [], pageInfo: { hasNextPage: false } } };
    }
    // ...but the idempotency-source load of existing views FAILS (500 → throws).
    if (method === "GET" && path.startsWith("/rest/metadata/views")) {
      return { status: 500, body: { message: "views unavailable" } };
    }
    if (method === "GET" && path.startsWith("/rest/metadata/viewFilters")) {
      return { body: { data: [], pageInfo: { hasNextPage: false } } };
    }
    return { body: { data: [] } };
  });
  try {
    await model.methods.ensureOpportunityViews.execute(
      { confirm: true, names: ["Sales Pipeline"] },
      ctx as never,
    );
    const snap = writes[writes.length - 1];
    const res = (snap.data.results as Array<Record<string, unknown>>)[0];
    assertEquals(res.action, "refuse");
    assert(String(res.reason).includes("existing views could not be loaded"));
  } finally {
    restore();
  }
});

Deno.test("R2 ensureOpportunityViews(confirm): endpoint unreachable at confirm → refuse (F4)", async () => {
  const { writes, ctx } = readCtx();
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/metadata/objects")) {
      return { body: oppMetaBody() };
    }
    // Reachability probe FAILS (404) → reachable=false.
    if (method === "GET" && path === "/rest/metadata/views?limit=1") {
      return { status: 404, body: {} };
    }
    // The existing-view load itself succeeds (empty), so existingLoadOk=true.
    if (method === "GET" && path.startsWith("/rest/metadata/views")) {
      return { body: { data: [], pageInfo: { hasNextPage: false } } };
    }
    if (method === "GET" && path.startsWith("/rest/metadata/viewFilters")) {
      return { body: { data: [], pageInfo: { hasNextPage: false } } };
    }
    return { body: { data: [] } };
  });
  try {
    await model.methods.ensureOpportunityViews.execute(
      { confirm: true, names: ["Sales Pipeline"] },
      ctx as never,
    );
    const snap = writes[writes.length - 1];
    const res = (snap.data.results as Array<Record<string, unknown>>)[0];
    assertEquals(res.action, "refuse");
    assert(String(res.reason).includes("not reachable at confirm time"));
    // Fail-closed: no view POST was ever issued.
    assert(
      !calls.some((c) =>
        c.method === "POST" && c.path === "/rest/metadata/views"
      ),
    );
  } finally {
    restore();
  }
});

// --- TWENTY-NOTE-RECONCILE: noteHash keyed-HMAC field + surface --------------

// A DEDICATED NON-PRODUCTION test key (SEC-8): the real vault key is never
// embedded in tests/fixtures. The frozen vector below asserts ext<->report
// byte-identity under THIS key, not the prod key.
const NOTE_TEST_KEY = "test-key-not-prod";

/** Object metadata GET payload; note.noteHash present iff `withNoteHash`. */
function noteMeta(withNoteHash: boolean) {
  const noteFields: Array<Record<string, unknown>> = [
    { name: "leadId", type: "TEXT" },
  ];
  if (withNoteHash) noteFields.push({ name: "noteHash", type: "TEXT" });
  return {
    data: [
      {
        id: "note-oid",
        nameSingular: "note",
        namePlural: "notes",
        fields: noteFields,
      },
      {
        id: "person-oid",
        nameSingular: "person",
        namePlural: "people",
        fields: [
          { name: "leadId", type: "TEXT" },
          { name: "isEmergency", type: "BOOLEAN" },
        ],
      },
      {
        id: "opp-oid",
        nameSingular: "opportunity",
        namePlural: "opportunities",
        fields: [
          { name: "leadId", type: "TEXT" },
          { name: "isEmergency", type: "BOOLEAN" },
        ],
      },
      {
        id: "company-oid",
        nameSingular: "company",
        namePlural: "companies",
        fields: [],
      },
    ],
  };
}

/** Capturing execute-context whose globalArgs carry a chosen HMAC key. */
function noteWriteCtx(hmacKey: string) {
  const writes: Array<
    { type: string; name: string; data: Record<string, unknown> }
  > = [];
  const ctx = {
    globalArgs: {
      baseUrl: "https://crm.example.com",
      apiToken: "tok",
      opportunityStage: "NEW",
      emailDomainBlocklist: [...DEFAULT_EMAIL_DOMAIN_BLOCKLIST],
      emergencyRestrictedRole: "",
      noteHashHmacKey: hmacKey,
    },
    logger: { debug() {}, info() {}, warning() {}, error() {} },
    writeResource: (
      type: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ type, name, data });
      return Promise.resolve({ name });
    },
  };
  return { writes, ctx };
}

// --- canonicalNote / hashNote (pure) ---------------------------------------

Deno.test("canonicalNote: stable sorted-key form; title/body not interchangeable", () => {
  assertEquals(canonicalNote("T", "B"), '{"body":"B","title":"T"}');
  assert(canonicalNote("A", "B") !== canonicalNote("B", "A"));
});

Deno.test("hashNote: frozen fixture vector under the test key (ext<->report byte-identity, SEC-8)", async () => {
  const v = await hashNote(
    NOTE_TEST_KEY,
    "Inbound lead L1",
    "Name: Ada\nMessage: hello world\n",
  );
  assertEquals(
    v,
    "b379851ad2ccd0c5f31b10e6e9345f7553a55fe400fbc27cfd9c4ea8d2b6bcb4",
  );
  assertEquals(v.length, 64); // hex SHA-256
});

Deno.test("hashNote: deterministic, keyed, and covers title AND body (ADV-3)", async () => {
  const a = await hashNote("k1", "T", "B");
  assertEquals(a, await hashNote("k1", "T", "B")); // deterministic
  assert(a !== (await hashNote("k2", "T", "B"))); // keyed
  assert(a !== (await hashNote("k1", "T2", "B"))); // title drift
  assert(a !== (await hashNote("k1", "T", "B2"))); // body drift
});

Deno.test("hashNote: FAILS CLOSED on an empty key (SEC-5)", async () => {
  await assertRejects(() => hashNote("", "T", "B"), Error, "empty HMAC key");
});

// --- mapNoteView surfacing --------------------------------------------------

Deno.test("mapNoteView surfaces noteHash body-free; omits when empty/absent; never a body", () => {
  const v = mapNoteView({
    id: "n1",
    leadId: "L1",
    noteHash: "abc123",
    bodyV2: { markdown: "secret body" },
  });
  assertEquals(v.noteHash, "abc123");
  assertEquals(v.leadId, "L1");
  assertEquals("body" in v, false);
  assertEquals("bodyV2" in v, false);
  assertEquals(JSON.stringify(v).includes("secret body"), false);
  assertEquals("noteHash" in mapNoteView({ id: "n2", noteHash: "" }), false);
  assertEquals("noteHash" in mapNoteView({ id: "n3" }), false);
});

// --- ensureNoteFields -------------------------------------------------------

Deno.test("ensureNoteFields refuses without confirm:true", async () => {
  const { ctx } = noteWriteCtx("");
  await assertRejects(
    () =>
      model.methods.ensureNoteFields.execute(
        { confirm: false } as never,
        ctx as never,
      ),
    Error,
    "confirm:true",
  );
});

Deno.test("ensureNoteFields creates note.noteHash when absent; idempotent when present", async () => {
  __clearNoteFieldCache();
  {
    const { writes, ctx } = noteWriteCtx("");
    const { calls, restore } = stubTwentyFetch((method, path) => {
      if (path.startsWith("/rest/metadata/objects")) return noteMeta(false);
      if (method === "POST" && path === "/rest/metadata/fields") return {};
      return {};
    });
    try {
      await model.methods.ensureNoteFields.execute(
        { confirm: true } as never,
        ctx as never,
      );
      assertEquals(writes[writes.length - 1].data.created, ["note.noteHash"]);
      assert(
        calls.some((c) =>
          c.method === "POST" && c.path === "/rest/metadata/fields" &&
          (c.body as Record<string, unknown>).name === "noteHash"
        ),
      );
    } finally {
      restore();
    }
  }
  {
    const { writes, ctx } = noteWriteCtx("");
    const { calls, restore } = stubTwentyFetch((_m, path) => {
      if (path.startsWith("/rest/metadata/objects")) return noteMeta(true);
      return {};
    });
    try {
      await model.methods.ensureNoteFields.execute(
        { confirm: true } as never,
        ctx as never,
      );
      assertEquals(writes[writes.length - 1].data.alreadyPresent, [
        "note.noteHash",
      ]);
      assert(
        !calls.some((c) =>
          c.method === "POST" && c.path === "/rest/metadata/fields"
        ),
      );
    } finally {
      restore();
    }
  }
});

Deno.test("ensureNoteFields refreshes the provisioned-ness memo even when the field is alreadyPresent (ADV-1)", async () => {
  __clearNoteFieldCache();
  // Phase 1: metadata WITHOUT noteHash — a createNote caches present:false.
  {
    const { ctx } = noteWriteCtx(NOTE_TEST_KEY);
    const { restore } = stubTwentyFetch((method, path) => {
      if (path.startsWith("/rest/metadata/objects")) return noteMeta(false);
      if (method === "POST" && path === "/rest/notes") {
        return { data: { createNote: { id: "n0" } } };
      }
      return {};
    });
    try {
      await model.methods.createNote.execute(
        { title: "pre", body: "x", dryRun: false, confirm: true } as never,
        ctx as never,
      );
    } finally {
      restore();
    }
  }
  // Phase 2: the field is provisioned out-of-band; ensureNoteFields finds it
  // alreadyPresent (created:[]) yet MUST still clear the stale memo.
  {
    const { writes, ctx } = noteWriteCtx(NOTE_TEST_KEY);
    const { restore } = stubTwentyFetch((_m, path) => {
      if (path.startsWith("/rest/metadata/objects")) return noteMeta(true);
      return {};
    });
    try {
      await model.methods.ensureNoteFields.execute(
        { confirm: true } as never,
        ctx as never,
      );
      assertEquals(writes[writes.length - 1].data.alreadyPresent, [
        "note.noteHash",
      ]);
    } finally {
      restore();
    }
  }
  // Phase 3: the next createNote must SEE the now-provisioned field and hash
  // (without the ADV-1 fix it would read the stale present:false and skip it).
  {
    const { ctx } = noteWriteCtx(NOTE_TEST_KEY);
    const { calls, restore } = stubTwentyFetch((method, path) => {
      if (path.startsWith("/rest/metadata/objects")) return noteMeta(true);
      if (method === "POST" && path === "/rest/notes") {
        return { data: { createNote: { id: "n1" } } };
      }
      return {};
    });
    try {
      await model.methods.createNote.execute(
        { title: "post", body: "y", dryRun: false, confirm: true } as never,
        ctx as never,
      );
      const post = calls.find((c) =>
        c.method === "POST" && c.path === "/rest/notes"
      )!;
      assertEquals(
        (post.body as Record<string, unknown>).noteHash,
        await hashNote(NOTE_TEST_KEY, "post", "y"),
      );
    } finally {
      restore();
    }
  }
});

// --- createNote population ---------------------------------------------------

Deno.test("createNote: noteHash field ABSENT => write succeeds, no noteHash, no bodyHash (ADV-2)", async () => {
  __clearNoteFieldCache();
  const { writes, ctx } = noteWriteCtx(NOTE_TEST_KEY);
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return noteMeta(false);
    if (method === "POST" && path === "/rest/notes") {
      return { data: { createNote: { id: "n1" } } };
    }
    return {};
  });
  try {
    await model.methods.createNote.execute(
      { title: "Hi", body: "Body", dryRun: false, confirm: true } as never,
      ctx as never,
    );
    const post = calls.find((c) =>
      c.method === "POST" && c.path === "/rest/notes"
    )!;
    assertEquals("noteHash" in (post.body as Record<string, unknown>), false);
    assertEquals(writes[writes.length - 1].data.action, "created");
    assertEquals("bodyHash" in writes[writes.length - 1].data, false);
  } finally {
    restore();
  }
});

Deno.test("createNote: field PROVISIONED + key => stamps keyed noteHash on the POST + bodyHash snapshot", async () => {
  __clearNoteFieldCache();
  const { writes, ctx } = noteWriteCtx(NOTE_TEST_KEY);
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return noteMeta(true);
    if (method === "POST" && path === "/rest/notes") {
      return { data: { createNote: { id: "n1" } } };
    }
    return {};
  });
  try {
    await model.methods.createNote.execute(
      { title: "Hi", body: "Body", dryRun: false, confirm: true } as never,
      ctx as never,
    );
    const post = calls.find((c) =>
      c.method === "POST" && c.path === "/rest/notes"
    )!;
    const expected = await hashNote(NOTE_TEST_KEY, "Hi", "Body");
    assertEquals((post.body as Record<string, unknown>).noteHash, expected);
    assertEquals(writes[writes.length - 1].data.bodyHash, expected);
  } finally {
    restore();
  }
});

Deno.test("createNote: field PROVISIONED + EMPTY key => FAILS CLOSED, no note POST (SEC-5)", async () => {
  __clearNoteFieldCache();
  const { ctx } = noteWriteCtx("");
  const { calls, restore } = stubTwentyFetch((_m, path) => {
    if (path.startsWith("/rest/metadata/objects")) return noteMeta(true);
    return {};
  });
  try {
    await assertRejects(
      () =>
        model.methods.createNote.execute(
          { title: "Hi", body: "Body", dryRun: false, confirm: true } as never,
          ctx as never,
        ),
      Error,
      "empty",
    );
    assert(!calls.some((c) => c.method === "POST" && c.path === "/rest/notes"));
  } finally {
    restore();
  }
});

Deno.test("createNote dryRun: plans with no metadata read and no hash", async () => {
  __clearNoteFieldCache();
  const { writes, ctx } = noteWriteCtx(NOTE_TEST_KEY);
  const { calls, restore } = stubTwentyFetch(() => ({}));
  try {
    await model.methods.createNote.execute(
      { title: "Hi", body: "Body", dryRun: true, confirm: true } as never,
      ctx as never,
    );
    assertEquals(writes[writes.length - 1].data.action, "planned-create");
    assertEquals("bodyHash" in writes[writes.length - 1].data, false);
    assert(!calls.some((c) => c.path.startsWith("/rest/metadata/objects")));
  } finally {
    restore();
  }
});

// --- updateNote population ---------------------------------------------------

const U_NOTE = "11111111-1111-1111-1111-111111111111";

Deno.test("updateNote: provisioned + key, title+body => PATCH carries keyed noteHash + bodyHash snapshot", async () => {
  __clearNoteFieldCache();
  const { writes, ctx } = noteWriteCtx(NOTE_TEST_KEY);
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) {
      return { body: noteMeta(true) };
    }
    if (method === "GET") {
      return {
        body: {
          data: {
            note: { id: U_NOTE, title: "old", bodyV2: { markdown: "oldbody" } },
          },
        },
      };
    }
    return { body: {} };
  });
  try {
    await model.methods.updateNote.execute(
      {
        noteId: U_NOTE,
        title: "New",
        body: "NewBody",
        dryRun: false,
        confirm: true,
      } as never,
      ctx as never,
    );
    const patch = calls.find((c) => c.method === "PATCH")!;
    const expected = await hashNote(NOTE_TEST_KEY, "New", "NewBody");
    assertEquals((patch.body as Record<string, unknown>).noteHash, expected);
    assertEquals(writes[writes.length - 1].data.bodyHash, expected);
  } finally {
    restore();
  }
});

Deno.test("updateNote body-only: hash covers EXISTING title + new body; title not PATCHed", async () => {
  __clearNoteFieldCache();
  const { ctx } = noteWriteCtx(NOTE_TEST_KEY);
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) {
      return { body: noteMeta(true) };
    }
    if (method === "GET") {
      return {
        body: {
          data: {
            note: {
              id: U_NOTE,
              title: "Existing Title",
              bodyV2: { markdown: "oldbody" },
            },
          },
        },
      };
    }
    return { body: {} };
  });
  try {
    await model.methods.updateNote.execute(
      {
        noteId: U_NOTE,
        body: "NewBody",
        dryRun: false,
        confirm: true,
      } as never,
      ctx as never,
    );
    const patch = calls.find((c) => c.method === "PATCH")!;
    assertEquals(
      (patch.body as Record<string, unknown>).noteHash,
      await hashNote(NOTE_TEST_KEY, "Existing Title", "NewBody"),
    );
    assertEquals("title" in (patch.body as Record<string, unknown>), false);
  } finally {
    restore();
  }
});

Deno.test("updateNote title-only: hash covers new title + EXISTING body; body never leaves the fetch", async () => {
  __clearNoteFieldCache();
  const { writes, ctx } = noteWriteCtx(NOTE_TEST_KEY);
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) {
      return { body: noteMeta(true) };
    }
    if (method === "GET") {
      return {
        body: {
          data: {
            note: {
              id: U_NOTE,
              title: "old",
              bodyV2: { markdown: "SECRET-BODY" },
            },
          },
        },
      };
    }
    return { body: {} };
  });
  try {
    await model.methods.updateNote.execute(
      {
        noteId: U_NOTE,
        title: "New Title",
        dryRun: false,
        confirm: true,
      } as never,
      ctx as never,
    );
    const patch = calls.find((c) => c.method === "PATCH")!;
    assertEquals(
      (patch.body as Record<string, unknown>).noteHash,
      await hashNote(NOTE_TEST_KEY, "New Title", "SECRET-BODY"),
    );
    assertEquals("bodyV2" in (patch.body as Record<string, unknown>), false);
    // The SR-1 body is used only to hash — never snapshotted.
    for (const w of writes) {
      assertEquals(JSON.stringify(w.data).includes("SECRET-BODY"), false);
    }
  } finally {
    restore();
  }
});

Deno.test("updateNote: provisioned + EMPTY key => FAILS CLOSED, no PATCH (SEC-5)", async () => {
  __clearNoteFieldCache();
  const { ctx } = noteWriteCtx("");
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) {
      return { body: noteMeta(true) };
    }
    if (method === "GET") {
      return {
        body: {
          data: { note: { id: U_NOTE, title: "t", bodyV2: { markdown: "b" } } },
        },
      };
    }
    return { body: {} };
  });
  try {
    await assertRejects(
      () =>
        model.methods.updateNote.execute(
          {
            noteId: U_NOTE,
            title: "New",
            body: "B",
            dryRun: false,
            confirm: true,
          } as never,
          ctx as never,
        ),
      Error,
      "empty",
    );
    assert(!calls.some((c) => c.method === "PATCH"));
  } finally {
    restore();
  }
});

Deno.test("updateNote: field ABSENT => PATCH has no noteHash (never breaks the write)", async () => {
  __clearNoteFieldCache();
  const { ctx } = noteWriteCtx(NOTE_TEST_KEY);
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) {
      return { body: noteMeta(false) };
    }
    if (method === "GET") {
      return {
        body: {
          data: { note: { id: U_NOTE, title: "t", bodyV2: { markdown: "b" } } },
        },
      };
    }
    return { body: {} };
  });
  try {
    await model.methods.updateNote.execute(
      {
        noteId: U_NOTE,
        title: "New",
        body: "B",
        dryRun: false,
        confirm: true,
      } as never,
      ctx as never,
    );
    const patch = calls.find((c) => c.method === "PATCH")!;
    assertEquals("noteHash" in (patch.body as Record<string, unknown>), false);
  } finally {
    restore();
  }
});

// --- provisioned-ness cache -------------------------------------------------

Deno.test("noteHash provisioned-ness is memoized per baseUrl; __clearNoteFieldCache forces a re-read", async () => {
  __clearNoteFieldCache();
  const { ctx } = noteWriteCtx(NOTE_TEST_KEY);
  let metaReads = 0;
  const { restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) {
      metaReads++;
      return noteMeta(true);
    }
    if (method === "POST" && path === "/rest/notes") {
      return { data: { createNote: { id: "n1" } } };
    }
    return {};
  });
  try {
    await model.methods.createNote.execute(
      { title: "A", body: "1", dryRun: false, confirm: true } as never,
      ctx as never,
    );
    await model.methods.createNote.execute(
      { title: "B", body: "2", dryRun: false, confirm: true } as never,
      ctx as never,
    );
    assertEquals(metaReads, 1); // 2nd write served from the memo
    __clearNoteFieldCache();
    await model.methods.createNote.execute(
      { title: "C", body: "3", dryRun: false, confirm: true } as never,
      ctx as never,
    );
    assertEquals(metaReads, 2); // re-read after clear
  } finally {
    restore();
  }
});

// --- pushLeadsContract: the lead sink never hashes --------------------------

Deno.test("pushLeadsContract: push_leads note-write carries NO noteHash even when provisioned + key set", async () => {
  __clearNoteFieldCache();
  const ctx = {
    ...gateCtx,
    globalArgs: { ...gateCtx.globalArgs, noteHashHmacKey: NOTE_TEST_KEY },
  };
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (path.startsWith("/rest/metadata/objects")) return noteMeta(true);
    if (method === "GET" && path.startsWith("/rest/people")) {
      return { data: { people: [] } };
    }
    if (method === "POST" && path === "/rest/people") {
      return { data: { createPerson: { id: "p1" } } };
    }
    if (method === "GET" && path.startsWith("/rest/companies")) {
      return { data: { companies: [] } };
    }
    if (method === "POST" && path === "/rest/companies") {
      return { data: { createCompany: { id: "c1" } } };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { data: { opportunities: [] } };
    }
    if (method === "POST" && path === "/rest/opportunities") {
      return { data: { createOpportunity: { id: "o1" } } };
    }
    if (method === "GET" && path.startsWith("/rest/noteTargets")) {
      return { data: { noteTargets: [] } };
    }
    if (method === "POST" && path === "/rest/noteTargets") {
      return {
        data: {
          createNoteTarget: { targetPersonId: "p1", targetOpportunityId: "o1" },
        },
      };
    }
    if (method === "GET" && path.startsWith("/rest/notes")) {
      return { data: { notes: [] } };
    }
    if (method === "POST" && path === "/rest/notes") {
      return { data: { createNote: { id: "n1" } } };
    }
    return {};
  });
  try {
    await model.methods.push_leads.execute(
      {
        leads: [baseLead],
        kvEntries: [],
        confirm: true,
        dryRun: false,
        maxBatch: 200,
      } as never,
      ctx as never,
    );
    const notePosts = calls.filter((c) =>
      c.method === "POST" && c.path === "/rest/notes"
    );
    assert(notePosts.length >= 1, "expected at least one note POST");
    for (const p of notePosts) {
      assertEquals("noteHash" in (p.body as Record<string, unknown>), false);
    }
  } finally {
    restore();
  }
});

// ============================================================================
// TWENTY-VIEW-UPSERT — reconciling opportunity view management
// ============================================================================

const U_OPP = "opp-oid-vu";
const U_STAGE = "stage-fid-vu";
const U_LOB = "lob-fid-vu";
const U_OPEN = ["NEW", "SCREENING", "MEETING", "PROPOSAL"];
const U_FIELDMETA: Record<
  string,
  { fieldMetadataId?: string; options: string[] } | undefined
> = {
  stage: {
    fieldMetadataId: U_STAGE,
    options: [
      "NEW",
      "SCREENING",
      "MEETING",
      "PROPOSAL",
      "CUSTOMER",
      "CLOSED_WON",
      "CLOSED_LOST",
      "ON_HOLD",
    ],
  },
  lineOfBusiness: {
    fieldMetadataId: U_LOB,
    options: ["CONSULTING", "HOSTING", "LOCAL_IT", "NETWORK_PROVIDER", "GAMES"],
  },
};

// deno-lint-ignore no-explicit-any
function uView(over: Record<string, unknown>): any {
  return {
    id: "v-1",
    name: "X",
    key: null,
    isSystemSideEffect: false,
    isCustom: true,
    objectMetadataId: U_OPP,
    filters: [],
    filterGroups: [],
    ...over,
  };
}

function uOps(p: { ops: unknown[] }): Array<Record<string, unknown>> {
  return p.ops as Array<Record<string, unknown>>;
}

Deno.test("VIEW-UPSERT buildViewFilterValueString: UI stringified-array form", () => {
  assertEquals(
    buildViewFilterValueString(["NEW", "SCREENING"]),
    '["NEW","SCREENING"]',
  );
  assertEquals(buildViewFilterValueString(["CONSULTING"]), '["CONSULTING"]');
});

Deno.test("VIEW-UPSERT plan: absent name -> create with stringified value", () => {
  const p = planUpsertOpportunityView(
    {
      name: "Consulting",
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    [],
    U_OPP,
  );
  assertEquals(p.action, "create");
  assertEquals(p.filtersAdded, 1);
  const ops = uOps(p);
  assertEquals(ops.length, 1);
  assertEquals(ops[0].op, "create-filter");
  assertEquals(ops[0].value, '["CONSULTING"]');
  assertEquals(ops[0].grouped, false);
});

Deno.test("VIEW-UPSERT plan: present no-op when filter already matches (bare-array normalized)", () => {
  const existing = [uView({
    name: "Consulting",
    filters: [{
      id: "f1",
      fieldMetadataId: U_LOB,
      operand: "IS",
      value: ["CONSULTING"], // stored as bare array (legacy) -> normalized
      subFieldName: null,
      viewFilterGroupId: null,
    }],
  })];
  const p = planUpsertOpportunityView(
    {
      name: "Consulting",
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "present");
  assertEquals(uOps(p).length, 0);
});

Deno.test("VIEW-UPSERT plan: divergent name-match WITHOUT adoptFrom is refused (SEC-3)", () => {
  const existing = [uView({
    name: "Consulting",
    filters: [{
      id: "f1",
      fieldMetadataId: U_LOB,
      operand: "IS",
      value: '["HOSTING"]',
      subFieldName: null,
      viewFilterGroupId: null,
    }],
  })];
  const p = planUpsertOpportunityView(
    {
      name: "Consulting",
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("SEC-3"));
});

Deno.test("VIEW-UPSERT plan: value drift -> reconcile patch-filter (stringified, self-adopt opt-in)", () => {
  const existing = [uView({
    name: "Consulting",
    filters: [{
      id: "f1",
      fieldMetadataId: U_LOB,
      operand: "IS",
      value: '["HOSTING"]',
      subFieldName: null,
      viewFilterGroupId: null,
    }],
  })];
  const p = planUpsertOpportunityView(
    {
      name: "Consulting",
      adoptFrom: "Consulting", // explicit opt-in to reconcile the divergence
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "reconcile");
  assertEquals(p.filtersPatched, 1);
  const ops = uOps(p);
  assertEquals(ops[0].op, "patch-filter");
  assertEquals(ops[0].filterId, "f1");
  assertEquals(ops[0].value, '["CONSULTING"]');
});

Deno.test("VIEW-UPSERT plan: reconcile add-missing + delete-extra", () => {
  const existing = [uView({
    name: "Consulting",
    filters: [{
      id: "fx",
      fieldMetadataId: U_STAGE,
      operand: "IS",
      value: '["NEW"]',
      subFieldName: null,
      viewFilterGroupId: null,
    }],
  })];
  const p = planUpsertOpportunityView(
    {
      name: "Consulting",
      adoptFrom: "Consulting", // explicit opt-in to reconcile the divergence
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "reconcile");
  assertEquals(p.filtersAdded, 1);
  assertEquals(p.filtersRemoved, 1);
  const kinds = uOps(p).map((o) => o.op);
  assert(kinds.includes("create-filter"));
  assert(kinds.includes("delete-filter"));
});

Deno.test("VIEW-UPSERT plan: adopt (rename + reduce grouped 2-clause -> single ungrouped)", () => {
  const existing = [uView({
    id: "open-pipe",
    name: "Open Pipeline",
    filterGroups: [{
      id: "g1",
      logicalOperator: "AND",
      parentViewFilterGroupId: null,
    }],
    filters: [
      {
        id: "m-lob",
        fieldMetadataId: U_LOB,
        operand: "IS_NOT",
        value: '["NETWORK_PROVIDER"]',
        subFieldName: null,
        viewFilterGroupId: "g1",
        positionInViewFilterGroup: 0,
      },
      {
        id: "m-stage",
        fieldMetadataId: U_STAGE,
        operand: "IS_NOT",
        value: '["CUSTOMER"]',
        subFieldName: null,
        viewFilterGroupId: "g1",
        positionInViewFilterGroup: 1,
      },
    ],
  })];
  const p = planUpsertOpportunityView(
    {
      name: "Sales Pipeline",
      adoptFrom: "Open Pipeline",
      filters: [{ field: "stage", operand: "IS", values: U_OPEN }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "adopt");
  assertEquals(p.viewId, "open-pipe");
  const ops = uOps(p);
  assertEquals(ops[0].op, "rename-view");
  assertEquals(ops[0].toName, "Sales Pipeline");
  const kinds = ops.map((o) => o.op);
  assert(kinds.includes("create-filter"), "adds the desired stage IS clause");
  assertEquals(kinds.filter((k) => k === "delete-filter").length, 2);
  assert(
    kinds.includes("delete-group"),
    "removes the emptied group (no dangling)",
  );
  // delete-group must come after the member deletes (ADV-3).
  const lastDelFilter = kinds.lastIndexOf("delete-filter");
  const delGroup = kinds.indexOf("delete-group");
  assert(
    delGroup > lastDelFilter,
    "delete-group is emitted after all member deletes",
  );
});

Deno.test("VIEW-UPSERT plan: locked/system view refused as name target", () => {
  const existing = [uView({ name: "Consulting", isCustom: false })];
  const p = planUpsertOpportunityView(
    {
      name: "Consulting",
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("locked/system"));
});

Deno.test("VIEW-UPSERT plan: locked adoptFrom source refused (SEC-8)", () => {
  const existing = [uView({ id: "old", name: "Old", isCustom: false })];
  const p = planUpsertOpportunityView(
    {
      name: "New",
      adoptFrom: "Old",
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("SEC-8"));
});

Deno.test("VIEW-UPSERT plan: >1 name match refused", () => {
  const existing = [
    uView({ id: "a", name: "Consulting" }),
    uView({ id: "b", name: "Consulting" }),
  ];
  const p = planUpsertOpportunityView(
    {
      name: "Consulting",
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("ambiguous"));
});

Deno.test("VIEW-UPSERT plan: >1 adoptFrom match refused", () => {
  const existing = [
    uView({ id: "a", name: "Old" }),
    uView({ id: "b", name: "Old" }),
  ];
  const p = planUpsertOpportunityView(
    {
      name: "New",
      adoptFrom: "Old",
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("adoptFrom"));
});

Deno.test("VIEW-UPSERT plan: retired/invalid enum token refused (live allowlist)", () => {
  const p = planUpsertOpportunityView(
    {
      name: "Consulting",
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["RETIRED_LOB"],
      }],
    },
    U_FIELDMETA,
    [],
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("absent from live"));
});

Deno.test("VIEW-UPSERT plan: unresolved fieldMetadataId refused", () => {
  const p = planUpsertOpportunityView(
    {
      name: "Ghost",
      filters: [{ field: "nonexistentField", operand: "IS", values: ["X"] }],
    },
    U_FIELDMETA,
    [],
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("fieldMetadataId"));
});

Deno.test("VIEW-UPSERT plan: multi-clause without filterGroup refused", () => {
  const p = planUpsertOpportunityView(
    {
      name: "Board",
      filters: [
        { field: "stage", operand: "IS", values: ["NEW"] },
        { field: "lineOfBusiness", operand: "IS", values: ["CONSULTING"] },
      ],
    },
    U_FIELDMETA,
    [],
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("filterGroup"));
});

Deno.test("VIEW-UPSERT plan: unsupported operand refused", () => {
  const p = planUpsertOpportunityView(
    {
      name: "Consulting",
      filters: [{
        field: "lineOfBusiness",
        operand: "CONTAINS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    [],
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("not supported"));
});

Deno.test("VIEW-UPSERT plan: duplicate desired clause refused", () => {
  const p = planUpsertOpportunityView(
    {
      name: "Board",
      filterGroup: "and",
      filters: [
        { field: "stage", operand: "IS", values: ["NEW"] },
        { field: "stage", operand: "IS", values: ["PROPOSAL"] },
      ],
    },
    U_FIELDMETA,
    [],
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("duplicate desired clause"));
});

Deno.test("VIEW-UPSERT plan: grouped create (create-group + members)", () => {
  const p = planUpsertOpportunityView(
    {
      name: "Board",
      filterGroup: "and",
      filters: [
        { field: "stage", operand: "IS", values: ["NEW"] },
        { field: "lineOfBusiness", operand: "IS", values: ["CONSULTING"] },
      ],
    },
    U_FIELDMETA,
    [],
    U_OPP,
  );
  assertEquals(p.action, "create");
  assertEquals(p.grouped, true);
  assertEquals(p.groupOperator, "AND");
  const ops = uOps(p);
  assertEquals(ops[0].op, "create-group");
  assertEquals(ops[0].logicalOperator, "AND");
  assertEquals(ops.filter((o) => o.op === "create-filter").length, 2);
  assert(ops.slice(1).every((o) => o.grouped === true));
});

Deno.test("VIEW-UPSERT plan: group operator drift -> patch-group-operator", () => {
  const existing = [uView({
    name: "Board",
    filterGroups: [{
      id: "g1",
      logicalOperator: "AND",
      parentViewFilterGroupId: null,
    }],
    filters: [
      {
        id: "m1",
        fieldMetadataId: U_STAGE,
        operand: "IS",
        value: '["NEW"]',
        subFieldName: null,
        viewFilterGroupId: "g1",
        positionInViewFilterGroup: 0,
      },
      {
        id: "m2",
        fieldMetadataId: U_LOB,
        operand: "IS",
        value: '["CONSULTING"]',
        subFieldName: null,
        viewFilterGroupId: "g1",
        positionInViewFilterGroup: 1,
      },
    ],
  })];
  const p = planUpsertOpportunityView(
    {
      name: "Board",
      adoptFrom: "Board", // divergence (operator) -> explicit opt-in (SEC-3)
      filterGroup: "or",
      filters: [
        { field: "stage", operand: "IS", values: ["NEW"] },
        { field: "lineOfBusiness", operand: "IS", values: ["CONSULTING"] },
      ],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "reconcile");
  const ops = uOps(p);
  assertEquals(ops.length, 1);
  assertEquals(ops[0].op, "patch-group-operator");
  assertEquals(ops[0].logicalOperator, "OR");
  // group-operator drift is NOT counted as a filter patch (CR-3)
  assertEquals(p.filtersPatched, 0);
  assert(p.reason.includes("group-operator"));
});

Deno.test("VIEW-UPSERT plan: nested viewFilterGroup refused (fail-closed ADV-10)", () => {
  const existing = [uView({
    name: "Board",
    filterGroups: [
      { id: "g1", logicalOperator: "AND", parentViewFilterGroupId: null },
      { id: "g2", logicalOperator: "OR", parentViewFilterGroupId: "g1" },
    ],
    filters: [{
      id: "m1",
      fieldMetadataId: U_LOB,
      operand: "IS",
      value: '["CONSULTING"]',
      subFieldName: null,
      viewFilterGroupId: "g1",
    }],
  })];
  const p = planUpsertOpportunityView(
    {
      name: "Board",
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("nested"));
});

Deno.test("VIEW-UPSERT plan: >1 top-level group refused (fail-closed ADV-10)", () => {
  const existing = [uView({
    name: "Board",
    filterGroups: [
      { id: "g1", logicalOperator: "AND", parentViewFilterGroupId: null },
      { id: "g2", logicalOperator: "AND", parentViewFilterGroupId: null },
    ],
    filters: [{
      id: "m1",
      fieldMetadataId: U_LOB,
      operand: "IS",
      value: '["CONSULTING"]',
      subFieldName: null,
      viewFilterGroupId: "g1",
    }],
  })];
  const p = planUpsertOpportunityView(
    {
      name: "Board",
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("top-level"));
});

Deno.test("VIEW-UPSERT plan: ungrouped -> grouped restructure refused", () => {
  const existing = [uView({
    name: "Board",
    filters: [
      {
        id: "m1",
        fieldMetadataId: U_STAGE,
        operand: "IS",
        value: '["NEW"]',
        subFieldName: null,
        viewFilterGroupId: null,
      },
      {
        id: "m2",
        fieldMetadataId: U_LOB,
        operand: "IS",
        value: '["CONSULTING"]',
        subFieldName: null,
        viewFilterGroupId: null,
      },
    ],
  })];
  const p = planUpsertOpportunityView(
    {
      name: "Board",
      filterGroup: "and",
      filters: [
        { field: "stage", operand: "IS", values: ["NEW"] },
        { field: "lineOfBusiness", operand: "IS", values: ["CONSULTING"] },
      ],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("grouped restructure"));
});

Deno.test("VIEW-UPSERT plan: adoptFrom by viewId (UUID-parse selects id)", () => {
  const id = "12345678-1234-1234-1234-1234567890ab";
  const existing = [uView({ id, name: "Old", filters: [] })];
  const p = planUpsertOpportunityView(
    {
      name: "New",
      adoptFrom: id,
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "adopt");
  assertEquals(p.viewId, id);
});

Deno.test("VIEW-UPSERT plan: object-scoped (view in another object ignored)", () => {
  const existing = [uView({
    name: "Consulting",
    objectMetadataId: "some-other-object",
  })];
  const p = planUpsertOpportunityView(
    {
      name: "Consulting",
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    existing,
    U_OPP,
  );
  assertEquals(p.action, "create");
});

Deno.test("VIEW-UPSERT plan: unresolved objectMetadataId refused", () => {
  const p = planUpsertOpportunityView(
    {
      name: "Consulting",
      filters: [{
        field: "lineOfBusiness",
        operand: "IS",
        values: ["CONSULTING"],
      }],
    },
    U_FIELDMETA,
    [],
    undefined,
  );
  assertEquals(p.action, "refuse");
  assert(p.reason.includes("objectMetadataId"));
});

// --- Method integration (stateful HTTP store + read-back) -------------------

type StoreRow = Record<string, unknown>;
function makeViewStore(seed: {
  views?: StoreRow[];
  filters?: StoreRow[];
  groups?: StoreRow[];
} = {}): {
  handler: (method: string, path: string, body: unknown) => unknown;
  views: StoreRow[];
  filters: StoreRow[];
  groups: StoreRow[];
} {
  const objects = {
    data: [{
      nameSingular: "opportunity",
      id: U_OPP,
      fields: [
        {
          name: "stage",
          id: U_STAGE,
          type: "SELECT",
          options: U_FIELDMETA.stage!.options.map((v) => ({ value: v })),
        },
        {
          name: "lineOfBusiness",
          id: U_LOB,
          type: "SELECT",
          options: U_FIELDMETA.lineOfBusiness!.options.map((v) => ({
            value: v,
          })),
        },
      ],
    }],
    pageInfo: { hasNextPage: false },
  };
  const views = [...(seed.views ?? [])];
  const filters = [...(seed.filters ?? [])];
  const groups = [...(seed.groups ?? [])];
  let seq = 1;
  const nid = (p: string) => `${p}-${seq++}`;
  const handler = (method: string, path: string, body: unknown): unknown => {
    const b = (body ?? {}) as Record<string, unknown>;
    const p = path.split("?")[0];
    if (method === "GET") {
      if (p === "/rest/metadata/objects") return objects;
      if (p === "/rest/metadata/views") {
        return { data: views, pageInfo: { hasNextPage: false } };
      }
      if (p === "/rest/metadata/viewFilters") {
        return { data: filters, pageInfo: { hasNextPage: false } };
      }
      if (p === "/rest/metadata/viewFilterGroups") {
        return { data: groups, pageInfo: { hasNextPage: false } };
      }
      return { data: [], pageInfo: { hasNextPage: false } };
    }
    if (method === "POST") {
      if (p === "/rest/metadata/views") {
        const id = nid("view");
        views.push({
          id,
          name: b.name,
          key: null,
          isCustom: true,
          isSystemSideEffect: false,
          objectMetadataId: b.objectMetadataId,
        });
        return { id };
      }
      if (p === "/rest/metadata/viewFilterGroups") {
        const id = nid("grp");
        groups.push({
          id,
          viewId: b.viewId,
          logicalOperator: b.logicalOperator,
          parentViewFilterGroupId: null,
        });
        return { id };
      }
      if (p === "/rest/metadata/viewFilters") {
        const id = nid("flt");
        filters.push({
          id,
          viewId: b.viewId,
          fieldMetadataId: b.fieldMetadataId,
          operand: b.operand,
          value: b.value,
          subFieldName: b.subFieldName ?? null,
          viewFilterGroupId: b.viewFilterGroupId ?? null,
          positionInViewFilterGroup: b.positionInViewFilterGroup ?? null,
        });
        return { id };
      }
    }
    if (method === "PATCH") {
      const mv = p.match(/^\/rest\/metadata\/views\/(.+)$/);
      if (mv) {
        const v = views.find((x) => x.id === mv[1]);
        if (v) Object.assign(v, b);
        return v ?? {};
      }
      const mf = p.match(/^\/rest\/metadata\/viewFilters\/(.+)$/);
      if (mf) {
        const f = filters.find((x) => x.id === mf[1]);
        if (f) Object.assign(f, b);
        return f ?? {};
      }
      const mg = p.match(/^\/rest\/metadata\/viewFilterGroups\/(.+)$/);
      if (mg) {
        const g = groups.find((x) => x.id === mg[1]);
        if (g) Object.assign(g, b);
        return g ?? {};
      }
    }
    if (method === "DELETE") {
      const mf = p.match(/^\/rest\/metadata\/viewFilters\/(.+)$/);
      if (mf) {
        const i = filters.findIndex((x) => x.id === mf[1]);
        if (i >= 0) filters.splice(i, 1);
        return { success: true };
      }
      const mg = p.match(/^\/rest\/metadata\/viewFilterGroups\/(.+)$/);
      if (mg) {
        const i = groups.findIndex((x) => x.id === mg[1]);
        if (i >= 0) groups.splice(i, 1);
        return { success: true };
      }
      const mv = p.match(/^\/rest\/metadata\/views\/(.+)$/);
      if (mv) {
        const i = views.findIndex((x) => x.id === mv[1]);
        if (i >= 0) views.splice(i, 1);
        return { success: true };
      }
    }
    return {};
  };
  return { handler, views, filters, groups };
}

type ViewEnsured2Snap = {
  results: Array<Record<string, unknown>>;
  [k: string]: unknown;
};
function vuCtx(): {
  ctx: unknown;
  writes: ViewEnsured2Snap[];
} {
  const writes: ViewEnsured2Snap[] = [];
  const ctx = {
    globalArgs: { baseUrl: "https://crm.example.com", apiToken: "tok" },
    logger: { debug() {}, info() {}, warning() {}, error() {} },
    writeResource: (_s: string, _n: string, data: unknown) => {
      writes.push(data as ViewEnsured2Snap);
      return Promise.resolve({ name: "viewEnsured2" });
    },
  };
  return { ctx, writes };
}

Deno.test("VIEW-UPSERT method: dryRun (default) plans only, no writes", async () => {
  const store = makeViewStore();
  const { calls, restore } = stubTwentyFetch(store.handler);
  const { ctx, writes } = vuCtx();
  try {
    await model.methods.upsertOpportunityViews.execute(
      {
        views: [{
          name: "Consulting",
          filters: [{
            field: "lineOfBusiness",
            operand: "IS",
            values: ["CONSULTING"],
          }],
        }],
      } as never,
      ctx as never,
    );
    const mutations = calls.filter((c) => c.method !== "GET");
    assertEquals(mutations.length, 0);
    assertEquals(writes[0].results[0].action, "create");
    assertEquals(writes[0].dryRun, true);
  } finally {
    restore();
  }
});

Deno.test("VIEW-UPSERT method: confirm create writes stringified value + reads back", async () => {
  const store = makeViewStore();
  const { calls, restore } = stubTwentyFetch(store.handler);
  const { ctx, writes } = vuCtx();
  try {
    await model.methods.upsertOpportunityViews.execute(
      {
        views: [{
          name: "Consulting",
          filters: [{
            field: "lineOfBusiness",
            operand: "IS",
            values: ["CONSULTING"],
          }],
        }],
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    const viewPost = calls.find((c) =>
      c.method === "POST" && c.path === "/rest/metadata/views"
    );
    assert(viewPost, "POSTs the view");
    const filterPost = calls.find((c) =>
      c.method === "POST" && c.path === "/rest/metadata/viewFilters"
    );
    assert(filterPost, "POSTs the viewFilter");
    assertEquals(
      (filterPost!.body as Record<string, unknown>).value,
      '["CONSULTING"]',
    );
    assertEquals(writes[0].results[0].action, "created");
    assertEquals(writes[0].results[0].readBackOk, true);
    assertEquals(writes[0].createdCount, 1);
    assertEquals(store.views.length, 1);
    assertEquals(store.filters.length, 1);
  } finally {
    restore();
  }
});

Deno.test("VIEW-UPSERT method: confirm adopt reduces grouped source, no dangling group", async () => {
  const store = makeViewStore({
    views: [{
      id: "open-pipe",
      name: "Open Pipeline",
      key: null,
      isCustom: true,
      isSystemSideEffect: false,
      objectMetadataId: U_OPP,
    }],
    groups: [{
      id: "g1",
      viewId: "open-pipe",
      logicalOperator: "AND",
      parentViewFilterGroupId: null,
    }],
    filters: [
      {
        id: "m-lob",
        viewId: "open-pipe",
        fieldMetadataId: U_LOB,
        operand: "IS_NOT",
        value: '["NETWORK_PROVIDER"]',
        subFieldName: null,
        viewFilterGroupId: "g1",
        positionInViewFilterGroup: 0,
      },
      {
        id: "m-stage",
        viewId: "open-pipe",
        fieldMetadataId: U_STAGE,
        operand: "IS_NOT",
        value: '["CUSTOMER"]',
        subFieldName: null,
        viewFilterGroupId: "g1",
        positionInViewFilterGroup: 1,
      },
    ],
  });
  const { calls, restore } = stubTwentyFetch(store.handler);
  const { ctx, writes } = vuCtx();
  try {
    await model.methods.upsertOpportunityView.execute(
      {
        name: "Sales Pipeline",
        adoptFrom: "Open Pipeline",
        filters: [{ field: "stage", operand: "IS", values: U_OPEN }],
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    const rename = calls.find((c) =>
      c.method === "PATCH" && c.path === "/rest/metadata/views/open-pipe"
    );
    assert(rename, "renames the source view");
    assertEquals(
      (rename!.body as Record<string, unknown>).name,
      "Sales Pipeline",
    );
    assert(
      calls.some((c) =>
        c.method === "DELETE" &&
        c.path === "/rest/metadata/viewFilterGroups/g1"
      ),
      "deletes the emptied group",
    );
    // final state: one ungrouped stage IS filter, no groups.
    assertEquals(store.groups.length, 0);
    assertEquals(store.filters.length, 1);
    assertEquals(store.filters[0].fieldMetadataId, U_STAGE);
    assertEquals(store.filters[0].operand, "IS");
    assertEquals(store.filters[0].viewFilterGroupId, null);
    assertEquals(store.views[0].name, "Sales Pipeline");
    assertEquals(writes[0].results[0].action, "adopted");
    assertEquals(writes[0].results[0].readBackOk, true);
  } finally {
    restore();
  }
});

Deno.test("VIEW-UPSERT method: confirm re-run is a quiet present no-op", async () => {
  const store = makeViewStore({
    views: [{
      id: "cv",
      name: "Consulting",
      key: null,
      isCustom: true,
      isSystemSideEffect: false,
      objectMetadataId: U_OPP,
    }],
    filters: [{
      id: "cf",
      viewId: "cv",
      fieldMetadataId: U_LOB,
      operand: "IS",
      value: ["CONSULTING"], // bare-array legacy form -> must normalize to no-op
      subFieldName: null,
      viewFilterGroupId: null,
      positionInViewFilterGroup: null,
    }],
  });
  const { calls, restore } = stubTwentyFetch(store.handler);
  const { ctx, writes } = vuCtx();
  try {
    await model.methods.upsertOpportunityView.execute(
      {
        name: "Consulting",
        filters: [{
          field: "lineOfBusiness",
          operand: "IS",
          values: ["CONSULTING"],
        }],
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    assertEquals(calls.filter((c) => c.method !== "GET").length, 0);
    assertEquals(writes[0].results[0].action, "present");
    assertEquals(writes[0].presentCount, 1);
  } finally {
    restore();
  }
});

Deno.test("VIEW-UPSERT method: confirm refuses a locked view (no writes)", async () => {
  const store = makeViewStore({
    views: [{
      id: "sys",
      name: "Consulting",
      key: "INDEX",
      isCustom: false,
      isSystemSideEffect: true,
      objectMetadataId: U_OPP,
    }],
  });
  const { calls, restore } = stubTwentyFetch(store.handler);
  const { ctx, writes } = vuCtx();
  try {
    await model.methods.upsertOpportunityView.execute(
      {
        name: "Consulting",
        filters: [{
          field: "lineOfBusiness",
          operand: "IS",
          values: ["CONSULTING"],
        }],
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    assertEquals(calls.filter((c) => c.method !== "GET").length, 0);
    assertEquals(writes[0].results[0].action, "refuse");
    assertEquals(writes[0].refusedCount, 1);
  } finally {
    restore();
  }
});

Deno.test("VIEW-UPSERT method: fan-out duplicate desired name refused", async () => {
  const store = makeViewStore();
  const { calls, restore } = stubTwentyFetch(store.handler);
  const { ctx, writes } = vuCtx();
  try {
    await model.methods.upsertOpportunityViews.execute(
      {
        views: [
          {
            name: "Dup",
            filters: [{
              field: "lineOfBusiness",
              operand: "IS",
              values: ["CONSULTING"],
            }],
          },
          {
            name: "Dup",
            filters: [{
              field: "lineOfBusiness",
              operand: "IS",
              values: ["HOSTING"],
            }],
          },
        ],
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    assertEquals(calls.filter((c) => c.method !== "GET").length, 0);
    assertEquals(writes[0].results[0].action, "refuse");
    assertEquals(writes[0].results[1].action, "refuse");
    assert(String(writes[0].results[0].reason).includes("duplicate"));
  } finally {
    restore();
  }
});

Deno.test("VIEW-UPSERT method: fan-out duplicate adoptFrom refused (no writes)", async () => {
  const store = makeViewStore({
    views: [{
      id: "src",
      name: "Src",
      key: null,
      isCustom: true,
      isSystemSideEffect: false,
      objectMetadataId: U_OPP,
    }],
  });
  const { calls, restore } = stubTwentyFetch(store.handler);
  const { ctx, writes } = vuCtx();
  try {
    await model.methods.upsertOpportunityViews.execute(
      {
        views: [
          {
            name: "A",
            adoptFrom: "Src",
            filters: [{
              field: "lineOfBusiness",
              operand: "IS",
              values: ["CONSULTING"],
            }],
          },
          {
            name: "B",
            adoptFrom: "Src",
            filters: [{
              field: "lineOfBusiness",
              operand: "IS",
              values: ["HOSTING"],
            }],
          },
        ],
        confirm: true,
        dryRun: false,
      } as never,
      ctx as never,
    );
    assertEquals(calls.filter((c) => c.method !== "GET").length, 0);
    assertEquals(writes[0].results[0].action, "refuse");
    assertEquals(writes[0].results[1].action, "refuse");
    assert(String(writes[0].results[0].reason).includes("adoptFrom"));
  } finally {
    restore();
  }
});

// --- Email/thread READ (TWENTY-EMAIL) ---------------------------------------

const T_OPP = "44444444-4444-4444-4444-444444444444";
const T_PERSON = "55555555-5555-5555-5555-555555555555";
const THREAD1 = "66666666-6666-6666-6666-666666666666";
const THREAD2 = "77777777-7777-7777-7777-777777777777";
const MSG1 = "88888888-8888-8888-8888-888888888888";
const MSG2 = "99999999-9999-9999-9999-999999999999";
const MSG3 = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const PID1 = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

// --- Pure helpers -----------------------------------------------------------

Deno.test("messageTs coalesces receivedAt, else createdAt, else ''", () => {
  assertEquals(
    messageTs({ receivedAt: "2026-09-05T00:00:00.000Z", createdAt: "x" }),
    "2026-09-05T00:00:00.000Z",
  );
  assertEquals(
    messageTs({ receivedAt: null, createdAt: "2026-09-05T00:00:00.000Z" }),
    "2026-09-05T00:00:00.000Z",
  );
  assertEquals(messageTs({}), "");
});

Deno.test("pickLastMessage is receivedAt-null-safe (F15): createdAt fallback wins", () => {
  const older = { id: MSG1, receivedAt: "2026-09-01T00:00:00.000Z" };
  // Null receivedAt but a LATER createdAt => this is the true last message.
  const newer = {
    id: MSG2,
    receivedAt: null,
    createdAt: "2026-09-05T00:00:00.000Z",
  };
  const last = pickLastMessage([older, newer]);
  assertEquals(last?.id, MSG2);
  // Order-independent.
  assertEquals(pickLastMessage([newer, older])?.id, MSG2);
  assertEquals(pickLastMessage([]), null);
});

Deno.test("deriveThreadState covers every branch (incl. unknown edge, F8)", () => {
  assertEquals(deriveThreadState("OUTGOING", 2, 7, 0), "empty");
  // Direction unknown => never guess.
  assertEquals(deriveThreadState("unknown", 2, 7, 3), "unknown");
  assertEquals(deriveThreadState("INCOMING", 100, 7, 3), "awaiting-us");
  assertEquals(deriveThreadState("OUTGOING", 2, 7, 3), "sent-unanswered");
  assertEquals(deriveThreadState("OUTGOING", 10, 7, 3), "dormant");
  // Null age with an OUTGOING last defaults to sent-unanswered (not dormant).
  assertEquals(deriveThreadState("OUTGOING", null, 7, 3), "sent-unanswered");
});

// --- Shared thread-scenario mock --------------------------------------------
// A two-message thread THREAD1: MSG1 OUTGOING (09-03), MSG2 INCOMING (09-05,
// receivedAt-null so its createdAt is the effective ts). Participants carry a
// raw handle + displayName that MUST be stripped from every snapshot (F6).
function threadOneHandler(method: string, path: string): unknown {
  if (method === "GET" && path.startsWith("/rest/messages?")) {
    return {
      data: {
        messages: [
          {
            id: MSG1,
            subject: "Re: hi",
            text: "hello there",
            receivedAt: "2026-09-03T00:00:00.000Z",
            createdAt: "2026-09-03T00:00:00.000Z",
          },
          {
            id: MSG2,
            subject: "",
            text: "reply",
            receivedAt: null,
            createdAt: "2026-09-05T00:00:00.000Z",
          },
        ],
      },
      pageInfo: { hasNextPage: false },
    };
  }
  if (
    method === "GET" &&
    path.startsWith("/rest/messageChannelMessageAssociations?")
  ) {
    if (path.includes(MSG1)) {
      return {
        data: {
          messageChannelMessageAssociations: [{ direction: "OUTGOING" }],
        },
      };
    }
    if (path.includes(MSG2)) {
      return {
        data: {
          messageChannelMessageAssociations: [{ direction: "INCOMING" }],
        },
      };
    }
    return { data: { messageChannelMessageAssociations: [] } };
  }
  if (method === "GET" && path.startsWith("/rest/messageParticipants?")) {
    return {
      data: {
        messageParticipants: [
          {
            personId: PID1,
            role: path.includes(MSG1) ? "from" : "to",
            handle: "ada@example.com",
            displayName: "Ada Lovelace",
          },
        ],
      },
    };
  }
  return {};
}

Deno.test("listThreads (opportunity target): body-free per-thread summary", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (method === "GET" && path.startsWith("/rest/messageThreadTargets?")) {
      return {
        data: {
          messageThreadTargets: [{ id: "tt1", messageThreadId: THREAD1 }],
        },
        pageInfo: { hasNextPage: false },
      };
    }
    return threadOneHandler(method, path);
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listThreads.execute(
      { opportunityId: T_OPP, limit: 30, messageLimit: 60 } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "threadList");
    assert(snap, "expected a threadList snapshot");
    assert(String(snap!.name).startsWith("threads-"));
    const d = snap!.data;
    assertEquals((d.target as Record<string, unknown>).kind, "opportunity");
    assertEquals((d.target as Record<string, unknown>).found, true);
    assertEquals((d.target as Record<string, unknown>).resolvedId, T_OPP);
    assertEquals(d.count, 1);
    const items = d.items as Array<Record<string, unknown>>;
    assertEquals(items[0].id, THREAD1);
    assertEquals(items[0].messageCount, 2);
    // Subject comes from the true LAST message (MSG2, empty subject).
    assertEquals(items[0].subjectPresent, false);
    assertEquals(items[0].subjectLength, 0);
    assertEquals(items[0].lastOutboundAt, "2026-09-03T00:00:00.000Z");
    assertEquals(items[0].lastInboundAt, "2026-09-05T00:00:00.000Z");
    // Participants deduped to ONE join key; no handle/displayName.
    const parts = items[0].participants as Array<Record<string, unknown>>;
    assertEquals(parts.length, 1);
    assertEquals(parts[0].personId, PID1);
    // Filtered on the correct polymorphic field (F18).
    assert(
      calls.some((c) =>
        c.path.startsWith("/rest/messageThreadTargets?") &&
        c.path.includes("targetOpportunityId")
      ),
    );
    // PII guard (F6): no raw handle/name/subject/body anywhere in the snapshot.
    const blob = JSON.stringify(d);
    for (
      const pii of [
        "ada@example.com",
        "Ada Lovelace",
        "hello there",
        "reply",
        "Re: hi",
      ]
    ) {
      assert(!blob.includes(pii), `snapshot leaked PII: ${pii}`);
    }
  } finally {
    restore();
  }
});

Deno.test("listThreads rejects a non-UUID opportunity target before I/O", async () => {
  const { calls, restore } = stubTwentyFetch(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.listThreads.execute(
          { opportunityId: "not-a-uuid", limit: 30, messageLimit: 60 } as never,
          ctx as never,
        ),
      Error,
      "Invalid opportunityId",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("listThreads (leadId -> person fallback): resolves person when no opp", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (method === "GET" && path.startsWith("/rest/opportunities?")) {
      return { data: { opportunities: [] } }; // no opp for this lead
    }
    if (method === "GET" && path.startsWith("/rest/people?")) {
      return { data: { people: [{ id: T_PERSON }] } };
    }
    if (method === "GET" && path.startsWith("/rest/messageThreadTargets?")) {
      return {
        data: {
          messageThreadTargets: [{ id: "tt-x", messageThreadId: THREAD1 }],
        },
        pageInfo: { hasNextPage: false },
      };
    }
    return threadOneHandler(method, path);
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listThreads.execute(
      { leadId: "LEAD-1", limit: 30, messageLimit: 60 } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "threadList");
    const t = snap!.data.target as Record<string, unknown>;
    assertEquals(t.kind, "leadId");
    assertEquals(t.resolvedKind, "person");
    assertEquals(t.resolvedId, T_PERSON);
    // Filtered by the PERSON join column, never the opportunity one (F18).
    assert(
      calls.some((c) =>
        c.path.startsWith("/rest/messageThreadTargets?") &&
        c.path.includes("targetPersonId")
      ),
    );
    assert(
      !calls.some((c) => c.path.includes("targetOpportunityId")),
    );
  } finally {
    restore();
  }
});

Deno.test("listThreads (leadId with no opp AND no person): found:false, empty", async () => {
  const { restore } = stubTwentyFetch((method, path) => {
    if (method === "GET" && path.startsWith("/rest/opportunities?")) {
      return { data: { opportunities: [] } };
    }
    if (method === "GET" && path.startsWith("/rest/people?")) {
      return { data: { people: [] } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listThreads.execute(
      { leadId: "LEAD-nope", limit: 30, messageLimit: 60 } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "threadList");
    assertEquals((snap!.data.target as Record<string, unknown>).found, false);
    assertEquals(snap!.data.count, 0);
    assertEquals(snap!.data.stopReason, "complete");
    assertEquals((snap!.data.items as unknown[]).length, 0);
  } finally {
    restore();
  }
});

Deno.test("getThread: oldest->newest ordering + body-free views (F6/F15)", async () => {
  const { restore } = stubTwentyFetch((method, path) =>
    threadOneHandler(method, path)
  );
  const { writes, ctx } = readCtx();
  try {
    await model.methods.getThread.execute(
      { threadId: THREAD1, limit: 200 } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "threadDetail");
    assert(snap, "expected a threadDetail snapshot");
    assertEquals(snap!.name, `thread-${THREAD1}`);
    const msgs = snap!.data.messages as Array<Record<string, unknown>>;
    // Oldest (MSG1, 09-03) -> newest (MSG2, 09-05 via createdAt fallback).
    assertEquals(msgs.map((m) => m.id), [MSG1, MSG2]);
    assertEquals(msgs[0].direction, "OUTGOING");
    assertEquals(msgs[1].direction, "INCOMING");
    // Subject/body as presence+length only, never text.
    assertEquals(msgs[0].subjectPresent, true);
    assertEquals(msgs[0].subjectLength, 6); // "Re: hi"
    assertEquals(msgs[0].bodyLength, 11); // "hello there"
    const blob = JSON.stringify(snap!.data);
    for (
      const pii of ["ada@example.com", "Ada Lovelace", "hello there", "Re: hi"]
    ) {
      assert(!blob.includes(pii), `getThread leaked PII: ${pii}`);
    }
  } finally {
    restore();
  }
});

Deno.test("getThread: message with no association => direction 'unknown' (F8 edge)", async () => {
  const { restore } = stubTwentyFetch((method, path) => {
    if (method === "GET" && path.startsWith("/rest/messages?")) {
      return {
        data: {
          messages: [{
            id: MSG3,
            subject: "x",
            text: "y",
            createdAt: "2026-09-06T00:00:00.000Z",
          }],
        },
        pageInfo: { hasNextPage: false },
      };
    }
    if (
      method === "GET" &&
      path.startsWith("/rest/messageChannelMessageAssociations?")
    ) {
      return { data: { messageChannelMessageAssociations: [] } }; // no association
    }
    if (method === "GET" && path.startsWith("/rest/messageParticipants?")) {
      return { data: { messageParticipants: [] } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.getThread.execute(
      { threadId: THREAD2, limit: 200 } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "threadDetail");
    const msgs = snap!.data.messages as Array<Record<string, unknown>>;
    assertEquals(msgs[0].direction, "unknown");
  } finally {
    restore();
  }
});

Deno.test("getThread rejects a non-UUID threadId before any I/O", async () => {
  const { calls, restore } = stubTwentyFetch(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.getThread.execute(
          { threadId: "not-a-uuid", limit: 200 } as never,
          ctx as never,
        ),
      Error,
      "Invalid threadId",
    );
    assertEquals(calls.length, 0);
  } finally {
    restore();
  }
});

Deno.test("threadStatus (single thread): last INCOMING => awaiting-us", async () => {
  const { restore } = stubTwentyFetch((method, path) =>
    threadOneHandler(method, path)
  );
  const { writes, ctx } = readCtx();
  try {
    await model.methods.threadStatus.execute(
      {
        threadId: THREAD1,
        dormantDays: 7,
        limit: 30,
        messageLimit: 60,
      } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "threadStatus");
    assert(snap, "expected a threadStatus snapshot");
    assertEquals(snap!.name, `thread-status-${THREAD1}`);
    const items = snap!.data.items as Array<Record<string, unknown>>;
    assertEquals(items[0].state, "awaiting-us");
    assertEquals(items[0].lastDirection, "INCOMING");
    assertEquals(items[0].messageCount, 2);
  } finally {
    restore();
  }
});

Deno.test("threadStatus: OUTGOING last, old => dormant", async () => {
  const { restore } = stubTwentyFetch((method, path) => {
    if (method === "GET" && path.startsWith("/rest/messages?")) {
      return {
        data: {
          messages: [{
            id: MSG1,
            subject: "hi",
            text: "old outbound",
            receivedAt: null,
            createdAt: "2020-01-01T00:00:00.000Z",
          }],
        },
        pageInfo: { hasNextPage: false },
      };
    }
    if (
      method === "GET" &&
      path.startsWith("/rest/messageChannelMessageAssociations?")
    ) {
      return {
        data: {
          messageChannelMessageAssociations: [{ direction: "OUTGOING" }],
        },
      };
    }
    if (method === "GET" && path.startsWith("/rest/messageParticipants?")) {
      return { data: { messageParticipants: [] } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.threadStatus.execute(
      {
        threadId: THREAD1,
        dormantDays: 7,
        limit: 30,
        messageLimit: 60,
      } as never,
      ctx as never,
    );
    const items = (writes.find((w) => w.type === "threadStatus"))!.data
      .items as Array<Record<string, unknown>>;
    assertEquals(items[0].state, "dormant");
    assertEquals(items[0].lastDirection, "OUTGOING");
    assert((items[0].ageDays as number) > 7);
  } finally {
    restore();
  }
});

Deno.test("threadStatus: no association on last message => state 'unknown' (F8)", async () => {
  const { restore } = stubTwentyFetch((method, path) => {
    if (method === "GET" && path.startsWith("/rest/messages?")) {
      return {
        data: {
          messages: [{ id: MSG3, createdAt: "2026-09-06T00:00:00.000Z" }],
        },
        pageInfo: { hasNextPage: false },
      };
    }
    if (
      method === "GET" &&
      path.startsWith("/rest/messageChannelMessageAssociations?")
    ) {
      return { data: { messageChannelMessageAssociations: [] } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.threadStatus.execute(
      {
        threadId: THREAD2,
        dormantDays: 7,
        limit: 30,
        messageLimit: 60,
      } as never,
      ctx as never,
    );
    const items = (writes.find((w) => w.type === "threadStatus"))!.data
      .items as Array<Record<string, unknown>>;
    assertEquals(items[0].state, "unknown");
    assertEquals(items[0].lastDirection, "unknown");
  } finally {
    restore();
  }
});

Deno.test("threadStatus (leadId target): resolves opp, statuses its threads", async () => {
  const { calls, restore } = stubTwentyFetch((method, path) => {
    if (method === "GET" && path.startsWith("/rest/opportunities?")) {
      return { data: { opportunities: [{ id: T_OPP }] } };
    }
    if (method === "GET" && path.startsWith("/rest/messageThreadTargets?")) {
      return {
        data: {
          messageThreadTargets: [{ id: "tt-x", messageThreadId: THREAD1 }],
        },
        pageInfo: { hasNextPage: false },
      };
    }
    return threadOneHandler(method, path);
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.threadStatus.execute(
      {
        leadId: "LEAD-1",
        dormantDays: 7,
        limit: 30,
        messageLimit: 60,
      } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "threadStatus");
    const t = snap!.data.target as Record<string, unknown>;
    assertEquals(t.kind, "leadId");
    assertEquals(t.resolvedKind, "opportunity");
    assertEquals(t.resolvedId, T_OPP);
    assertEquals(snap!.data.count, 1);
    const items = snap!.data.items as Array<Record<string, unknown>>;
    assertEquals(items[0].threadId, THREAD1);
    assertEquals(items[0].state, "awaiting-us");
    assert(
      calls.some((c) =>
        c.path.startsWith("/rest/messageThreadTargets?") &&
        c.path.includes("targetOpportunityId")
      ),
    );
  } finally {
    restore();
  }
});

Deno.test("threadStatus refuses threadId AND a record target together", async () => {
  const { restore } = stubTwentyFetch(() => ({}));
  const { ctx } = readCtx();
  try {
    await assertRejects(
      () =>
        model.methods.threadStatus.execute(
          {
            threadId: THREAD1,
            opportunityId: T_OPP,
            dormantDays: 7,
            limit: 30,
            messageLimit: 60,
          } as never,
          ctx as never,
        ),
      Error,
      "not both",
    );
  } finally {
    restore();
  }
});

// ===========================================================================
// TWENTY-EMAIL send subsystem (mocked — NO live calls)
// ===========================================================================

const S_CID = "11111111-1111-4111-8111-111111111111";
const S_PERSON = "22222222-2222-4222-8222-222222222222";
const S_OPP = "33333333-3333-4333-8333-333333333333";
const S_WVID = "44444444-4444-4444-8444-444444444444";

// A ctx whose globalArgs carry the send subsystem fields (mirrors readCtx).
function sendCtx(overrides?: Record<string, unknown>): {
  writes: Array<{ type: string; name: string; data: Record<string, unknown> }>;
  ctx: unknown;
} {
  const writes: Array<
    { type: string; name: string; data: Record<string, unknown> }
  > = [];
  return {
    writes,
    ctx: {
      globalArgs: {
        baseUrl: "https://crm.example.com",
        apiToken: "tok",
        opportunityStage: "NEW",
        emailDomainBlocklist: [...DEFAULT_EMAIL_DOMAIN_BLOCKLIST],
        emergencyRestrictedRole: "",
        noteHashHmacKey: "",
        sendUserEmail: "svc@brandhost.example",
        sendUserPassword: "hunter2",
        brandConnectedAccounts: { "brandhost.example": S_CID },
        lineOfBusinessBrand: {},
        sendWorkflowName: "Send Email",
        twentyOrigin: "",
        ...overrides,
      },
      logger: { debug() {}, info() {}, warning() {}, error() {} },
      writeResource: (
        type: string,
        name: string,
        data: Record<string, unknown>,
      ) => {
        writes.push({ type, name, data });
        return Promise.resolve({ name });
      },
    },
  };
}

// A fetch router for the send path. Routes graphql ops by body.query content and
// REST by method+path. Every handler is mock-only; nothing hits the network.
function sendRouter(opts: {
  accounts?: Array<Record<string, unknown>>;
  workflows?: Array<Record<string, unknown>>;
  priorNotes?: Array<Record<string, unknown>>;
  runId?: string;
  lob?: string | null;
  personEmail?: string;
  loginToken?: string | null;
  accessToken?: string | null;
} = {}) {
  const accounts = opts.accounts ??
    [{
      id: S_CID,
      handle: "send@brandhost.example",
      provider: "google",
      authFailedAt: null,
      archivedAt: null,
    }];
  const workflows = opts.workflows ??
    [{ id: "wf1", name: "Send Email", lastPublishedVersionId: S_WVID }];
  return (method: string, path: string, body: unknown): unknown => {
    if (method === "POST" && path === "/graphql") {
      const q = String((body as { query?: string })?.query ?? "");
      if (q.includes("getLoginTokenFromCredentials")) {
        return {
          data: {
            getLoginTokenFromCredentials: {
              loginToken: opts.loginToken === undefined
                ? "login-tok"
                : opts.loginToken,
            },
          },
        };
      }
      if (q.includes("getAuthTokensFromLoginToken")) {
        return {
          data: {
            getAuthTokensFromLoginToken: {
              tokens: {
                accessOrWorkspaceAgnosticToken: {
                  token: opts.accessToken === undefined
                    ? "access-tok"
                    : opts.accessToken,
                  expiresAt: "2026-09-21T01:00:00.000Z",
                },
                refreshToken: { token: "refresh-tok", expiresAt: "x" },
              },
            },
          },
        };
      }
      if (q.includes("runWorkflowVersion")) {
        return {
          data: {
            runWorkflowVersion: { workflowRunId: opts.runId ?? "run-1" },
          },
        };
      }
      return { data: {} };
    }
    if (method === "POST" && path === "/metadata") {
      return { data: { myConnectedAccounts: accounts } };
    }
    if (method === "GET" && path.startsWith("/rest/workflows")) {
      return { data: { workflows } };
    }
    if (method === "GET" && path.startsWith("/rest/notes")) {
      return { data: { notes: opts.priorNotes ?? [] } };
    }
    if (method === "POST" && path === "/rest/notes") {
      return { data: { createNote: { id: "marker-note" } } };
    }
    if (method === "GET" && path.startsWith("/rest/opportunities/")) {
      return { data: { opportunity: { lineOfBusiness: opts.lob ?? null } } };
    }
    if (method === "GET" && path.startsWith("/rest/people/")) {
      return {
        data: { person: { emails: { primaryEmail: opts.personEmail ?? "" } } },
      };
    }
    return {};
  };
}

// --- pure helpers ---

Deno.test("handleDomain keeps the domain only, never the local-part", () => {
  assertEquals(handleDomain("Alice.Sender@Brandhost.Example"), "brandhost.example");
  assertEquals(handleDomain("nodomain"), "");
  assertEquals(handleDomain(null), "");
});

Deno.test("validateBrandMap: rejects a non-UUID value (F14 load)", () => {
  assert(validateBrandMap({ "brandhost.example": "not-a-uuid" }) !== null);
  assert(validateBrandMap({ "brandhost.example": "" }) !== null);
});

Deno.test("validateBrandMap: rejects duplicate connectedAccountIds (F14)", () => {
  const err = validateBrandMap({ "brandhost.example": S_CID, "brandmail.example": S_CID });
  assert(err !== null && /duplicate/.test(err));
});

Deno.test("validateBrandMap: an empty or all-valid map passes", () => {
  assertEquals(validateBrandMap({}), null);
  assertEquals(validateBrandMap({ "brandhost.example": S_CID }), null);
});

Deno.test("resolveBrandForSend: explicit unmapped fromBrand => hard refuse (F4)", () => {
  const r = resolveBrandForSend({
    fromBrand: "brandzzz.example",
    targetKind: "opportunity",
    lineOfBusiness: "HOSTING",
    brandMap: { "brandhost.example": S_CID },
    lobMap: { HOSTING: "brandhost.example" },
  });
  assertEquals(r.ok, false);
  if (!r.ok) assert(/F4/.test(r.reason));
});

Deno.test("resolveBrandForSend: empty mapped connectedAccountId => hard refuse", () => {
  const r = resolveBrandForSend({
    fromBrand: "brandhost.example",
    targetKind: "person",
    brandMap: { "brandhost.example": "" },
    lobMap: {},
  });
  assertEquals(r.ok, false);
});

Deno.test("resolveBrandForSend: non-opp target, no fromBrand => refuse (F5)", () => {
  const r = resolveBrandForSend({
    targetKind: "person",
    brandMap: { "brandhost.example": S_CID },
    lobMap: { HOSTING: "brandhost.example" },
  });
  assertEquals(r.ok, false);
  if (!r.ok) assert(/F5/.test(r.reason));
});

Deno.test("resolveBrandForSend: opp + LoB default resolves (F5 default)", () => {
  const r = resolveBrandForSend({
    targetKind: "opportunity",
    lineOfBusiness: "HOSTING",
    brandMap: { "brandhost.example": S_CID },
    lobMap: { HOSTING: "brandhost.example" },
  });
  assertEquals(r.ok, true);
  if (r.ok) {
    assertEquals(r.connectedAccountId, S_CID);
    assertEquals(r.brand, "brandhost.example");
    assertEquals(r.source, "lob-default");
  }
});

Deno.test("computeDedupKey is stable within a UTC day and varies by input", async () => {
  const now = new Date("2026-09-21T12:00:00.000Z");
  const a = await computeDedupKey({
    to: "x@y.com",
    connectedAccountId: S_CID,
    subject: "hi",
    body: "b",
    now,
  });
  const b = await computeDedupKey({
    to: "x@y.com",
    connectedAccountId: S_CID,
    subject: "hi",
    body: "b",
    now: new Date("2026-09-21T23:00:00.000Z"),
  });
  const c = await computeDedupKey({
    to: "x@y.com",
    connectedAccountId: S_CID,
    subject: "different",
    body: "b",
    now,
  });
  assertEquals(a, b); // same UTC day => same key
  assert(a !== c); // different subject => different key
});

// --- token mint ---

Deno.test("mintUserAccessToken: happy path returns the access token", async () => {
  const { restore } = stubTwentyFetch(sendRouter());
  try {
    const tok = await mintUserAccessToken({
      baseUrl: "https://crm.example.com",
      apiToken: "tok",
      sendUserEmail: "svc@brandhost.example",
      sendUserPassword: "pw",
      twentyOrigin: "",
    } as never);
    assertEquals(tok, "access-tok");
  } finally {
    restore();
  }
});

Deno.test("mintUserAccessToken: fail-closed on missing credentials (no I/O)", async () => {
  const orig = globalThis.fetch;
  let called = false;
  globalThis.fetch = (() => {
    called = true;
    return Promise.resolve(new Response("{}", { status: 200 }));
  }) as typeof fetch;
  try {
    await assertRejects(
      () =>
        mintUserAccessToken({
          baseUrl: "https://crm.example.com",
          apiToken: "tok",
          sendUserEmail: "",
          sendUserPassword: "",
          twentyOrigin: "",
        } as never),
      Error,
      "not configured",
    );
    assertEquals(called, false);
  } finally {
    globalThis.fetch = orig;
  }
});

Deno.test("mintUserAccessToken: fail-closed when step 1 yields no loginToken", async () => {
  const { restore } = stubTwentyFetch(sendRouter({ loginToken: null }));
  try {
    await assertRejects(
      () =>
        mintUserAccessToken({
          baseUrl: "https://crm.example.com",
          apiToken: "tok",
          sendUserEmail: "svc@brandhost.example",
          sendUserPassword: "pw",
          twentyOrigin: "",
        } as never),
      Error,
      "step 1",
    );
  } finally {
    restore();
  }
});

// --- listConnectedAccounts ---

Deno.test("listConnectedAccounts: domain-only snapshot, never the full handle (PII)", async () => {
  const { restore } = stubTwentyFetch(sendRouter({
    accounts: [
      {
        id: S_CID,
        handle: "Alice.Sender@brandhost.example",
        provider: "google",
        authFailedAt: null,
        archivedAt: null,
      },
      {
        id: "55555555-5555-4555-8555-555555555555",
        handle: "ops@brandmail.example",
        provider: "microsoft",
        authFailedAt: "2026-09-01T00:00:00Z",
        archivedAt: null,
      },
    ],
  }));
  const { writes, ctx } = sendCtx();
  try {
    await model.methods.listConnectedAccounts.execute(
      {} as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "connectedAccountList");
    assert(snap, "expected a connectedAccountList snapshot");
    const items = snap!.data.items as Array<Record<string, unknown>>;
    assertEquals(items.length, 2);
    assertEquals(items[0].domain, "brandhost.example");
    assertEquals(items[0].authFailed, false);
    assertEquals(items[1].domain, "brandmail.example");
    assertEquals(items[1].authFailed, true);
    // PII guard: no full handle / local-part anywhere.
    const blob = JSON.stringify(snap!.data);
    for (
      const pii of [
        "Alice.Sender",
        "alice.sender",
        "ops@brandmail.example",
        "@brandhost.example",
      ]
    ) {
      assert(!blob.includes(pii), `snapshot leaked handle: ${pii}`);
    }
  } finally {
    restore();
  }
});

// --- sendEmail ---

Deno.test("sendEmail: dryRun returns a plan and records NO dedup marker", async () => {
  const { calls, restore } = stubTwentyFetch(sendRouter());
  const { writes, ctx } = sendCtx();
  try {
    await model.methods.sendEmail.execute(
      {
        personId: S_PERSON,
        to: "client@corp.example",
        subject: "Hello",
        body: "Body text",
        fromBrand: "brandhost.example",
      } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "sendRun");
    assert(snap, "expected a sendRun snapshot");
    assertEquals(snap!.data.status, "planned");
    assertEquals(snap!.data.dryRun, true);
    assertEquals(snap!.data.wouldSend, true);
    assertEquals(snap!.data.dedupRecorded, false);
    assertEquals(snap!.data.connectedAccountId, S_CID);
    assertEquals(snap!.data.workflowVersionId, S_WVID);
    // NO send + NO durable marker write on dryRun.
    assert(
      !calls.some((c) =>
        c.method === "POST" && c.path === "/graphql" &&
        String((c.body as { query?: string })?.query ?? "").includes(
          "runWorkflowVersion",
        )
      ),
      "dryRun must not call runWorkflowVersion",
    );
    assert(
      !calls.some((c) => c.method === "POST" && c.path === "/rest/notes"),
      "dryRun must not write a dedup marker",
    );
    // PII guard.
    const blob = JSON.stringify(snap!.data);
    for (const pii of ["client@corp.example", "Hello", "Body text"]) {
      assert(!blob.includes(pii), `sendRun leaked PII: ${pii}`);
    }
  } finally {
    restore();
  }
});

Deno.test("sendEmail: explicit unmapped fromBrand => refuse (F4)", async () => {
  const { restore } = stubTwentyFetch(sendRouter());
  const { ctx } = sendCtx();
  try {
    await assertRejects(
      () =>
        model.methods.sendEmail.execute(
          {
            personId: S_PERSON,
            to: "c@corp.example",
            subject: "x",
            body: "y",
            fromBrand: "brandzzz.example",
          } as never,
          ctx as never,
        ),
      Error,
      "not in brandConnectedAccounts",
    );
  } finally {
    restore();
  }
});

Deno.test("sendEmail: non-opp target with no fromBrand => refuse (F5)", async () => {
  const { restore } = stubTwentyFetch(sendRouter());
  const { ctx } = sendCtx();
  try {
    await assertRejects(
      () =>
        model.methods.sendEmail.execute(
          {
            personId: S_PERSON,
            to: "c@corp.example",
            subject: "x",
            body: "y",
          } as never,
          ctx as never,
        ),
      Error,
      "explicit fromBrand required",
    );
  } finally {
    restore();
  }
});

Deno.test("sendEmail: invalid map (empty connectedAccountId) => hard refuse (F14)", async () => {
  const { restore } = stubTwentyFetch(sendRouter());
  const { ctx } = sendCtx({ brandConnectedAccounts: { "brandhost.example": "" } });
  try {
    await assertRejects(
      () =>
        model.methods.sendEmail.execute(
          {
            personId: S_PERSON,
            to: "c@corp.example",
            subject: "x",
            body: "y",
            fromBrand: "brandhost.example",
          } as never,
          ctx as never,
        ),
      Error,
      "brandConnectedAccounts invalid",
    );
  } finally {
    restore();
  }
});

Deno.test("sendEmail: live domain mismatch => refuse (F3)", async () => {
  // The mapped account's live handle is on a DIFFERENT domain than the brand.
  const { restore } = stubTwentyFetch(sendRouter({
    accounts: [{
      id: S_CID,
      handle: "send@brandgames.example",
      provider: "google",
      authFailedAt: null,
      archivedAt: null,
    }],
  }));
  const { ctx } = sendCtx();
  try {
    await assertRejects(
      () =>
        model.methods.sendEmail.execute(
          {
            personId: S_PERSON,
            to: "c@corp.example",
            subject: "x",
            body: "y",
            fromBrand: "brandhost.example",
            dryRun: false,
            confirm: true,
          } as never,
          ctx as never,
        ),
      Error,
      "domain mismatch",
    );
  } finally {
    restore();
  }
});

Deno.test("sendEmail: invalid recipient => refuse (F11)", async () => {
  const { restore } = stubTwentyFetch(sendRouter());
  const { ctx } = sendCtx();
  try {
    await assertRejects(
      () =>
        model.methods.sendEmail.execute(
          {
            personId: S_PERSON,
            to: "not an email",
            subject: "x",
            body: "y",
            fromBrand: "brandhost.example",
          } as never,
          ctx as never,
        ),
      Error,
      "valid recipient",
    );
  } finally {
    restore();
  }
});

Deno.test("sendEmail: no active Send-Email workflow version => refuse (F12)", async () => {
  const { restore } = stubTwentyFetch(sendRouter({ workflows: [] }));
  const { ctx } = sendCtx();
  try {
    await assertRejects(
      () =>
        model.methods.sendEmail.execute(
          {
            personId: S_PERSON,
            to: "c@corp.example",
            subject: "x",
            body: "y",
            fromBrand: "brandhost.example",
            dryRun: false,
            confirm: true,
          } as never,
          ctx as never,
        ),
      Error,
      "no active/published version",
    );
  } finally {
    restore();
  }
});

Deno.test("sendEmail: durable dedup hit => skipped, no send (F9/F10)", async () => {
  const { calls, restore } = stubTwentyFetch(sendRouter({
    priorNotes: [{ id: "prior-marker", leadId: "send-abc" }],
  }));
  const { writes, ctx } = sendCtx();
  try {
    await model.methods.sendEmail.execute(
      {
        personId: S_PERSON,
        to: "c@corp.example",
        subject: "x",
        body: "y",
        fromBrand: "brandhost.example",
        dryRun: false,
        confirm: true,
      } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "sendRun");
    assert(snap, "expected a sendRun snapshot");
    assertEquals(snap!.data.status, "skipped");
    assertEquals(snap!.data.skipped, true);
    assertEquals(snap!.data.sent, false);
    // A dedup hit must NOT enqueue the workflow.
    assert(
      !calls.some((c) =>
        c.method === "POST" && c.path === "/graphql" &&
        String((c.body as { query?: string })?.query ?? "").includes(
          "runWorkflowVersion",
        )
      ),
      "a dedup hit must not send",
    );
  } finally {
    restore();
  }
});

Deno.test("sendEmail: confirm + dryRun:false records workflowRunId, PII-safe (F13)", async () => {
  const { calls, restore } = stubTwentyFetch(sendRouter({ runId: "run-xyz" }));
  const { writes, ctx } = sendCtx();
  try {
    await model.methods.sendEmail.execute(
      {
        personId: S_PERSON,
        to: "client@corp.example",
        subject: "Résumé",
        body: "Bonne journée",
        fromBrand: "brandhost.example",
        dryRun: false,
        confirm: true,
      } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "sendRun");
    assert(snap, "expected a sendRun snapshot");
    assertEquals(snap!.data.status, "sent");
    assertEquals(snap!.data.sent, true);
    assertEquals(snap!.data.workflowRunId, "run-xyz");
    assertEquals(snap!.data.dedupRecorded, true);
    // runWorkflowVersion was called with the pinned connectedAccountId in the payload.
    const runCall = calls.find((c) =>
      c.method === "POST" && c.path === "/graphql" &&
      String((c.body as { query?: string })?.query ?? "").includes(
        "runWorkflowVersion",
      )
    );
    assert(runCall, "expected a runWorkflowVersion call");
    const input =
      (runCall!.body as { variables?: { input?: Record<string, unknown> } })
        ?.variables?.input as Record<string, unknown>;
    const payload = input.payload as Record<string, unknown>;
    assertEquals(payload.connectedAccountId, S_CID);
    assertEquals(input.workflowVersionId, S_WVID);
    // A durable dedup marker was written AFTER the send.
    assert(
      calls.some((c) => c.method === "POST" && c.path === "/rest/notes"),
      "expected a durable dedup marker write",
    );
    // PII guard: no raw to/subject/body in the audit.
    const blob = JSON.stringify(snap!.data);
    for (const pii of ["client@corp.example", "Résumé", "Bonne journée"]) {
      assert(!blob.includes(pii), `sendRun leaked PII: ${pii}`);
    }
  } finally {
    restore();
  }
});

Deno.test("sendEmail: sanitizeText preserves UTF-8 in the workflow payload (F19)", async () => {
  const { calls, restore } = stubTwentyFetch(sendRouter());
  const { ctx } = sendCtx();
  try {
    await model.methods.sendEmail.execute(
      {
        personId: S_PERSON,
        to: "c@corp.example",
        subject: "Événement — café",
        body: "你好世界",
        fromBrand: "brandhost.example",
        dryRun: false,
        confirm: true,
      } as never,
      ctx as never,
    );
    const runCall = calls.find((c) =>
      c.method === "POST" && c.path === "/graphql" &&
      String((c.body as { query?: string })?.query ?? "").includes(
        "runWorkflowVersion",
      )
    );
    assert(runCall, "expected a runWorkflowVersion call");
    const payload = (runCall!.body as {
      variables?: { input?: { payload?: Record<string, unknown> } };
    })?.variables?.input?.payload as Record<string, unknown>;
    // Accented + CJK characters survive sanitization (NOT ASCII-forced).
    assert(String(payload.subject).includes("café"));
    assert(String(payload.body).includes("你好世界"));
  } finally {
    restore();
  }
});

Deno.test("sendEmail: dryRun:false without confirm => refuse", async () => {
  const { restore } = stubTwentyFetch(sendRouter());
  const { ctx } = sendCtx();
  try {
    await assertRejects(
      () =>
        model.methods.sendEmail.execute(
          {
            personId: S_PERSON,
            to: "c@corp.example",
            subject: "x",
            body: "y",
            fromBrand: "brandhost.example",
            dryRun: false,
          } as never,
          ctx as never,
        ),
      Error,
      "requires confirm:true",
    );
  } finally {
    restore();
  }
});

// --- transport helpers ---

Deno.test("resolveActiveWorkflowVersionId returns lastPublishedVersionId or null", async () => {
  const { restore } = stubTwentyFetch(sendRouter());
  try {
    const cfg = {
      baseUrl: "https://crm.example.com",
      apiToken: "tok",
    } as never;
    assertEquals(
      await resolveActiveWorkflowVersionId(cfg, "Send Email"),
      S_WVID,
    );
    restore();
    const { restore: r2 } = stubTwentyFetch(sendRouter({ workflows: [] }));
    assertEquals(await resolveActiveWorkflowVersionId(cfg, "Send Email"), null);
    r2();
  } finally {
    // already restored
  }
});

Deno.test("fetchConnectedAccounts reduces rows to domain-only + booleans", async () => {
  const { restore } = stubTwentyFetch(sendRouter({
    accounts: [{
      id: S_CID,
      handle: "x@brandhost.example",
      provider: "google",
      authFailedAt: null,
      archivedAt: "2026-01-01T00:00:00Z",
    }],
  }));
  try {
    const accts = await fetchConnectedAccounts(
      { baseUrl: "https://crm.example.com", apiToken: "tok" } as never,
      "user-tok",
    );
    assertEquals(accts.length, 1);
    assertEquals(accts[0].domain, "brandhost.example");
    assertEquals(accts[0].archived, true);
    assertEquals(accts[0].authFailed, false);
    assertEquals(
      (accts[0] as unknown as Record<string, unknown>).handle,
      undefined,
    );
  } finally {
    restore();
  }
});

Deno.test("sendDedupMarkerId is filter-safe hex namespaced under send-", async () => {
  const id = await sendDedupMarkerId("arbitrary caller key!!");
  assert(id.startsWith("send-"));
  assert(isFilterSafe(id));
  assert(/^send-[0-9a-f]{64}$/.test(id));
  const sha = await sha256Hex("arbitrary caller key!!");
  assertEquals(id, "send-" + sha);
});

// ===========================================================================
// TWENTY-EMAIL code-review fixes: ORD-1 ordering, TE-1 redaction, TE-4 ambiguity,
// EMAIL-WF-1 duplicate workflow, EMAIL-DEDUP-1 marker namespace.
// ===========================================================================

// A >messageLimit thread spanning 2 pages: an INCOMING message is the OLDEST
// (page 1 in the old ASCENDING read) and an OUTGOING message is the NEWEST (page
// 2 in the old read, i.e. the TRUE last). With messageLimit=1 the per-thread read
// is capped to the head page, so the OLD ascending fetch would have returned the
// INCOMING oldest and derived the WRONG state; the EMAIL-ORD-1 newest-first fetch
// returns the OUTGOING newest on the head page and derives the true state. The
// handler serves a different single-record head page depending on order_by
// (DescNullsLast => newest-first).
function twoPageThreadHandler(method: string, path: string): unknown {
  const OLD_IN = {
    id: MSG1,
    subject: "",
    text: "inbound old",
    receivedAt: "2026-01-01T00:00:00.000Z",
    createdAt: "2026-01-01T00:00:00.000Z",
  };
  const NEW_OUT = {
    id: MSG2,
    subject: "",
    text: "outbound new",
    receivedAt: "2026-01-10T00:00:00.000Z",
    createdAt: "2026-01-10T00:00:00.000Z",
  };
  if (method === "GET" && path.startsWith("/rest/messages?")) {
    const desc = path.includes("DescNullsLast");
    const head = desc ? NEW_OUT : OLD_IN;
    // A capped head page with more pages available => truncated read.
    return {
      data: { messages: [head] },
      pageInfo: { hasNextPage: true, endCursor: "cur-1" },
    };
  }
  if (
    method === "GET" &&
    path.startsWith("/rest/messageChannelMessageAssociations?")
  ) {
    if (path.includes(MSG2)) {
      return {
        data: {
          messageChannelMessageAssociations: [{ direction: "OUTGOING" }],
        },
      };
    }
    if (path.includes(MSG1)) {
      return {
        data: {
          messageChannelMessageAssociations: [{ direction: "INCOMING" }],
        },
      };
    }
    return { data: { messageChannelMessageAssociations: [] } };
  }
  if (method === "GET" && path.startsWith("/rest/messageParticipants?")) {
    return { data: { messageParticipants: [] } };
  }
  return {};
}

Deno.test("threadStatus: >messageLimit thread, true-last OUTGOING on page 2 => sent-unanswered/dormant + truncated (EMAIL-ORD-1/EMAIL-TEST-1.2)", async () => {
  const { calls, restore } = stubTwentyFetch((m, p) =>
    twoPageThreadHandler(m, p)
  );
  const { writes, ctx } = readCtx();
  try {
    await model.methods.threadStatus.execute(
      {
        threadId: THREAD1,
        dormantDays: 7,
        limit: 30,
        messageLimit: 1,
      } as never,
      ctx as never,
    );
    const items = (writes.find((w) => w.type === "threadStatus"))!.data
      .items as Array<Record<string, unknown>>;
    // The verdict comes from the newest-first head (OUTGOING), NOT the oldest.
    assertEquals(items[0].lastDirection, "OUTGOING");
    assert(
      ["sent-unanswered", "dormant"].includes(String(items[0].state)),
      `expected sent-unanswered/dormant, got ${items[0].state}`,
    );
    // The capped read is flagged so a partial verdict is never authoritative.
    assertEquals(items[0].truncated, true);
    // Proof the message read was newest-first (bracket-modifier DescNullsLast).
    assert(
      calls.some((c) =>
        c.path.startsWith("/rest/messages?") && c.path.includes("DescNullsLast")
      ),
      "message read must be newest-first",
    );
  } finally {
    restore();
  }
});

Deno.test("listThreads: >messageLimit thread => lastOutboundAt reflects the page-2 (newest) message + truncated (EMAIL-ORD-1/EMAIL-TEST-1.2)", async () => {
  const { restore } = stubTwentyFetch((method, path) => {
    if (method === "GET" && path.startsWith("/rest/messageThreadTargets?")) {
      return {
        data: {
          messageThreadTargets: [{ id: "tt1", messageThreadId: THREAD1 }],
        },
        pageInfo: { hasNextPage: false },
      };
    }
    return twoPageThreadHandler(method, path);
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listThreads.execute(
      { opportunityId: T_OPP, limit: 30, messageLimit: 1 } as never,
      ctx as never,
    );
    const items = (writes.find((w) => w.type === "threadList"))!.data
      .items as Array<Record<string, unknown>>;
    assertEquals(items[0].id, THREAD1);
    // The newest message (page 2 in the old read) is OUTGOING and dominates.
    assertEquals(items[0].lastOutboundAt, "2026-01-10T00:00:00.000Z");
    assertEquals(items[0].lastInboundAt, undefined);
    assertEquals(items[0].truncated, true);
  } finally {
    restore();
  }
});

// ORD-1-R pin: the true-newest message is an OUTBOUND reply with receivedAt=NULL
// (the common shape for a just-sent reply). The head page must still contain it.
// This handler models Twenty's real ordering: whichever column LEADS the order_by
// decides the head. A receivedAt-led DescNullsLast (the ORD-1-R bug) buries the
// null-receivedAt row at the tail, so a cap=1 head is the OLD inbound; a
// createdAt-led order (the fix) keeps the newest-createdAt outbound in the head.
function nullRecvOutboundThreadHandler(method: string, path: string): unknown {
  const OLD_IN = {
    id: MSG1,
    subject: "",
    text: "",
    receivedAt: "2026-01-01T00:00:00.000Z",
    createdAt: "2026-01-01T00:00:00.000Z",
  };
  const NEW_OUT = {
    id: MSG2,
    subject: "",
    text: "",
    receivedAt: null,
    createdAt: "2026-01-10T00:00:00.000Z",
  };
  if (method === "GET" && path.startsWith("/rest/messages?")) {
    const m = path.match(/order_by=([^&]+)/);
    const ob = m ? decodeURIComponent(m[1]) : "";
    const leadsCreatedAt = /^createdAt\b/.test(ob);
    const head = leadsCreatedAt ? NEW_OUT : OLD_IN;
    return {
      data: { messages: [head] },
      pageInfo: { hasNextPage: true, endCursor: "cur-1" },
    };
  }
  return twoPageThreadHandler(method, path);
}

Deno.test("threadStatus: null-receivedAt OUTBOUND true-newest past the cap must not invert to awaiting-us (ORD-1-R)", async () => {
  const { restore } = stubTwentyFetch(nullRecvOutboundThreadHandler);
  const { writes, ctx } = readCtx();
  try {
    await model.methods.threadStatus.execute(
      {
        threadId: THREAD1,
        dormantDays: 7,
        limit: 30,
        messageLimit: 1,
      } as never,
      ctx as never,
    );
    const items = (writes.find((w) => w.type === "threadStatus"))!.data
      .items as Array<Record<string, unknown>>;
    // Fixed (createdAt-led) order keeps the null-receivedAt newest OUTGOING in the
    // head; the ORD-1-R bug (receivedAt-led) would bury it -> wrongly awaiting-us.
    assertEquals(items[0].lastDirection, "OUTGOING");
    assert(
      ["sent-unanswered", "dormant"].includes(String(items[0].state)),
      `expected sent-unanswered/dormant, got ${items[0].state}`,
    );
    assertEquals(items[0].truncated, true);
  } finally {
    restore();
  }
});

Deno.test("redactError masks additional literal secrets (TE-1)", () => {
  const out = redactError(
    new Error("boom: password=hunter2 and token usr-token-xyz remained"),
    300,
    "apitok",
    ["hunter2", "usr-token-xyz"],
  );
  assert(!out.includes("hunter2"), "leaked the send password");
  assert(!out.includes("usr-token-xyz"), "leaked the minted user token");
  // Backward compatible: undefined/short secrets are ignored, not thrown on.
  const out2 = redactError(new Error("plain"), 300, undefined, [
    undefined,
    "ab",
  ]);
  assertEquals(out2, "plain");
});

Deno.test("mint/send path: a failing mint error carries neither the password nor the raw server body (TE-1)", async () => {
  const orig = globalThis.fetch;
  // The auth graphql endpoint fails 401 with a body that ECHOES the password.
  globalThis.fetch = (() =>
    Promise.resolve(
      new Response(
        JSON.stringify({
          errors: [{ message: "bad credentials for password hunter2" }],
        }),
        { status: 401, statusText: "Unauthorized" },
      ),
    )) as typeof fetch;
  const { ctx } = sendCtx();
  try {
    let msg = "";
    try {
      await model.methods.listConnectedAccounts.execute(
        {} as never,
        ctx as never,
      );
    } catch (e) {
      msg = (e as Error).message;
    }
    assert(msg.length > 0, "expected the mint to fail-closed");
    assert(!msg.includes("hunter2"), "error leaked the send password");
    assert(
      !msg.includes("bad credentials"),
      "error leaked the raw server response body",
    );
    assert(/credential mint failed/.test(msg), "expected the generic label");
  } finally {
    globalThis.fetch = orig;
  }
});

Deno.test("sendEmail: ambiguous leadId (>1 opportunity) => refuse before send (TE-4)", async () => {
  const { calls, restore } = stubTwentyFetch((method, path, body) => {
    if (method === "GET" && path.startsWith("/rest/opportunities?")) {
      return {
        data: {
          opportunities: [
            { id: S_OPP },
            { id: "33333333-3333-4333-8333-333333333334" },
          ],
        },
      };
    }
    return sendRouter()(method, path, body);
  });
  const { ctx } = sendCtx();
  try {
    await assertRejects(
      () =>
        model.methods.sendEmail.execute(
          {
            leadId: "LEAD-DUP",
            to: "c@corp.example",
            subject: "x",
            body: "y",
            fromBrand: "brandhost.example",
            dryRun: false,
            confirm: true,
          } as never,
          ctx as never,
        ),
      Error,
      "Ambiguous leadId",
    );
    // Refused BEFORE minting a token / running the workflow.
    assert(
      !calls.some((c) =>
        c.method === "POST" && c.path === "/graphql" &&
        String((c.body as { query?: string })?.query ?? "").includes(
          "runWorkflowVersion",
        )
      ),
      "an ambiguous leadId must never reach the send",
    );
  } finally {
    restore();
  }
});

Deno.test("resolveActiveWorkflowVersionId refuses a duplicate workflow name (EMAIL-WF-1)", async () => {
  const { restore } = stubTwentyFetch(sendRouter({
    workflows: [
      { id: "wf1", name: "Send Email", lastPublishedVersionId: S_WVID },
      {
        id: "wf2",
        name: "Send Email",
        lastPublishedVersionId: "44444444-4444-4444-8444-444444444445",
      },
    ],
  }));
  try {
    await assertRejects(
      () =>
        resolveActiveWorkflowVersionId(
          { baseUrl: "https://crm.example.com", apiToken: "tok" } as never,
          "Send Email",
        ),
      Error,
      "Ambiguous Send-Email workflow name",
    );
  } finally {
    restore();
  }
});

Deno.test("sendEmail dedup: findPriorSend matches on the TITLE marker, not the leadId namespace (EMAIL-DEDUP-1/EMAIL-TEST-1.1)", async () => {
  const dedupKey = "explicit-key-1";
  const markerId = await sendDedupMarkerId(dedupKey);
  const wantTitle = encodeURIComponent(`sent:${markerId}`);
  let sawTitleQuery = false;
  const { calls, restore } = stubTwentyFetch((method, path, body) => {
    if (method === "GET" && path.startsWith("/rest/notes")) {
      // Honor the title[eq] filter: return the prior marker ONLY when the queried
      // title equals sent:<expected markerId>. A leadId-keyed lookup (the old
      // bug) would never match this, so the dedup hit proves the correct key.
      if (path.includes("title") && path.includes(wantTitle)) {
        sawTitleQuery = true;
        return {
          data: { notes: [{ id: "prior-marker", title: `sent:${markerId}` }] },
        };
      }
      return { data: { notes: [] } };
    }
    return sendRouter()(method, path, body);
  });
  const { writes, ctx } = sendCtx();
  try {
    await model.methods.sendEmail.execute(
      {
        personId: S_PERSON,
        to: "c@corp.example",
        subject: "x",
        body: "y",
        fromBrand: "brandhost.example",
        dedupKey,
        dryRun: false,
        confirm: true,
      } as never,
      ctx as never,
    );
    const snap = writes.find((w) => w.type === "sendRun");
    assertEquals(snap!.data.status, "skipped");
    assert(sawTitleQuery, "findPriorSend must query the title marker");
    // The dedup lookup must NOT touch the leadId Note namespace.
    assert(
      !calls.some((c) =>
        c.path.startsWith("/rest/notes") && c.path.includes("leadId")
      ),
      "dedup lookup must not use the leadId namespace",
    );
  } finally {
    restore();
  }
});

// ============================================================================
// TWENTY-COMPANY-UPSERT (upsertCompany / reconcileCompanies / exportCompanies)
// ============================================================================

// --- canonicalizers (pure) --------------------------------------------------
Deno.test("canonicalCompanyHost strips scheme AND leading www (ADV-1)", () => {
  assertEquals(canonicalCompanyHost("acme.com"), "acme.com");
  assertEquals(canonicalCompanyHost("https://www.acme.com"), "acme.com");
  assertEquals(
    canonicalCompanyHost("http://www.acme.com/path?q=1"),
    "acme.com",
  );
  assertEquals(canonicalCompanyHost("WWW.Acme.com"), "acme.com");
  assertEquals(canonicalCompanyHost("shop.acme.com"), "shop.acme.com");
  // acme.com and https://www.acme.com reduce to the SAME canonical host.
  assertEquals(
    canonicalCompanyHost("acme.com"),
    canonicalCompanyHost("https://www.acme.com"),
  );
  assertEquals(canonicalCompanyHost(""), null);
  assertEquals(canonicalCompanyHost(null), null);
});

Deno.test("canonicalCompanyName lowercases + collapses whitespace", () => {
  assertEquals(canonicalCompanyName("  Acme   Inc  "), "acme inc");
  assertEquals(canonicalCompanyName("ACME\tInc"), "acme inc");
  assertEquals(canonicalCompanyName(null), "");
});

// --- company test harness ---------------------------------------------------
// A stateful in-memory company/member server routed by method+path. The GET
// list endpoint returns ALL companies so the MODEL performs the real canonical
// client-side dedup. A handler may return {__status} to force a non-ok response.
function stubCompanyFetch(
  handler: (method: string, path: string, body: unknown) => unknown,
): {
  calls: Array<{ method: string; path: string; body: unknown }>;
  restore: () => void;
} {
  const calls: Array<{ method: string; path: string; body: unknown }> = [];
  const orig = globalThis.fetch;
  globalThis.fetch = ((url: string | URL, init?: RequestInit) => {
    const path = String(url).replace("https://crm.example.com", "");
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path, body });
    let payload: unknown;
    try {
      payload = handler(method, path, body) ?? {};
    } catch (e) {
      return Promise.resolve(
        {
          ok: false,
          status: 500,
          statusText: "ERR",
          text: () => Promise.resolve(String(e)),
        } as Response,
      );
    }
    if (payload && typeof payload === "object" && "__status" in payload) {
      const p = payload as { __status: number; __body?: unknown };
      return Promise.resolve(
        {
          ok: p.__status >= 200 && p.__status < 300,
          status: p.__status,
          statusText: "S",
          text: () => Promise.resolve(JSON.stringify(p.__body ?? {})),
        } as Response,
      );
    }
    return Promise.resolve(
      {
        ok: true,
        status: 200,
        statusText: "OK",
        text: () => Promise.resolve(JSON.stringify(payload)),
      } as Response,
    );
  }) as typeof fetch;
  return { calls, restore: () => (globalThis.fetch = orig) };
}

const COMPANY_META = {
  data: [{
    id: "obj-company",
    nameSingular: "company",
    namePlural: "companies",
    fields: [
      { name: "region", type: "TEXT" },
      { name: "annualRevenue", type: "CURRENCY" }, // composite -> rejected
      {
        name: "tier",
        type: "SELECT",
        options: [{ value: "STANDARD" }, { value: "PRIORITY" }],
      },
    ],
  }],
};

function makeCaptureCtx(): {
  ctx: unknown;
  writes: Array<{ type: string; name: string; data: Record<string, unknown> }>;
} {
  const writes: Array<
    { type: string; name: string; data: Record<string, unknown> }
  > = [];
  const ctx = {
    globalArgs: { baseUrl: "https://crm.example.com", apiToken: "tok" },
    logger: { debug() {}, info() {}, warning() {}, error() {} },
    writeResource: (
      type: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ type, name, data });
      return Promise.resolve({ name });
    },
  };
  return { ctx, writes };
}

// A company server backed by a mutable store (for create/update/idempotency).
function companyServer(opts: {
  companies?: Array<Record<string, unknown>>;
  members?: Array<Record<string, unknown>>;
  ilikeError?: boolean;
  metaError?: boolean;
  nameError?: boolean;
  pageScanError?: boolean;
} = {}) {
  const companies = opts.companies ?? [];
  const members = opts.members ?? [];
  let nextId = 1;
  const handler = (method: string, path: string, body: unknown) => {
    if (path.startsWith("/rest/metadata/objects")) {
      if (opts.metaError) return { __status: 500 };
      return COMPANY_META;
    }
    if (path.startsWith("/rest/workspaceMembers")) {
      return {
        data: { workspaceMembers: members },
        pageInfo: { hasNextPage: false },
      };
    }
    // Single company by id.
    if (method === "GET" && /^\/rest\/companies\/[^/?]+$/.test(path)) {
      const id = path.split("/").pop();
      const rec = companies.find((c) => c.id === id);
      return { data: { company: rec ?? {} } };
    }
    // List / filtered fetch.
    if (method === "GET" && path.startsWith("/rest/companies")) {
      if (opts.ilikeError && path.includes("[ilike]")) return { __status: 400 };
      // Hard error on the name-exact lookup (CR-ADV-2a).
      if (opts.nameError && path.includes("filter=name")) {
        return { __status: 500 };
      }
      // Hard error on the bounded domain page-scan fallback (CR-ADV-2b).
      if (opts.pageScanError && path.includes("order_by")) {
        return { __status: 500 };
      }
      return {
        data: { companies },
        pageInfo: { hasNextPage: false },
        totalCount: companies.length,
      };
    }
    if (method === "POST" && path === "/rest/companies") {
      const rec = { id: `c${nextId++}`, ...(body as Record<string, unknown>) };
      companies.push(rec);
      return { data: { createCompany: rec } };
    }
    if (method === "PATCH" && path.startsWith("/rest/companies/")) {
      const id = path.split("/").pop();
      const rec = companies.find((c) => c.id === id);
      if (rec) Object.assign(rec, body as Record<string, unknown>);
      return { data: { updateCompany: rec ?? {} } };
    }
    return {};
  };
  return { companies, members, handler };
}

// deno-lint-ignore no-explicit-any
const asAny = (v: unknown) => v as any;

Deno.test("upsertCompany: dryRun create plans without writing", async () => {
  const srv = companyServer();
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.upsertCompany.execute(
      asAny({
        name: "NewCo",
        domain: "newco.com",
        confirm: false,
        dryRun: true,
      }),
      asAny(ctx),
    );
    const snap = writes.find((w) => w.type === "companyUpsert")!.data;
    CompanyUpsertSchema.parse(snap);
    assertEquals(snap.action, "planned-create");
    assertEquals(snap.found, false);
    assertEquals(srv.companies.length, 0); // nothing written
    assert(!calls.some((c) => c.method === "POST"), "no POST in dryRun");
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: confirm create then idempotent re-run == noop (one record)", async () => {
  const srv = companyServer();
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.upsertCompany.execute(
      asAny({
        name: "NewCo",
        domain: "newco.com",
        confirm: true,
        dryRun: false,
      }),
      asAny(ctx),
    );
    assertEquals(writes.at(-1)!.data.action, "created");
    assertEquals(srv.companies.length, 1);
    const posts1 = calls.filter((c) => c.method === "POST").length;
    assertEquals(posts1, 1);
    // Re-run with identical inputs -> noop, no new write.
    await model.methods.upsertCompany.execute(
      asAny({
        name: "NewCo",
        domain: "newco.com",
        confirm: true,
        dryRun: false,
      }),
      asAny(ctx),
    );
    const last = writes.at(-1)!.data;
    assertEquals(last.action, "noop"); // ASSERT noop, not noop/updated
    assertEquals(srv.companies.length, 1); // still exactly one
    assertEquals(calls.filter((c) => c.method === "POST").length, 1);
    assert(!calls.some((c) => c.method === "PATCH"), "noop must not PATCH");
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: non-destructive update sets only the provided field", async () => {
  const srv = companyServer({
    companies: [{
      id: "11111111-1111-1111-1111-111111111111",
      name: "Acme",
      domainName: { primaryLinkUrl: "acme.com" },
    }],
  });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.upsertCompany.execute(
      asAny({
        name: "Acme",
        domain: "acme.com",
        legalName: "Acme, Inc.",
        confirm: true,
        dryRun: false,
      }),
      asAny(ctx),
    );
    const patch = calls.find((c) => c.method === "PATCH");
    assert(patch, "expected a PATCH");
    assertEquals(Object.keys(patch!.body as Record<string, unknown>), [
      "legalName",
    ]);
    assertEquals(writes.at(-1)!.data.action, "updated");
    assertEquals(writes.at(-1)!.data.fieldsSet, ["legalName"]);
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: domain canonicalization matches a stored www/full-URL (no create)", async () => {
  const srv = companyServer({
    companies: [{
      id: "c-acme",
      name: "Acme",
      domainName: { primaryLinkUrl: "https://www.acme.com" },
    }],
  });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.upsertCompany.execute(
      asAny({ name: "Acme", domain: "acme.com", confirm: true, dryRun: false }),
      asAny(ctx),
    );
    const snap = writes.at(-1)!.data;
    assertEquals(snap.action, "noop"); // matched the www-stored record
    assertEquals(snap.found, true);
    assertEquals(snap.matchedVia, "domain");
    assert(!calls.some((c) => c.method === "POST"), "must not create a dup");
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: create-guard — near-candidate yields planned-conflict, not create", async () => {
  const srv = companyServer({
    companies: [{
      id: "c-shop",
      name: "Shop Acme",
      domainName: { primaryLinkUrl: "https://shop.acme.com" },
    }],
  });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.upsertCompany.execute(
      asAny({
        name: "Acme Corp",
        domain: "acme.com",
        confirm: true,
        dryRun: false,
      }),
      asAny(ctx),
    );
    const snap = writes.at(-1)!.data;
    assertEquals(snap.action, "planned-conflict");
    assertEquals((snap.candidates as unknown[]).length, 1);
    assertEquals(
      (snap.candidates as Array<{ domain?: string }>)[0].domain,
      "shop.acme.com",
    );
    assert(
      !calls.some((c) => c.method === "POST"),
      "near-candidate must NOT create",
    );
  } finally {
    restore();
  }
});

// CR-ADV-3: the broad-domain re-narrow must use a HOST-BOUNDARY match, not a
// bare substring. Stored siblings `notacme.com` and `acme.com.au` both CONTAIN
// the substring "acme.com" but are neither equal, a true subdomain, nor a
// registrable parent of `acme.com`, so they must NOT be treated as candidates.
// Under the old bare-`.includes` logic both are kept as near-candidates and
// force a spurious planned-conflict; under `hostMatchesDomainScope` they are
// dropped and the upsert proceeds to create. (The create-guard test above uses
// `shop.acme.com`, a true subdomain that is a candidate under BOTH logics, so
// it does not exercise this boundary.)
Deno.test("upsertCompany: create-guard — substring siblings are NOT candidates (host-boundary), create proceeds", async () => {
  const srv = companyServer({
    companies: [
      {
        id: "c-notacme",
        name: "Not Acme",
        domainName: { primaryLinkUrl: "https://notacme.com" },
      },
      {
        id: "c-acme-au",
        name: "Acme Australia",
        domainName: { primaryLinkUrl: "https://acme.com.au" },
      },
    ],
  });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    // Phase 1: dryRun plans a CREATE (not a conflict) — siblings are out of scope.
    await model.methods.upsertCompany.execute(
      asAny({
        name: "Acme Corp",
        domain: "acme.com",
        confirm: false,
        dryRun: true,
      }),
      asAny(ctx),
    );
    const plan = writes.at(-1)!.data;
    CompanyUpsertSchema.parse(plan);
    assertEquals(plan.action, "planned-create");
    assertEquals(plan.found, false);
    assert(!calls.some((c) => c.method === "POST"), "dryRun must not POST");
    assertEquals(srv.companies.length, 2); // nothing written yet

    // Phase 2: confirm actually creates, with a real POST.
    await model.methods.upsertCompany.execute(
      asAny({
        name: "Acme Corp",
        domain: "acme.com",
        confirm: true,
        dryRun: false,
      }),
      asAny(ctx),
    );
    const done = writes.at(-1)!.data;
    assertEquals(done.action, "created");
    assertEquals(calls.filter((c) => c.method === "POST").length, 1);
    assertEquals(srv.companies.length, 3); // the new Acme Corp
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: broad fetch falls back to a page-scan when ilike errors", async () => {
  const srv = companyServer({
    companies: [{
      id: "c-acme",
      name: "Acme",
      domainName: { primaryLinkUrl: "https://www.acme.com" },
    }],
    ilikeError: true, // force the operator-unsupported fallback path
  });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.upsertCompany.execute(
      asAny({ name: "Acme", domain: "acme.com", confirm: false, dryRun: true }),
      asAny(ctx),
    );
    // Found via the page-scan fallback (not a false planned-create).
    assertEquals(writes.at(-1)!.data.found, true);
    assertEquals(writes.at(-1)!.data.action, "noop");
    assert(
      calls.some((c) => c.path.includes("[ilike]")),
      "ilike was attempted first",
    );
    assert(
      calls.some((c) =>
        c.path.includes("order_by") && !c.path.includes("[ilike]")
      ),
      "page-scan fallback ran",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: multi-match name -> conflict WITH candidate ids, no write", async () => {
  const srv = companyServer({
    companies: [
      { id: "c-a1", name: "Acme" },
      { id: "c-a2", name: "Acme" },
    ],
  });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.upsertCompany.execute(
      asAny({ matchBy: "name", name: "Acme", confirm: true, dryRun: false }),
      asAny(ctx),
    );
    const snap = writes.at(-1)!.data;
    assertEquals(snap.action, "conflict");
    const ids = (snap.candidates as Array<{ id: string }>).map((c) => c.id)
      .sort();
    assertEquals(ids, ["c-a1", "c-a2"]);
    assert(
      !calls.some((c) => c.method === "POST" || c.method === "PATCH"),
      "a conflict writes nothing",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: domain-hit with a materially different name is a conflict (no silent rename)", async () => {
  const srv = companyServer({
    companies: [{
      id: "c-acme",
      name: "Acme",
      domainName: { primaryLinkUrl: "acme.com" },
    }],
  });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.upsertCompany.execute(
      asAny({
        name: "Globex",
        domain: "acme.com",
        confirm: true,
        dryRun: false,
      }),
      asAny(ctx),
    );
    const snap = writes.at(-1)!.data;
    assertEquals(snap.action, "conflict");
    assertEquals((snap.candidates as Array<{ id: string }>)[0].id, "c-acme");
    assert(!calls.some((c) => c.method === "PATCH"), "no silent rename");
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: customFields reserved key is rejected at plan time", async () => {
  const srv = companyServer();
  const { restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertCompany.execute(
          asAny({
            name: "NewCo",
            domain: "newco.com",
            customFields: { legalName: "x" },
            confirm: false,
            dryRun: true,
          }),
          asAny(ctx),
        ),
      Error,
      "reserved",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: customFields unknown key is rejected (fail-closed) at plan time", async () => {
  const srv = companyServer();
  const { restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertCompany.execute(
          asAny({
            name: "NewCo",
            domain: "newco.com",
            customFields: { bogusField: "x" },
            confirm: false,
            dryRun: true,
          }),
          asAny(ctx),
        ),
      Error,
      "Unknown customFields key",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: customFields non-scalar (composite) key is rejected", async () => {
  const srv = companyServer();
  const { restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertCompany.execute(
          asAny({
            name: "NewCo",
            domain: "newco.com",
            customFields: { annualRevenue: 5 },
            confirm: false,
            dryRun: true,
          }),
          asAny(ctx),
        ),
      Error,
      "non-scalar",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: a valid customFields scalar flows into the create body", async () => {
  const srv = companyServer();
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.upsertCompany.execute(
      asAny({
        name: "NewCo",
        domain: "newco.com",
        customFields: { region: "US", tier: "PRIORITY" },
        confirm: true,
        dryRun: false,
      }),
      asAny(ctx),
    );
    const post = calls.find((c) => c.method === "POST")!.body as Record<
      string,
      unknown
    >;
    assertEquals(post.region, "US");
    assertEquals(post.tier, "PRIORITY");
    assert((writes.at(-1)!.data.fieldsSet as string[]).includes("region"));
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: unmatched explicit id ABORTS (never creates)", async () => {
  const srv = companyServer();
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertCompany.execute(
          asAny({
            id: "22222222-2222-2222-2222-222222222222",
            name: "Ghost",
            domain: "ghost.com",
            confirm: true,
            dryRun: false,
          }),
          asAny(ctx),
        ),
      Error,
      "id not found",
    );
    assert(
      !calls.some((c) => c.method === "POST"),
      "unmatched id must not create",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: name-only miss (no domain) aborts, no stable key", async () => {
  const srv = companyServer();
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertCompany.execute(
          asAny({ name: "Orphan", confirm: true, dryRun: false }),
          asAny(ctx),
        ),
      Error,
      "without a domain",
    );
    assert(!calls.some((c) => c.method === "POST"));
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: accountOwnerEmail resolves to an opaque id; email never in the snapshot", async () => {
  const srv = companyServer({
    members: [{ id: "member-xyz", userEmail: "owner@acme.com" }],
  });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.upsertCompany.execute(
      asAny({
        name: "NewCo",
        domain: "newco.com",
        accountOwnerEmail: "owner@acme.com",
        confirm: true,
        dryRun: false,
      }),
      asAny(ctx),
    );
    const post = calls.find((c) => c.method === "POST")!.body as Record<
      string,
      unknown
    >;
    assertEquals(post.accountOwnerId, "member-xyz");
    const snap = writes.at(-1)!.data;
    assertEquals(snap.accountOwnerResolved, true);
    assert(
      !JSON.stringify(snap).includes("owner@acme.com"),
      "the owner email must never enter the snapshot",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: unresolved accountOwnerEmail aborts (email not leaked)", async () => {
  const srv = companyServer({ members: [] });
  const { restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    const err = await assertRejects(
      () =>
        model.methods.upsertCompany.execute(
          asAny({
            name: "NewCo",
            domain: "newco.com",
            accountOwnerEmail: "nobody@acme.com",
            confirm: true,
            dryRun: false,
          }),
          asAny(ctx),
        ),
      Error,
      "did not resolve",
    );
    assert(
      !err.message.includes("nobody@acme.com"),
      "email scrubbed from error",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: a filter-unsafe/invalid accountOwnerEmail errors before any filter use", async () => {
  const srv = companyServer();
  const { restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertCompany.execute(
          asAny({
            name: "NewCo",
            domain: "newco.com",
            accountOwnerEmail: "a(b)@x.com",
            confirm: false,
            dryRun: true,
          }),
          asAny(ctx),
        ),
      Error,
      "accountOwnerEmail",
    );
  } finally {
    restore();
  }
});

// CR-ADV-1: an owner-set re-run is a TRUE noop (no idempotency churn), whether
// Twenty echoes the owner FK flat (accountOwnerId) or nested (accountOwner.id).
Deno.test("upsertCompany: accountOwnerEmail re-run is a noop with NO PATCH (flat owner FK)", async () => {
  const srv = companyServer({
    members: [{ id: "member-xyz", userEmail: "owner@acme.com" }],
  });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    const input = {
      name: "NewCo",
      domain: "newco.com",
      accountOwnerEmail: "owner@acme.com",
      confirm: true,
      dryRun: false,
    };
    await model.methods.upsertCompany.execute(asAny(input), asAny(ctx));
    assertEquals(writes.at(-1)!.data.action, "created");
    // The mock stores the POST body, so the owner FK is now flat on the record.
    const postCount = calls.filter((c) => c.method === "POST").length;
    assertEquals(postCount, 1);
    // Re-run identical inputs -> owner unchanged -> noop, NO PATCH.
    await model.methods.upsertCompany.execute(asAny(input), asAny(ctx));
    assertEquals(writes.at(-1)!.data.action, "noop");
    assertEquals(calls.filter((c) => c.method === "POST").length, 1);
    assert(
      !calls.some((c) => c.method === "PATCH"),
      "owner-noop must not PATCH",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: accountOwnerEmail noop when stored owner is NESTED (accountOwner.id)", async () => {
  // Twenty returns the owner nested, with NO flat accountOwnerId — buildCompanyWrite
  // must read accountOwner.id so the diff is a true noop (CR-ADV-1).
  const srv = companyServer({
    companies: [{
      id: "c-acme",
      name: "Acme",
      domainName: { primaryLinkUrl: "acme.com" },
      accountOwner: { id: "member-xyz" },
    }],
    members: [{ id: "member-xyz", userEmail: "owner@acme.com" }],
  });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.upsertCompany.execute(
      asAny({
        name: "Acme",
        domain: "acme.com",
        accountOwnerEmail: "owner@acme.com",
        confirm: true,
        dryRun: false,
      }),
      asAny(ctx),
    );
    const snap = writes.at(-1)!.data;
    assertEquals(snap.action, "noop");
    assertEquals(snap.matchedVia, "domain");
    assert(
      !calls.some((c) => c.method === "PATCH"),
      "nested-owner unchanged must not PATCH",
    );
  } finally {
    restore();
  }
});

// CR-ADV-2: a hard API error on a lookup ABORTS the run — it must NEVER fall
// through to a create. Covers both lookup seams.
Deno.test("upsertCompany: a hard error on the name-exact lookup ABORTS (no create)", async () => {
  const srv = companyServer({ nameError: true });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertCompany.execute(
          asAny({
            matchBy: "name",
            name: "Acme",
            confirm: true,
            dryRun: false,
          }),
          asAny(ctx),
        ),
      Error,
    );
    assert(
      !calls.some((c) => c.method === "POST"),
      "lookup error must not create",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: a hard error on the domain page-scan fallback ABORTS (no create)", async () => {
  // ilike errors -> page-scan fallback -> page-scan ALSO hard-errors.
  const srv = companyServer({ ilikeError: true, pageScanError: true });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertCompany.execute(
          asAny({
            name: "NewCo",
            domain: "newco.com",
            confirm: true,
            dryRun: false,
          }),
          asAny(ctx),
        ),
      Error,
    );
    assert(
      !calls.some((c) => c.method === "POST"),
      "scan error must not create",
    );
  } finally {
    restore();
  }
});

// CR-ADV-5: company-scoped customFields parity with the opportunity tests.
Deno.test("upsertCompany: customFields fail-closed when company metadata is unreadable", async () => {
  const srv = companyServer({ metaError: true });
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertCompany.execute(
          asAny({
            name: "NewCo",
            domain: "newco.com",
            customFields: { region: "US" },
            confirm: true,
            dryRun: false,
          }),
          asAny(ctx),
        ),
      Error,
      "fail-closed",
    );
    assert(
      !calls.some((c) => c.method === "POST"),
      "fail-closed must not create",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: customFields SELECT bad value is rejected", async () => {
  const srv = companyServer();
  const { calls, restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertCompany.execute(
          asAny({
            name: "NewCo",
            domain: "newco.com",
            customFields: { tier: "NOPE" },
            confirm: true,
            dryRun: false,
          }),
          asAny(ctx),
        ),
      Error,
      "Valid options",
    );
    assert(
      !calls.some((c) => c.method === "POST"),
      "bad SELECT must not create",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: reserved IDENTITY customFields keys are rejected", async () => {
  const cases: Array<Record<string, unknown>> = [
    { name: "Hijack" },
    { domainName: "evil.com" },
    { accountOwnerId: "00000000-0000-0000-0000-000000000000" },
  ];
  for (const customFields of cases) {
    const srv = companyServer();
    const { calls, restore } = stubCompanyFetch(srv.handler);
    const { ctx } = makeCaptureCtx();
    try {
      await assertRejects(
        () =>
          model.methods.upsertCompany.execute(
            asAny({
              name: "NewCo",
              domain: "newco.com",
              customFields,
              confirm: true,
              dryRun: false,
            }),
            asAny(ctx),
          ),
        Error,
        "reserved",
      );
      assert(
        !calls.some((c) => c.method === "POST"),
        "reserved key must not create",
      );
    } finally {
      restore();
    }
  }
});

// --- reconcileCompanies -----------------------------------------------------
Deno.test("reconcileCompanies: per-entry isolation — one bad row never aborts the batch", async () => {
  const srv = companyServer();
  const { restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.reconcileCompanies.execute(
      asAny({
        entries: [
          { name: "Good", domain: "good.com" },
          { name: "BadNoDomain" }, // name-only miss -> aborts THIS entry only
        ],
        source: "crm/companies.yaml",
        confirm: false,
        dryRun: true,
        maxEntries: 100,
      }),
      asAny(ctx),
    );
    const snap = CompanyReconcileSchema.parse(writes.at(-1)!.data);
    assertEquals(snap.processed, 2);
    const e0 = snap.entries[0];
    const e1 = snap.entries[1];
    assertEquals(e0.ok, true);
    assertEquals(e0.action, "planned-create");
    assertEquals(e1.ok, false);
    assert(
      e1.error && e1.error.length > 0,
      "bad entry carries a redacted error",
    );
    assertEquals(snap.converged, false);
  } finally {
    restore();
  }
});

Deno.test("reconcileCompanies: an over-cap batch is refused unless maxEntries is raised", async () => {
  const srv = companyServer();
  const { restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    await assertRejects(
      () =>
        model.methods.reconcileCompanies.execute(
          asAny({
            entries: [
              { name: "A", domain: "a.com" },
              { name: "B", domain: "b.com" },
            ],
            source: "x",
            confirm: false,
            dryRun: true,
            maxEntries: 1,
          }),
          asAny(ctx),
        ),
      Error,
      "over the cap",
    );
  } finally {
    restore();
  }
});

Deno.test("reconcileCompanies: a clean re-run converges to all-noop", async () => {
  const srv = companyServer({
    companies: [{
      id: "c-acme",
      name: "Acme",
      domainName: { primaryLinkUrl: "acme.com" },
    }],
  });
  const { restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.reconcileCompanies.execute(
      asAny({
        entries: [{ name: "Acme", domain: "acme.com" }],
        source: "crm/companies.yaml",
        confirm: true,
        dryRun: false,
        maxEntries: 100,
      }),
      asAny(ctx),
    );
    const snap = writes.at(-1)!.data;
    assertEquals(snap.converged, true);
    assertEquals((snap.counts as Record<string, number>).noop, 1);
  } finally {
    restore();
  }
});

// CR-ADV-4: an empty desired-state list is trivially converged (not false).
Deno.test("reconcileCompanies: an EMPTY batch is converged", async () => {
  const srv = companyServer();
  const { restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.reconcileCompanies.execute(
      asAny({
        entries: [],
        source: "crm/companies.yaml",
        confirm: false,
        dryRun: true,
        maxEntries: 100,
      }),
      asAny(ctx),
    );
    const snap = writes.at(-1)!.data;
    assertEquals(snap.processed, 0);
    assertEquals(snap.converged, true);
  } finally {
    restore();
  }
});

// CR-SEC-1: an OUTER failure (e.g. resource persist) rejects with a token-scrubbed
// error — SEC-8 parity with upsertCompany/exportCompanies.
Deno.test("reconcileCompanies: an outer failure rejects with a redacted error", async () => {
  const srv = companyServer();
  const { restore } = stubCompanyFetch(srv.handler);
  const SECRET = "sk-reconcile-secret-token";
  const ctx = {
    globalArgs: { baseUrl: "https://crm.example.com", apiToken: SECRET },
    logger: { debug() {}, info() {}, warning() {}, error() {} },
    writeResource: () => {
      throw new Error(`persist failed with ${SECRET}`);
    },
  };
  try {
    const err = await assertRejects(
      () =>
        model.methods.reconcileCompanies.execute(
          asAny({
            entries: [{ name: "Acme", domain: "acme.com" }],
            source: "x",
            confirm: false,
            dryRun: true,
            maxEntries: 100,
          }),
          asAny(ctx),
        ),
      Error,
    );
    assert(
      !err.message.includes(SECRET),
      "the apiToken must be scrubbed from the outer error",
    );
  } finally {
    restore();
  }
});

// --- exportCompanies --------------------------------------------------------
Deno.test("exportCompanies: emits companyList with ids + legalName, scrubs PII", async () => {
  const srv = companyServer({
    companies: [
      {
        id: "c-1",
        name: "Acme",
        domainName: { primaryLinkUrl: "https://www.acme.com" },
        legalName: "Acme, Inc.",
        // PII / relations that MUST be scrubbed:
        accountOwner: { userEmail: "owner@acme.com" },
        people: [{ emails: { primaryEmail: "jane@acme.com" } }],
      },
      { id: "c-2", name: "Globex" },
    ],
  });
  const { restore } = stubCompanyFetch(srv.handler);
  const { ctx, writes } = makeCaptureCtx();
  try {
    await model.methods.exportCompanies.execute(
      asAny({ maxCompanies: 1000 }),
      asAny(ctx),
    );
    const w = writes.find((w) => w.type === "companyList")!;
    assertEquals(w.name, "companies-export");
    const items = w.data.items as Array<Record<string, unknown>>;
    assertEquals(items.length, 2);
    assertEquals(items[0].id, "c-1");
    assertEquals(items[0].domain, "acme.com"); // canonical host
    assertEquals(items[0].legalName, "Acme, Inc.");
    // Only the four whitelisted keys — nothing person/owner-bearing.
    assertEquals(Object.keys(items[0]).sort(), [
      "domain",
      "id",
      "legalName",
      "name",
    ]);
    assert(
      !JSON.stringify(w.data).includes("owner@acme.com"),
      "account-owner email scrubbed",
    );
    assert(
      !JSON.stringify(w.data).includes("jane@acme.com"),
      "person email scrubbed",
    );
  } finally {
    restore();
  }
});

Deno.test("upsertCompany: refuses a live write without confirm", async () => {
  const srv = companyServer();
  const { restore } = stubCompanyFetch(srv.handler);
  const { ctx } = makeCaptureCtx();
  try {
    await assertRejects(
      () =>
        model.methods.upsertCompany.execute(
          asAny({
            name: "NewCo",
            domain: "newco.com",
            confirm: false,
            dryRun: false,
          }),
          asAny(ctx),
        ),
      Error,
      "confirm:true",
    );
  } finally {
    restore();
  }
});
