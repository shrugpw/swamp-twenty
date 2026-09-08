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
} from "jsr:@std/assert@1";
import {
  amountFromMicros,
  buildFilterPath,
  canonicalJson,
  DEFAULT_EMAIL_DOMAIN_BLOCKLIST,
  domainOfEmail,
  escapeMarkdown,
  isBlockedDomain,
  isFilterSafe,
  listFiltered,
  listInstanceHash,
  mapCompanyView,
  mapNoteView,
  mapOppView,
  mapPersonView,
  model,
  normalizeCloseDate,
  normalizeDomainHost,
  normalizePhone,
  planLead,
  redactError,
  sanitizeText,
  selectBatch,
  splitName,
  titleCaseToken,
  toCurrency,
  validateDomain,
  validateEmail,
  validateLeadId,
  validateUuid,
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
  geo: "Bedford, MA",
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
  assert(isFilterSafe("Jackson Family Enterprises"));
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
          leadId: "jfw-aap-2.7-2026",
          name: "Test",
          currencyCode: "USD",
          closeDate: "",
          companyName: "",
          companyDomain: "",
          pointOfContactName: "",
          pointOfContactEmail: "",
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
        leadId: "jfw-aap-2.7-2026",
        name: "JFW",
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
  assertAlmostEquals(amountFromMicros(43_478_260_000), 43478.26, 1e-6);
  // Round-trip.
  assertEquals(amountFromMicros(toCurrency(19.99, "USD").amountMicros), 19.99);
});

Deno.test("mapOppView extracts the compact view incl. micros->units", () => {
  const v = mapOppView({
    id: "opp1",
    leadId: "L1",
    name: "AAP 2.7",
    stage: "PROPOSAL",
    amount: { amountMicros: 43_478_260_000, currencyCode: "USD" },
    closeDate: "2026-12-31T00:00:00.000Z",
    companyId: "co1",
    pointOfContactId: "poc1",
  });
  assertEquals(v.id, "opp1");
  assertEquals(v.stage, "PROPOSAL");
  assertAlmostEquals(v.amount!, 43478.26, 1e-6);
  assertEquals(v.currencyCode, "USD");
  // A record with no amount composite omits amount/currencyCode.
  const bare = mapOppView({ id: "opp2", name: "x", stage: "NEW" });
  assertEquals("amount" in bare, false);
  assertEquals("currencyCode" in bare, false);
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
              name: "Jackson Family Enterprises",
              domainName: { primaryLinkUrl: "jacksonfamilywines.com" },
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
      { domain: "jacksonfamilywines.com" } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.found, true);
    assertEquals(writes[0].data.id, "co1");
    assertEquals(writes[0].data.name, "Jackson Family Enterprises");
    assertEquals(writes[0].data.domain, "jacksonfamilywines.com");
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
      { name: "Jackson Family Enterprises" } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.found, false);
  } finally {
    restore();
  }
});

const JFW_OPP = {
  id: "opp-aap",
  leadId: "jfw-aap-2.7-2026",
  name: "AAP 2.7",
  stage: "PROPOSAL",
  amount: { amountMicros: 43_478_260_000, currencyCode: "USD" },
  closeDate: "2026-12-31T00:00:00.000Z",
  companyId: "co1",
  pointOfContactId: "poc1",
};

Deno.test("getOpportunity by leadId: PROPOSAL + amount 43478.26", async () => {
  const { restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return { body: { data: { opportunities: [JFW_OPP] } } };
    }
    return {};
  });
  const { writes, ctx } = readCtx();
  try {
    await model.methods.getOpportunity.execute(
      { leadId: "jfw-aap-2.7-2026" } as never,
      ctx as never,
    );
    const d = writes[0].data;
    assertEquals(d.found, true);
    assertEquals(d.stage, "PROPOSAL");
    assertAlmostEquals(d.amount as number, 43478.26, 1e-6);
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
        return { body: { data: { opportunity: JFW_OPP } } };
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

Deno.test("listOpportunities: AND-composes filters and returns both JFW opps", async () => {
  const cid = "33333333-3333-3333-3333-333333333333";
  const { calls, restore } = stubFetchStatus((method, path) => {
    if (method === "GET" && path.startsWith("/rest/opportunities")) {
      return {
        body: {
          data: {
            opportunities: [
              JFW_OPP,
              { id: "opp-sow", name: "SOW#26", stage: "CUSTOMER" },
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

Deno.test("listOpportunities: caps at limit and flags truncated", async () => {
  const { restore } = stubFetchStatus(() => ({
    body: {
      data: {
        opportunities: [
          { id: "x1", name: "a", stage: "NEW" },
          { id: "x2", name: "b", stage: "NEW" },
          { id: "x3", name: "c", stage: "NEW" },
        ],
      },
      pageInfo: { hasNextPage: false },
    },
  }));
  const { writes, ctx } = readCtx();
  try {
    await model.methods.listOpportunities.execute(
      { limit: 2 } as never,
      ctx as never,
    );
    assertEquals(writes[0].data.count, 2);
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

Deno.test("listFiltered cap-reached => truncated + hasMore + nextCursor + incomplete", async () => {
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
    // Resume from the cursor of the page holding our last kept item (no gap).
    assertEquals(p.nextCursor, "c0");
    assertEquals(p.stopReason, "cap-reached");
    assertEquals(p.incomplete, true);
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

Deno.test("listFiltered max-pages backstop => incomplete + max-pages", async () => {
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
    assertEquals(p.incomplete, true);
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
      { leadId: "L1", includeEmergency: false, limit: 60 } as never,
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

Deno.test("redactError scrubs filter= and starting_after= query values (SR-2)", () => {
  const s = redactError(
    "Twenty GET /rest/people?filter=leadId[eq]:topsecret&starting_after=CURSOR123 failed: 400 Bad Request",
  );
  assert(s.includes("filter=[redacted]"), s);
  assert(s.includes("starting_after=[redacted]"), s);
  assert(!s.includes("topsecret"), s);
  assert(!s.includes("CURSOR123"), s);
});
