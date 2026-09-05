/**
 * Unit tests for @shrug/twenty. Everything security-critical in the lead sink is
 * a pure function — email/domain validation (the anti filter-injection gate),
 * text sanitization (anti record-poisoning), the consumer-domain blocklist, the
 * name split, FIFO batch selection, and the whole per-lead plan — so it is all
 * exercised here without a live Twenty. The one impure guard tested is
 * push_leads' confirm-gate, which throws before any I/O.
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import {
  buildFilterPath,
  DEFAULT_EMAIL_DOMAIN_BLOCKLIST,
  domainOfEmail,
  escapeMarkdown,
  isBlockedDomain,
  isFilterSafe,
  model,
  normalizeCloseDate,
  normalizePhone,
  planLead,
  redactError,
  sanitizeText,
  selectBatch,
  splitName,
  toCurrency,
  validateDomain,
  validateEmail,
  validateLeadId,
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
