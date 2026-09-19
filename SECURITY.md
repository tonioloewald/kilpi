# Threat model

Read this before adopting kilpi. Its design makes a trade that is right for some
uses and wrong for others, and the name — *shield* — could oversell it.

## What it is for

An editor that accepts **pasted and dropped HTML** and inserts it into a live
document. If you have replaced `contentEditable`, you have also replaced the
sanitization the browser was quietly doing for you; that is the gap this fills.

## The trade

kilpi is a **denylist** for elements and attributes, and an **allowlist** for URL
schemes.

That is why it is small, and why **unknown elements survive**. Those two
properties are the same property.

| | consequence |
| --- | --- |
| good | a plugin architecture's custom elements round-trip intact, rather than being unwrapped or dropped |
| good | under 1 kB gzipped, no dependencies |
| **bad** | an element or attribute that becomes dangerous in a future browser, and that this library has never heard of, **passes through** |

An allowlist sanitizer inverts that: it drops anything it does not recognise, so
it is safe against the unknown and hostile to the unknown-but-legitimate.

**If protection from not-yet-known elements matters more to you than preserving
unknown markup, use [DOMPurify](https://github.com/cure53/DOMPurify).** It is
excellent, actively maintained by people who do this full time, and kilpi does
not try to replace it.

The one mitigation against the denylist's weak spot: **every attribute value is
scanned for an executing scheme regardless of the attribute's name**, so a URL
attribute this library has never heard of still cannot carry `javascript:`. That
is a capability check rather than a name check, and it exists because the
enumerated attribute list has already been wrong once (`ping`, `srcset` and
`poster` were all missing).

## What it removes

- every `on*` attribute, however spelled
- `script`, `iframe`, `object`, `embed`, `link`, `meta`, `base`, `style`,
  `form`, `noscript`, `template`, and the SVG animation elements — matched on
  `localName`, so **foreign content is covered**: `<svg><script>` and
  `<svg><style>` are caught, which an upper-cased `tagName` check silently misses
- `ping` (dangerous by capability: its URL is legitimate, and it reports the click)
- URL attributes whose scheme is not `http(s)`, `mailto`, `tel`, or relative;
  `data:` is permitted only for raster images, never for a link and never for
  `image/svg+xml`
- any attribute, named or not, whose value carries an executing scheme

## What it does NOT do

- **It does not sanitize content you supply yourself.** It is for untrusted input.
- **It does not remove `is=`.** `removeAttribute('is')` is a no-op in Chrome once
  the attribute has been parsed — verified directly. DOMPurify does not remove it
  either. Neutralizing it requires replacing the element rather than the
  attribute.
- **No Trusted Types, no hooks, no configuration.** If you need those, you need
  DOMPurify.
- **ES2020 or nothing.** Chrome/Edge 80, Firefox 74, Safari 13.1. Below that the
  module fails to PARSE — it does not degrade. Your app breaks; it does not
  quietly stop sanitizing.
  That is the safer failure for a security control, and it is worth saying that
  we got it for free from using `?.` rather than designing it. DOMPurify makes
  the opposite trade deliberately: `sanitize()` returns your input UNCHANGED and
  sets `isSupported = false` — a control failing open, recoverable only by a
  reader who knows the flag exists.
- It takes an **element and mutates it**, never an HTML string, on purpose: a
  string signature forces a serialize-and-reparse round trip, and that round trip
  is where mutation XSS lives.

## How it is verified

DOMPurify's published fixture corpus (223 payloads) is vendored into
`test/dompurify-fixtures.mjs` and run in a real Chromium on every publish
(`bun run test:browser`, wired into `prepublishOnly`). It is scored on
**executable residue**, not string equality — DOMPurify's expected outputs encode
its own policy, so matching them would measure agreement rather than safety.

Current result: **223/223 with zero executable residue.**

That corpus is not decoration. It caught a bypass — C0 control characters inside
a scheme, which Blink strips before parsing — that three adversarial review
passes and 33 hand-written vectors had all missed. Any change to the URL
normalizer must keep both of these passing, because they pull in opposite
directions:

```
<a href="&#1;java&#3;script:alert(1)">   must be stripped
<a href="Chapter 3: Intro.html">         must be KEPT
```

## Reporting a vulnerability

Open an issue at https://github.com/tonioloewald/kilpi/issues. If you would
rather not disclose publicly first, say so in an issue with no details and we
will find a private channel.
