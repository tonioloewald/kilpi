# CLAUDE.md

kilpi — a very small HTML sanitizer for rich-text paste paths. Finnish for *shield*.

## Commands

```bash
bun install
bun test              # unit tests (happy-dom)
bun run test:browser  # DOMPurify's 223-fixture corpus in real Chromium — THE gate
bun run build         # types + dist/index.js
bun run lint          # tsc --noEmit
```

## The one thing to understand before changing anything

**This is a denylist for elements and attributes, and an allowlist for URL
schemes.** That is deliberate, it is why the library is under 1 kB, and it is why
unknown elements survive — which is required by the plugin architecture of its
first consumer. It is also the wrong default for general-purpose sanitization.
`SECURITY.md` is the contract; if you change the trade, change that document
first.

## Do not weaken these without reading why

- `forSchemeTest` is normalization for the SCHEME TEST ONLY — the attribute value
  is never rewritten. It strips **every C0 control anywhere** and **leading and
  trailing spaces**, and deliberately **keeps interior spaces**. Both directions
  are load-bearing and pull against each other:
  - `<a href="&#1;java&#3;script:">` must be stripped (Blink removes low-ASCII
    before parsing, so that IS `javascript:`)
  - `<a href="Chapter 3: Intro.html">` must be KEPT (stripping spaces made it
    look like a scheme and deleted a legitimate link)
  There is exactly ONE copy of this logic, because when there were two, a fix
  reached only one of them.
- `FORBIDDEN_TAGS` is matched against **`localName`**, never `tagName`.
  `tagName` is upper-cased only in the HTML namespace, so an upper-case check
  silently misses all of SVG and MathML — `<svg><script>` survived that way.
- `localName` and `attributes` are read through **the prototype's own getters**.
  A form's named controls shadow its properties, so
  `<form><input name="localName">` otherwise turns a string into an element and
  throws out of the middle of a paste.
- Every attribute value is scanned for an executing scheme **regardless of the
  attribute's name**. The enumerated URL-attribute list has already been wrong
  once (`ping`, `srcset`, `poster`), so it is a backstop, not the defence.

## Testing

`test/dompurify-fixtures.mjs` is vendored from DOMPurify and is the real gate —
it is wired into `prepublishOnly` and exits non-zero on any executable residue.
It is scored on residue rather than string equality, because DOMPurify's expected
outputs encode its allowlist policy and matching them would measure agreement
rather than safety.

That corpus caught a bypass three adversarial review rounds and 33 hand-written
vectors had all missed. **Do not trust a hand-written vector list to be the
gate.** Refresh the fixtures from upstream periodically.
