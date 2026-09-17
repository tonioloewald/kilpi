# kilpi

A very small HTML sanitizer for rich-text paste paths. **Zero dependencies**,
**0.8 kB gzipped** once your bundler has minified it (1.0 kB as
published, unminified), and it passes DOMPurify's published 223-fixture corpus
with zero executable residue.

`kilpi` is Finnish for *shield*. The npm package is **`tosijs-kilpi`** — npm's
name-similarity check rejects the bare word.

```sh
npm install tosijs-kilpi
```

It has no dependency on tosijs or any other package — the prefix is ownership,
not coupling. Use it anywhere.

```js
import { sanitizeInPlace } from 'tosijs-kilpi'

const temp = document.createElement('div')
temp.innerHTML = untrustedHtml     // still detached
sanitizeInPlace(temp)              // now safe to insert
while (temp.firstChild) target.before(temp.firstChild)
```

## Why it exists

If you have replaced `contentEditable`, you have also replaced the sanitization
the browser was quietly doing on your behalf. Pasted and dropped HTML goes
straight into a live document — and from there into whatever you persist, which
means a payload is stored once and re-served to every later reader.

## Read SECURITY.md before adopting it

kilpi is a **denylist** for elements and attributes, and an **allowlist** for URL
schemes. That is a deliberate trade:

- **unknown elements survive** — a plugin architecture's custom elements round
  trip intact, which is why this exists at all
- **an element that becomes dangerous in a future browser, and that this library
  has never heard of, passes through**

Those are the same property. If the second matters more to you than the first,
use [DOMPurify](https://github.com/cure53/DOMPurify) — it is excellent, and kilpi
does not try to replace it.

[The full threat model is in SECURITY.md.](./SECURITY.md) It is short, and it is
the document that decides whether this library is right for you.

## API

### `sanitizeInPlace(root: Element | DocumentFragment): void`

Strips executable content from a subtree, in place. Run it while the nodes are
still **detached**, before anything enters the document.

It takes an element and mutates it rather than taking and returning an HTML
string, on purpose: a string signature forces a serialize-and-reparse round trip,
and that round trip is where mutation XSS lives.

### `isSafeNavigationUrl(url: string): boolean`

Whether a URL is safe to navigate to or write into an `href`. Stricter than the
rule applied to `src`: a link may never carry `data:`, an image may.

```js
isSafeNavigationUrl('https://example.com')        // true
isSafeNavigationUrl('/Chapter 3: Intro.html')     // true
isSafeNavigationUrl('javascript:alert(1)')        // false
isSafeNavigationUrl('java\tscript:alert(1)')      // false
```

## Measured

Against DOMPurify 3.4.15, in Chromium:

| | kilpi | DOMPurify |
| --- | --- | --- |
| size (gzip, minified) | **0.8 kB** | 10.9 kB |
| dependencies | **0** | 0 |
| sanitize a 28 kB document | **1.08 ms** | 3.38 ms |
| DOMPurify's 223 fixtures | **223/223 clean** | 223/223 clean |

Size and speed are the honest wins. On safety the correct claim is *parity on
that corpus* — not that kilpi is safer, and not that it is a drop-in replacement,
because the denylist/allowlist difference is real and is the whole of SECURITY.md.

## Credits

The verification corpus in `test/dompurify-fixtures.mjs` is vendored verbatim
from [DOMPurify](https://github.com/cure53/DOMPurify) (© 2015 Mario Heiderich,
MPL-2.0 OR Apache-2.0), used here under Apache-2.0. It is a test fixture and is
not part of the published package. kilpi exists alongside DOMPurify, not in
competition with it — see [SECURITY.md](./SECURITY.md) for which of the two you
should be using.

## License

Apache-2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
