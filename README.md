<img src="https://raw.githubusercontent.com/tonioloewald/kilpi/main/static/kilpi.png" alt="" width="96" align="right">

# kilpi

A very small HTML sanitizer for rich-text paste paths. **Zero dependencies**,
**0.8 kB gzipped** once your bundler has minified it (1.0 kB as published), and
it passes [DOMPurify](https://github.com/cure53/DOMPurify)'s published
223-fixture corpus with zero executable residue.

`kilpi` is Finnish for *shield*. The npm package is **`tosijs-kilpi`** — npm's
name-similarity check rejects the bare word.

```sh
npm install tosijs-kilpi
```

It has no dependency on tosijs or any other package — the prefix is ownership,
not coupling. Use it anywhere.

## Should you use DOMPurify instead?

**Probably, and we mean that.** [DOMPurify](https://github.com/cure53/DOMPurify)
is the reference implementation of this problem: a decade of adversarial
attention, a bug bounty, a security mailing list, a published attack-class
history, and an **allowlist** design that is safe against elements nobody has
heard of yet. kilpi is none of those things.

This library exists because of one specific requirement, not because DOMPurify
is deficient:

> **Unknown custom elements must survive sanitization intact.** An editor with a
> plugin architecture stores plugin markup in the document. If a sanitizer
> unwraps or drops elements it does not recognise, pasting a document destroys
> the plugins in it.

DOMPurify unwraps unknown custom elements by default — measured, not assumed —
and will preserve them once you configure `CUSTOM_ELEMENT_HANDLING`. That works.
It was simply not the default we needed, in a hot path where we also cared about
size.

So the honest comparison, measured against DOMPurify 3.4.15 in Chromium:

| | kilpi | DOMPurify |
| --- | --- | --- |
| size (gzip, minified) | **0.8 kB** | 10.9 kB |
| dependencies | 0 | 0 |
| sanitize a 28 kB document | **1.08 ms** | 3.38 ms |
| DOMPurify's 223 fixtures | 223/223 clean | 223/223 clean |
| unknown custom elements | **survive by default** | unwrapped unless configured |
| elements it has never heard of | **pass through** | dropped |
| configuration, hooks, Trusted Types | none | extensive |
| adversarial history | months | a decade, with a bounty |

Read that table in both directions. Size and speed are ours. **The last three
rows are theirs, and the "elements it has never heard of" row is the one that
should decide it for most people.**

### Why we did not just use it

Four reasons, in the order they actually mattered:

1. **The custom-element default**, above. This is the only reason that is really
   about DOMPurify at all.
2. **Size in a hot path.** The component this was written for is ~23 kB gzipped;
   adding 10.9 kB to gain behaviour we would then configure away was a poor
   trade *for that component*. It is not a general argument — 10.9 kB is
   cheap for most applications.
3. **It already existed.** The code was written to close an unsanitized
   paste/drop path in an editor, hardened across three adversarial review rounds,
   and only then extracted. We did not set out to write a sanitizer and pick this
   over DOMPurify; we wrote a filter, and it turned out to be worth sharing.
4. **A denylist is defensible *here*.** For untrusted paste into a rich-text
   document, the set of dangerous things is small and well understood, and the
   cost of dropping unknown-but-legitimate markup is high. Those weights invert
   for general-purpose sanitization.

### What we owe them

The verification corpus in this repository is **DOMPurify's**, vendored verbatim.
It is not decoration: it caught a bypass — C0 control characters inside a scheme,
which Blink strips before parsing — that **three adversarial review rounds and 33
hand-written vectors had all missed**. Our own imagination was demonstrably not
sufficient, and theirs was. If you are weighing the two libraries, weigh that.

## What does it do?

Strips executable content from untrusted HTML before it enters your document:
inline event handlers, executing and re-targeting elements, and URLs whose scheme
can run code — in **any namespace**, so `<svg><script>` and `<svg><style>` are
caught too.

```js
import { sanitizeInPlace } from 'tosijs-kilpi'

const temp = document.createElement('div')
temp.innerHTML = untrustedHtml     // still detached
sanitizeInPlace(temp)              // now safe to insert
while (temp.firstChild) target.before(temp.firstChild)
```

[SECURITY.md](./SECURITY.md) is the authoritative policy — what is removed, what
is deliberately not, and the threat model. It is short.

## Is there any foot-gun potential?

Yes, three.

1. **Sanitize, then do not touch it.** If you modify markup *after* sanitizing —
   or hand it to another library that does — you can void the sanitization
   entirely. This is the same warning DOMPurify gives, for the same reason.
2. **Sanitize while detached.** `sanitizeInPlace` mutates the subtree you give
   it. Run it before the nodes enter the document, never after: a
   `<svg><style>` applies document-wide the *moment* it is inserted, so
   sanitizing afterwards is already too late.
3. **It does not sanitize what you supply yourself.** It is for untrusted input.
   Content your own application authors is your trust boundary, not its.

The API takes an **element and mutates it**, never an HTML string, on purpose: a
string signature forces a serialize-and-reparse round trip, and that round trip
is where mutation XSS lives.

## API

### `sanitizeInPlace(root: Element | DocumentFragment): void`

Strips executable content from a subtree, in place.

### `isSafeNavigationUrl(url: string): boolean`

Whether a URL is safe to navigate to or write into an `href`. Stricter than the
rule applied to `src`: a link may never carry `data:`, an image may.

```js
isSafeNavigationUrl('https://example.com')        // true
isSafeNavigationUrl('/Chapter 3: Intro.html')     // true
isSafeNavigationUrl('javascript:alert(1)')        // false
isSafeNavigationUrl('java\tscript:alert(1)')      // false
```

## What is supported?

HTML, SVG and MathML, including foreign content — the namespace cases are where
hand-rolled sanitizers usually leak, and they are covered by tests.

**Baseline: ES2020.** Not the DOM APIs — those are ancient (`TreeWalker` and
`NodeFilter` are IE9-era, and the `Element.prototype` getter reads fall back to
plain property access). It is the *syntax*: the source uses optional chaining,
and `?.` appears at module top level.

| | minimum |
| --- | --- |
| Chrome / Edge | 80 (Feb 2020) |
| Firefox | 74 |
| Safari | 13.1 (Mar 2020) |

Below that — any Internet Explorer, legacy EdgeHTML, Safari ≤ 13.0 — kilpi does
not degrade, it **fails to parse**. The module throws `SyntaxError` and the
import fails, so your application breaks rather than silently losing its
sanitizer.

This is the one place we think our behaviour is better, so it is worth being
exact about why — and about what we did not do.

DOMPurify, on an engine it cannot help, sets `isSupported = false` and
`sanitize()` **returns your input unchanged**. That is a security control
failing OPEN: the call returns a string, the call site cannot tell anything went
wrong, and the default outcome for anyone who has not read about the flag is
unsanitized HTML in their document. A safeguard you have to know about and
remember to check is a footnote, not a safeguard.

kilpi cannot fail that way. Nothing runs, so nothing is silently let through,
and you find out on the first load in dev, in CI, or from the user.

**But we did not engineer that.** It falls out of using `?.` in the source, and
we are not going to claim it as a designed safety property after the fact. The
honest statement is that the failure modes differ and ours is the louder one.

It is tempting to call that an availability-versus-security trade and leave it
even. Put it this way instead:

> One car has a collision avoidance system, but fitted to the wrong car, the car
> will not start. The other car's system lets you start and drive — without
> collision avoidance.
>
> **Why did you fit a collision avoidance system?**

You fitted it because you would rather not crash. A system that quietly lets you
drive without it has defeated the only reason it is there — and it is worse than
fitting nothing, because now you believe you are protected. If you are content to
drive unprotected, do not fit one. Do not fit a sanitizer either.

The wrong car, in this analogy, is the old one: the one without airbags, crumple
zones or ABS. That is where the system switches itself off.

Precisely, the two failures are not the same size:

|  | breaking (ours) | failing open (theirs) |
| --- | --- | --- |
| who is affected | only users on that engine | **every later reader, on every browser** |
| when you find out | immediately | often from someone else |
| does fixing it fix it | yes, retroactively | no — the payload is already stored |

A sanitizer's failure is not confined to the session that hit it. The payload
gets *written down*, so it reaches people on perfectly modern browsers
afterwards, and repairing the sanitizer does not clean the corpus. The engines
where DOMPurify declines are also old ones — missing Trusted Types, modern CSP,
site isolation — so it stops sanitizing precisely where the other layers are
thinnest, and that correlation is causal, not coincidental.

DOMPurify's choice is still coherent for a library that must run everywhere and
hand the decision to the host. But the decision only gets made if the host knows
to make it. If you need to *support* those engines rather than fail noisily on
them, use DOMPurify — and check `isSupported`.

**No configuration, no hooks, no Trusted Types.** There is nothing to tune —
which is a feature at this size and a hard limit if you need any of it.

## What if I find a security bug?

Please [open an issue](https://github.com/tonioloewald/kilpi/issues). If you
would rather not disclose publicly first, open one with no details and we will
find a private channel.

There is no bug bounty. If you are looking for a sanitizer with a funded
disclosure programme, that is another point for DOMPurify.

## How it is verified

DOMPurify's 223 published fixtures run in real Chromium on every publish
(`bun run test:browser`, wired into `prepublishOnly`), scored on **executable
residue** rather than string equality — their expected outputs encode an
allowlist policy kilpi does not share, so matching them would measure agreement
rather than safety.

Current result: **223/223 with zero executable residue.**

## Credits

**[DOMPurify](https://github.com/cure53/DOMPurify)** by Mario Heiderich and
cure53 — the prior art for this entire problem space, the source of the
verification corpus, and the library you should reach for if the trade-offs above
do not describe your situation.

`test/dompurify-fixtures.mjs` is vendored verbatim from DOMPurify
(© 2015 Mario Heiderich, MPL-2.0 OR Apache-2.0), used here under Apache-2.0. It
is a test fixture and is not part of the published package.

## License

Apache-2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
