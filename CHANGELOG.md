# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Every release that closes a bypass carries a `### Security` section naming what
was closed and whether an earlier version is affected.** That is deliberate and
load-bearing: a consumer's update decision is made from this file, so anything a
reader has to infer from prose is something they will miss. Scan for `### Security`
and you have the whole disclosure history.

## [Unreleased]

## [1.0.0]

### Changed

Same code as 0.1.0. Versioned 1.0.0 so that **security fixes actually reach
consumers**.

`^0.1.0` resolves to `>=0.1.0 <0.2.0`: under ordinary 0.x convention the next
behaviour-changing fix ships as 0.2.0, and every installed dependant would stay
on 0.1.x indefinitely — `npm update` would not cross the minor. For a package
whose entire job is to be the consumer's XSS defence, a version range that
blocks propagation is a defect in itself.

The API is two functions and is not expected to change. 0.x was signalling an
instability that is not there, at the cost of the one property this package most
needs.


## [0.1.0]

First release. Extracted from
[tosijs-styled-editor](https://github.com/tonioloewald/tosijs-editor), where it
was written to close an unsanitized paste/drop path and then hardened across
three adversarial review rounds plus DOMPurify's published corpus.

### Security

No earlier version of this package exists, so **nothing below affects a released
version of kilpi** — these were all closed before 0.1.0 shipped. They are listed
because each is a regression test now, and because the shapes recur:

- **control characters inside a scheme** — `.trim()` removes only leading and
  trailing whitespace; the URL parser removes tab/LF/CR anywhere, and Blink
  removes the whole low-ASCII range, before matching a scheme. Checking a
  different string from the one that gets parsed is the shape of a sanitizer
  bypass, and it appeared twice: once as `java<TAB>script:`, and again as
  `<U+0001>java<U+0003>script:` after the first fix was narrowed too far to
  avoid destroying `Chapter 3: Intro.html`.
- **`tagName` vs `localName`** — `tagName` is upper-cased only in the HTML
  namespace, so an upper-case denylist misses everything in SVG and MathML
  foreign content. `<svg><script>` survived; worse, `<svg><style>` applies
  document-wide the moment it is inserted.
- **duplicated normalization** — the same URL policy existed twice as inline
  expressions, and a fix reached only one copy. It is one named function now.
- **unenumerated URL attributes** — `ping`, `srcset` and `poster` were all
  missing. Fixed by scanning every attribute value for an executing scheme
  regardless of name, which does not depend on having heard of the attribute.
- **DOM clobbering** — `<form><input name="localName">` made `el.localName`
  return an element, so `.toLowerCase()` threw and took the whole paste with it.
  Both `localName` and `attributes` are now read through the prototype's own
  getter.
