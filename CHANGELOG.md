# Changelog

## [Unreleased]

## [0.1.0]

First release. Extracted from
[tosijs-styled-editor](https://github.com/tonioloewald/tosijs-editor), where it
was written to close an unsanitized paste/drop path and then hardened across
three adversarial review rounds plus DOMPurify's published corpus.

The bypasses found and closed along the way, recorded because each is a
regression test now:

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
