/**
 * kilpi — a very small HTML sanitizer for rich-text paste paths.
 *
 * `kilpi` is Finnish for shield.
 *
 * WHAT THIS IS FOR: an editor that accepts pasted and dropped HTML and needs to
 * put it into a live document. Replacing `contentEditable` means replacing the
 * sanitization the browser was doing on your behalf, and that is the gap this
 * fills.
 *
 * READ THE THREAT MODEL BEFORE ADOPTING IT — see SECURITY.md. The short version:
 * this is a DENYLIST for elements and attributes, and an ALLOWLIST for URL
 * schemes. That is a deliberate trade, not an oversight. It is why the whole
 * thing is under 1 kB gzipped, and it is why UNKNOWN ELEMENTS SURVIVE — which
 * is required if your editor has a plugin architecture whose markup must round
 * trip, and is the WRONG default if you want to be protected from an element
 * nobody has heard of yet. If that second property is what you need, use
 * DOMPurify; it is excellent, and this library does not try to replace it.
 *
 * Verified against DOMPurify's own published fixture corpus (223 payloads):
 * zero executable residue. That corpus is vendored into this repository's tests
 * because it is the part that actually keeps a sanitizer honest — it caught a
 * bypass that three adversarial review passes and 33 hand-written vectors had
 * all missed.
 */

/**
 * Normalize a URL the way the URL parser does, for scheme testing only.
 *
 * WHATWG removes leading and trailing C0-or-space, and every ASCII tab/LF/CR
 * ANYWHERE, before matching a scheme. Testing the raw string instead let
 * `java&#9;script:` read as a schemeless relative path while the browser saw
 * `javascript:` — checking a different string from the one that gets parsed.
 *
 * It must mirror the parser in BOTH directions. Stripping all spaces was too
 * aggressive: `Chapter 3: Intro.html` became `Chapter3:Intro.html`, which
 * matches the scheme pattern, fails the allowlist, and had its href silently
 * removed — a legitimate relative link destroyed by the sanitizer. Interior
 * spaces are preserved here, and still break the scheme match exactly as they
 * do in the parser.
 *
 * ONE implementation, deliberately: this logic previously existed twice as
 * inline expressions, and the fix for the tab bypass reached only one of them.
 */
function forSchemeTest(value: string): string {
  return (
    value
      // Leading/trailing whitespace: the parser ignores it.
      .replace(/^[\u0000-\u0020]+|[\u0000-\u0020]+$/g, '')
      // EVERY C0 control anywhere, not just tab/LF/CR. Blink strips the whole
      // low-ASCII range out of a URL before parsing it, so
      // `\u0001java\u0003script:` is `javascript:` by the time it is used —
      // DOMPurify's own corpus carries this as "Low-range-ASCII obfuscated
      // JavaScript URI", and a narrower rule let it through.
      //
      // Interior SPACES are deliberately kept: stripping those turned
      // `Chapter 3: Intro.html` into something that looked like a scheme and
      // got a legitimate link deleted. Controls out, spaces in — the two
      // failures pull in opposite directions and this is the line between them.
      .replace(/[\u0000-\u001f\u007f]/g, '')
  )
}

function isSafeUrl(value: string): boolean {
  const trimmed = forSchemeTest(value)
  // Protocol-relative and path-relative URLs carry no scheme and are fine.
  if (!/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) return true
  if (/^data:image\/(png|jpeg|jpg|gif|webp|avif|bmp|svg\+xml);/i.test(trimmed)) {
    // SVG can carry script, so allow it only where it cannot execute (img src),
    // which the caller enforces by attribute name.
    return !/^data:image\/svg/i.test(trimmed)
  }
  return /^(https?|mailto|tel):/i.test(trimmed)
}

/**
 * Elements that can execute or re-target, and are never document content.
 *
 * Compared against `localName`, NOT `tagName`. `tagName` is upper-cased only
 * for elements in the HTML namespace: anything parsed into SVG or MathML
 * foreign content reports a LOWERCASE tagName, so an upper-case set silently
 * misses every entry there — `<svg><script>` survived, and an SVG `<style>`
 * needs no store-and-re-serve hop at all, since it applies document-wide the
 * moment it is inserted.
 */
const FORBIDDEN_TAGS = new Set([
  'script',
  'iframe',
  'object',
  'embed',
  'link',
  'meta',
  'base',
  'style',
  'form',
  'noscript',
  'template',
  // SVG animation can retarget an attribute — `<set attributeName="href"
  // to="javascript:…">` — which reintroduces a scheme we just checked.
  'animate',
  'animatetransform',
  'animatemotion',
  'set',
])

/**
 * Attributes whose value is a URL.
 *
 * Enumerating these is the weak part of a denylist and it has already been
 * wrong: `ping`, `srcset` and `poster` were all missing, so
 * `<a ping="https://evil/collect">` sailed through. The scheme scan below is
 * the real defence — this list only decides which attributes get the STRICTER
 * treatment (rejecting schemes that are merely unknown, rather than only those
 * that are known-dangerous).
 */
const URL_ATTRIBUTES = [
  'href',
  'src',
  'srcset',
  'xlink:href',
  'action',
  'formaction',
  'ping',
  'poster',
  'background',
  'cite',
  'data',
  'longdesc',
  'profile',
  'usemap',
  'manifest',
]

/**
 * Schemes that execute, in ANY attribute.
 *
 * Checked against every attribute value regardless of name, because the
 * attribute list above cannot be trusted to be complete — a capability check
 * does not depend on having heard of the attribute.
 */
const DANGEROUS_SCHEME = /^(javascript|vbscript|livescript|mocha|data:text\/html)/i

/**
 * Attributes removed outright, whatever their value.
 *
 * Dangerous by CAPABILITY rather than by scheme, so no URL check catches them:
 * `ping` fires a POST to an arbitrary URL when a link is clicked — a perfectly
 * ordinary https URL, reporting that the reader clicked.
 *
 * NOT `is`, though it belongs here conceptually: `removeAttribute('is')` is a
 * NO-OP in Chrome once the attribute has been parsed, verified directly, so a
 * line for it would only look like protection. DOMPurify does not remove it
 * either. Neutralizing it means replacing the element rather than the
 * attribute, which is not worth doing inside a TreeWalker for an attack that
 * needs the host page to have registered a hostile customized built-in.
 */
const FORBIDDEN_ATTRIBUTES = new Set(['ping'])

/**
 * Clobber-proof accessors.
 *
 * Named form controls shadow same-named properties on their form, so a crafted
 * `<input name="localName">` or `name="attributes"` turns a string or a
 * NamedNodeMap into an element. These read the real getters off the prototype,
 * which an attacker cannot shadow.
 */
const localNameGetter = Object.getOwnPropertyDescriptor(
  Element.prototype,
  'localName'
)?.get
const attributesGetter = Object.getOwnPropertyDescriptor(
  Element.prototype,
  'attributes'
)?.get

function getLocalName(el: Element): string | undefined {
  return localNameGetter
    ? (localNameGetter.call(el) as string)
    : (el.localName as string)
}

function getAttributes(el: Element): NamedNodeMap | undefined {
  return attributesGetter
    ? (attributesGetter.call(el) as NamedNodeMap)
    : el.attributes
}

/**
 * Strip executable content from a subtree, IN PLACE.
 *
 * The editor replaced `contentEditable` but not the sanitization the browser
 * was doing on its behalf: pasted and dropped HTML is written into the live
 * document, and from there into `value`, `internals.setFormValue` and every
 * undo snapshot — so an unsanitized payload is stored, re-served, and re-fired
 * on undo. Must run BEFORE any node enters the document.
 *
 * This is deliberately a denylist for elements and an allowlist for URL
 * schemes: unknown ELEMENTS are content (including a plugin's custom elements,
 * which must survive — see EXTENSIBILITY.md), whereas unknown SCHEMES are not.
 */
export function sanitizeInPlace(root: Element | DocumentFragment): void {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT)
  const doomed: Element[] = []
  let node: Node | null
  while ((node = walker.nextNode())) {
    const el = node as Element
    // DOM CLOBBERING: a form's named controls shadow its own properties, so
    // `<form><input name="localName">` makes `el.localName` return that INPUT
    // rather than a string — `.toLowerCase()` then throws and takes the whole
    // paste with it. Reading through the prototype's own getter cannot be
    // clobbered, because the attacker can only shadow the instance.
    const localName = String(getLocalName(el) ?? '').toLowerCase()
    if (FORBIDDEN_TAGS.has(localName)) {
      doomed.push(el)
      continue
    }
    for (const attr of Array.from(getAttributes(el) ?? [])) {
      const name = attr.name.toLowerCase()
      // Every inline handler, however it is spelled.
      if (name.startsWith('on')) {
        el.removeAttribute(attr.name)
        continue
      }
      if (FORBIDDEN_ATTRIBUTES.has(name)) {
        el.removeAttribute(attr.name)
        continue
      }
      const normalized = forSchemeTest(attr.value)
      // Capability check first: an executing scheme is dangerous wherever it
      // appears, including in an attribute this list has never heard of.
      if (DANGEROUS_SCHEME.test(normalized)) {
        el.removeAttribute(attr.name)
        continue
      }
      if (URL_ATTRIBUTES.includes(name) && !isSafeUrl(attr.value)) {
        el.removeAttribute(attr.name)
      }
    }
  }
  // Removing during the walk invalidates it, so do it after.
  for (const el of doomed) el.remove()
}

/**
 * Is this URL safe to NAVIGATE to, or to write into an href?
 *
 * Stricter than `isSafeUrl`: that one allows raster `data:image/*` because an
 * `<img src>` may legitimately carry one, while a link must never — so this
 * rejects every `data:` URL. Both must normalize identically, or the stricter
 * check is the one that gets bypassed: `da&#9;ta:image/png;…` passed here while
 * `data:image/png;…` was correctly rejected.
 */
export function isSafeNavigationUrl(value: string): boolean {
  return isSafeUrl(value) && !/^data:/i.test(forSchemeTest(value))
}
