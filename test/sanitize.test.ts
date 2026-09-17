import { test, expect, describe } from 'bun:test'
import { sanitizeInPlace, isSafeNavigationUrl } from '../src/index'

describe('sanitizeInPlace', () => {
  const frag = (html: string): HTMLElement => {
    const el = document.createElement('div')
    el.innerHTML = html
    return el
  }

  test('strips inline event handlers however they are spelled', () => {
    const el = frag('<img src="x" onerror="boom()"><b ONCLICK="boom()">hi</b>')
    sanitizeInPlace(el)
    expect(el.querySelector('img')!.hasAttribute('onerror')).toBe(false)
    expect(el.querySelector('b')!.hasAttribute('ONCLICK')).toBe(false)
    expect(el.textContent).toBe('hi')
  })

  test('removes elements that execute or re-target', () => {
    const el = frag(
      '<p>keep</p><script>bad()</script><iframe src="x"></iframe><object></object><base href="http://evil">'
    )
    sanitizeInPlace(el)
    expect(el.querySelectorAll('script, iframe, object, base').length).toBe(0)
    expect(el.querySelector('p')!.textContent).toBe('keep')
  })

  test('drops javascript: URLs but keeps ordinary ones', () => {
    const el = frag(
      '<a id="bad" href="javascript:alert(1)">x</a>' +
        '<a id="spaced" href="  JaVaScRiPt:alert(1)">x</a>' +
        '<a id="ok" href="https://example.com">x</a>' +
        '<a id="rel" href="/page">x</a>' +
        '<a id="mail" href="mailto:a@b.c">x</a>'
    )
    sanitizeInPlace(el)
    expect(el.querySelector('#bad')!.hasAttribute('href')).toBe(false)
    expect(el.querySelector('#spaced')!.hasAttribute('href')).toBe(false)
    expect(el.querySelector('#ok')!.getAttribute('href')).toBe(
      'https://example.com'
    )
    expect(el.querySelector('#rel')!.getAttribute('href')).toBe('/page')
    expect(el.querySelector('#mail')!.getAttribute('href')).toBe('mailto:a@b.c')
  })

  test('allows raster data: images but not data:text/html or data:image/svg', () => {
    const el = frag(
      '<img id="png" src="data:image/png;base64,iVBOR">' +
        '<img id="html" src="data:text/html;base64,PHNjcmlwdD4=">' +
        '<img id="svg" src="data:image/svg+xml;base64,PHN2Zz4=">'
    )
    sanitizeInPlace(el)
    expect(el.querySelector('#png')!.hasAttribute('src')).toBe(true)
    expect(el.querySelector('#html')!.hasAttribute('src')).toBe(false)
    expect(el.querySelector('#svg')!.hasAttribute('src')).toBe(false)
  })

  test('leaves unknown custom elements and their content alone', () => {
    // Plugin markup must survive even when its component is not registered —
    // see EXTENSIBILITY.md. Unknown ELEMENTS are content; unknown SCHEMES are not.
    const el = frag('<x-plugin data-note="k">text <em>inside</em></x-plugin>')
    sanitizeInPlace(el)
    expect(el.querySelector('x-plugin')).not.toBeNull()
    expect(el.querySelector('x-plugin')!.getAttribute('data-note')).toBe('k')
    expect(el.textContent).toBe('text inside')
  })
})

describe('sanitizer bypasses that were shipped and caught in review', () => {
  const frag = (html: string): HTMLElement => {
    const el = document.createElement('div')
    el.innerHTML = html
    return el
  }

  test('control characters inside the scheme do not smuggle javascript:', () => {
    // The URL parser removes tab/LF/CR BEFORE matching a scheme, so these are
    // all `javascript:` to the browser. Testing the raw string saw a
    // schemeless relative path and let them through.
    expect(isSafeNavigationUrl('java\tscript:alert(1)')).toBe(false)
    expect(isSafeNavigationUrl('java\nscript:alert(1)')).toBe(false)
    expect(isSafeNavigationUrl('java\rscript:alert(1)')).toBe(false)
    expect(isSafeNavigationUrl('  java\t\nscript:alert(1)  ')).toBe(false)
    // the stricter data: rejection must normalize identically, or it is the
    // check that gets bypassed
    expect(isSafeNavigationUrl('data:image/png;base64,AAAA')).toBe(false)
    expect(isSafeNavigationUrl('da\tta:image/png;base64,AAAA')).toBe(false)
    expect(isSafeNavigationUrl('da\nta:image/png;base64,AAAA')).toBe(false)
    // and a legitimate URL is still legitimate
    expect(isSafeNavigationUrl('https://example.com/a b')).toBe(true)
    expect(isSafeNavigationUrl('/my page')).toBe(true)
  })

  test('a relative href containing a space keeps its href', () => {
    // Stripping every space made `Chapter 3: Intro.html` look like a scheme,
    // and the sanitizer silently deleted a legitimate link.
    const el = frag('<a id="rel" href="Chapter 3: Intro.html">x</a>')
    sanitizeInPlace(el)
    expect(el.querySelector('#rel')!.getAttribute('href')).toBe(
      'Chapter 3: Intro.html'
    )
    expect(isSafeNavigationUrl('Chapter 3: Intro.html')).toBe(true)
  })

  test('an encoded tab in a pasted href is stripped', () => {
    const el = frag('<a id="x" href="java&#9;script:alert(1)">x</a>')
    sanitizeInPlace(el)
    expect(el.querySelector('#x')!.hasAttribute('href')).toBe(false)
  })

  test('script and style in SVG/MathML foreign content are removed', () => {
    // localName, not tagName: foreign content reports a lowercase tagName, so
    // an upper-case denylist missed all of it. An SVG <style> applies
    // document-wide the moment it lands — no store-and-re-serve needed.
    // Two fragments, not one: happy-dom drops everything parsed after
    // `</script>`, so a combined fixture made the <style> assertion VACUOUS —
    // it passed against the pre-fix uppercase denylist too.
    // `<p>` goes first for the same reason (content after `</svg>` is dropped).
    const withScript = frag('<p>keep</p><svg><script>bad()</script></svg>')
    sanitizeInPlace(withScript)
    expect(withScript.querySelectorAll('script').length).toBe(0)
    expect(withScript.querySelector('p')!.textContent).toBe('keep')

    const withStyle = frag('<p>keep</p><svg><style>body{x:y}</style></svg>')
    expect(withStyle.querySelectorAll('style').length).toBe(1) // fixture is real
    sanitizeInPlace(withStyle)
    expect(withStyle.querySelectorAll('style').length).toBe(0)
    expect(withStyle.querySelector('p')!.textContent).toBe('keep')
  })

  test('SVG animation cannot retarget an attribute past the scheme check', () => {
    const el = frag(
      '<p>k</p><svg><set attributeName="href" to="javascript:bad()"/></svg>'
    )
    expect(el.querySelectorAll('set').length).toBe(1) // fixture is real
    sanitizeInPlace(el)
    expect(el.querySelectorAll('set').length).toBe(0)

    // camelCase animation tags too — localName is lower-case regardless
    const camel = frag('<p>k</p><svg><animateTransform attributeName="x"/></svg>')
    expect(camel.querySelectorAll('animateTransform').length).toBe(1)
    sanitizeInPlace(camel)
    expect(camel.querySelectorAll('animateTransform').length).toBe(0)
  })
})

describe("DOMPurify's corpus: the two cases that pull opposite ways", () => {
  // Our whole sanitizer passes DOMPurify's 223 published fixtures with zero
  // executable residue. These two are the pair that constrains the URL
  // normalizer from both sides — widen it and the link breaks, narrow it and
  // the payload executes.
  test('C0 controls inside a scheme are stripped (DOMPurify #Low-range-ASCII)', () => {
    const el = document.createElement('div')
    // Blink removes the whole low-ASCII range from a URL before parsing, so
    // this IS `javascript:` by the time it is used.
    el.innerHTML = '<a id="x" href="\u0001java\u0003script:alert(1)">y</a>'
    sanitizeInPlace(el)
    expect(el.querySelector('#x')!.hasAttribute('href')).toBe(false)
    expect(isSafeNavigationUrl('\u0001java\u0003script:alert(1)')).toBe(false)
  })

  test('but interior SPACES are preserved, so relative links survive', () => {
    const el = document.createElement('div')
    el.innerHTML = '<a id="x" href="Chapter 3: Intro.html">y</a>'
    sanitizeInPlace(el)
    expect(el.querySelector('#x')!.getAttribute('href')).toBe(
      'Chapter 3: Intro.html'
    )
  })
})

describe('DOM clobbering cannot break the sanitizer', () => {
  test('a form control named localName does not throw or hide the form', () => {
    // Named form controls shadow same-named properties on their form, so
    // `el.localName` returned an INPUT and `.toLowerCase()` threw — taking the
    // whole paste with it. Reading the prototype getter cannot be shadowed.
    const el = document.createElement('div')
    el.innerHTML =
      '<form><input name="localName"><input name="attributes"></form><p>keep</p>'
    expect(() => sanitizeInPlace(el)).not.toThrow()
    expect(el.querySelectorAll('form').length).toBe(0)
  })

  test('clobbering does not smuggle a handler past the attribute scan', () => {
    const el = document.createElement('div')
    el.innerHTML =
      '<form><input name="attributes"></form><img src="x" onerror="boom()">'
    sanitizeInPlace(el)
    expect(el.innerHTML).not.toMatch(/onerror/i)
  })
})

describe('attributes dangerous by capability, not by scheme', () => {
  test('ping is removed even though its URL is perfectly ordinary', () => {
    const el = document.createElement('div')
    el.innerHTML = '<a href="/ok" ping="https://evil.example/collect">x</a>'
    sanitizeInPlace(el)
    const a = el.querySelector('a')!
    expect(a.hasAttribute('ping')).toBe(false)
    expect(a.getAttribute('href')).toBe('/ok')
  })

  test('URL attributes beyond href/src are scheme-checked', () => {
    const el = document.createElement('div')
    el.innerHTML =
      '<img id="a" srcset="javascript:boom() 1x"><video id="b" poster="javascript:boom()"></video>'
    sanitizeInPlace(el)
    expect(el.querySelector('#a')!.hasAttribute('srcset')).toBe(false)
    expect(el.querySelector('#b')!.hasAttribute('poster')).toBe(false)
  })

  test('an executing scheme is stripped from an unlisted attribute too', () => {
    // The capability scan does not depend on having heard of the attribute.
    const el = document.createElement('div')
    el.innerHTML = '<div data-whatever="javascript:boom()">x</div>'
    sanitizeInPlace(el)
    expect(el.querySelector('div')!.hasAttribute('data-whatever')).toBe(false)
  })
})

describe('isSafeNavigationUrl', () => {
  test('rejects javascript: and data:, allows http(s)/mailto/relative', () => {
    expect(isSafeNavigationUrl('javascript:alert(1)')).toBe(false)
    expect(isSafeNavigationUrl(' javascript:alert(1)')).toBe(false)
    expect(isSafeNavigationUrl('data:image/png;base64,x')).toBe(false)
    expect(isSafeNavigationUrl('https://example.com')).toBe(true)
    expect(isSafeNavigationUrl('mailto:a@b.c')).toBe(true)
    expect(isSafeNavigationUrl('/relative/path')).toBe(true)
  })
})
