#!/usr/bin/env bun
/**
 * Browser gate: DOMPurify's published fixture corpus, run against kilpi in a
 * real engine.
 *
 * Scored on EXECUTABLE RESIDUE, not string equality. DOMPurify's `expected`
 * values encode its own allowlist policy (it keeps <style>, we drop it), so
 * matching them exactly would measure agreement-with-DOMPurify rather than
 * safety. What matters is whether anything that can execute survives.
 *
 * This is the gate that earns the library its claims: it caught a bypass that
 * three adversarial review passes and 33 hand-written vectors had all missed
 * (C0 control characters inside a scheme -- Blink strips them before parsing,
 * so `\\u0001java\\u0003script:` IS javascript: by the time it is used).
 *
 * Exits non-zero on any residue, so `prepublishOnly` cannot ship past it.
 */
import { chromium } from 'playwright'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
// `m` flag: the fixtures file opens with a vendoring/attribution comment, so
// `export default` is not at the start of the string.
const fixtures = readFileSync(join(here, 'dompurify-fixtures.mjs'), 'utf8').replace(
  /^export default/m,
  'window.__FIX ='
)
const bundle = readFileSync(join(here, '..', 'dist', 'index.js'), 'utf8')

const browser = await chromium.launch()
const page = await browser.newPage()
page.on('pageerror', () => {})
await page.goto('about:blank')
await page.addScriptTag({
  content: bundle.replace(/export\s*\{[^}]*\}\s*;?/g, '') +
    '\nwindow.__kilpi = { sanitizeInPlace, isSafeNavigationUrl };'
})
await page.addScriptTag({ content: fixtures })

const result = await page.evaluate(() => {
  const CTRL = new RegExp('[' + String.fromCharCode(0) + '-' + String.fromCharCode(32) + ']+', 'g')
  const EXEC = /^(javascript|vbscript|livescript|mocha|data:text\/html)/
  const residue = (root) => {
    const bad = []
    for (const el of root.querySelectorAll('*')) {
      const ln = el.localName.toLowerCase()
      if (['script', 'iframe', 'object', 'embed', 'base', 'meta'].includes(ln)) bad.push('<' + ln + '>')
      for (const a of Array.from(el.attributes || [])) {
        const n = a.name.toLowerCase()
        if (n.startsWith('on')) bad.push(n)
        if (n === 'srcdoc') bad.push('srcdoc')
        if (EXEC.test((a.value || '').replace(CTRL, '').toLowerCase())) bad.push(n)
      }
    }
    return bad
  }
  const fails = []
  let total = 0
  for (const f of window.__FIX) {
    if (!f || typeof f.payload !== 'string') continue
    total++
    try {
      const d = document.createElement('div')
      d.innerHTML = f.payload
      window.__kilpi.sanitizeInPlace(d)
      const bad = residue(d)
      if (bad.length) fails.push({ title: String(f.title).slice(0, 70), found: [...new Set(bad)].slice(0, 3) })
    } catch (e) {
      fails.push({ title: String(f.title).slice(0, 70), found: ['THREW: ' + String(e.message).slice(0, 40)] })
    }
  }
  return { total, fails }
})
await browser.close()

console.log('DOMPurify corpus: ' + (result.total - result.fails.length) + '/' + result.total + ' clean')
if (result.fails.length) {
  for (const f of result.fails) console.log('  FAIL ' + f.found.join(', ') + '  ' + f.title)
  process.exit(1)
}
