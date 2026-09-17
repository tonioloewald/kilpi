import { Window } from 'happy-dom'

const window = new Window()
const globals: Record<string, unknown> = { window }
for (const prop of [
  'window', 'document', 'HTMLElement', 'Element', 'Node', 'Text',
  'DocumentFragment', 'NodeFilter', 'Range', 'NamedNodeMap',
]) {
  const v = (window as unknown as Record<string, unknown>)[prop]
  if (v !== undefined) globals[prop] = v
}
Object.assign(globalThis, globals)
