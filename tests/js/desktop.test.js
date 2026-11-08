// Renders desktop/plugin.js against the SDK shim and fixtures the Python backend produced.
import { test, before } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, copyFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { JSDOM } from 'jsdom'

const dom = new JSDOM('<!doctype html><html><body><div id="root"></div></body></html>', { pretendToBeVisual: true })
globalThis.window = dom.window
globalThis.document = dom.window.document
Object.defineProperty(globalThis, 'navigator', { value: dom.window.navigator, configurable: true })
globalThis.HTMLElement = dom.window.HTMLElement
globalThis.Node = dom.window.Node
globalThis.SVGElement = dom.window.SVGElement
globalThis.getComputedStyle = dom.window.getComputedStyle
globalThis.IS_REACT_ACT_ENVIRONMENT = true

const fixtures = Object.fromEntries(['status', 'findings', 'finding', 'events', 'exporters', 'rules'].map((n) => [n, JSON.parse(readFileSync(new URL(`./fixtures/${n}.json`, import.meta.url)))]))

const React = await import('react')
const { act } = React
const { createRoot } = await import('react-dom/client')
const sdk = await import('@hermes/plugin-sdk')
copyFileSync(fileURLToPath(new URL('../../desktop/plugin.js', import.meta.url)), fileURLToPath(new URL('./.plugin-under-test.js', import.meta.url)))
const plugin = (await import('./.plugin-under-test.js')).default

const restLog = []
const ctx = {
  contributions: [],
  registerMany(cs) { this.contributions.push(...cs); return () => {} },
  register(c) { this.contributions.push(c); return () => {} },
  rest: async (path, opts) => {
    restLog.push({ path, opts })
    if (path.startsWith('/status')) return fixtures.status
    if (path.startsWith('/findings')) return fixtures.findings
    if (path.startsWith('/finding/ack')) return { ok: true }
    if (path.startsWith('/finding')) return fixtures.finding
    if (path.startsWith('/events')) return fixtures.events
    if (path.startsWith('/exporters/test')) return { ok: true, text: 'sent', exporters: fixtures.exporters.exporters }
    if (path.startsWith('/exporters')) return fixtures.exporters
    if (path.startsWith('/rules')) return fixtures.rules
    throw new Error('unexpected ' + path)
  },
  onEvent: (type, fn) => sdk.host.onEvent(type, fn),
  onDispose: () => {}
}

const flush = async () => { for (let i = 0; i < 8; i++) await act(async () => { await new Promise((r) => setTimeout(r, 15)) }) }

before(() => plugin.register(ctx))

test('contract: id, contributions, events, no app-markup reach', () => {
  assert.equal(plugin.id, 'siemless')
  const areas = ctx.contributions.map((c) => c.area)
  assert.ok(areas.includes(sdk.ROUTES_AREA) && areas.includes(sdk.SIDEBAR_NAV_AREA) && areas.includes(sdk.STATUSBAR_AREAS.right) && areas.includes(sdk.PALETTE_AREA))
  assert.equal(ctx.contributions.find((c) => c.area === sdk.SIDEBAR_NAV_AREA).data.path, '/siemless')
  assert.ok(sdk.calls.events['plugin.siemless.finding'] && sdk.calls.events['plugin.siemless.health'])
  ctx.contributions.find((c) => c.area === sdk.PALETTE_AREA).data.run()
  assert.deepEqual(sdk.calls.navigate, ['/siemless'])
  const src = readFileSync(new URL('../../desktop/plugin.js', import.meta.url), 'utf8')
  assert.doesNotMatch(src, /document\.(querySelector|getElementsBy|getElementById)|data-slot|data-tour|data-sidebar|data-testid|MutationObserver|window\.hermesDesktop|dangerouslySetInnerHTML|\beval\(|new Function/)
})

test('page: tiles, findings list, evidence chain with visibility labels, ack, tabs', async () => {
  const page = ctx.contributions.find((c) => c.area === sdk.ROUTES_AREA)
  const root = createRoot(document.getElementById('root'))
  await act(async () => root.render(page.render()))
  await flush()
  let html = document.body.innerHTML
  assert.match(html, /SIEMless/)
  assert.match(html, /events 24h/i)
  assert.match(html, /SL-001/)
  assert.match(html, /SL-008/)
  assert.match(html, /Sensitive access then egress/)
  // detail pane shows evidence with observed/inferred badges and ATT&CK
  assert.match(html, /evidence chain/i)
  assert.match(html, /observed/)
  assert.match(html, /inferred/)
  assert.match(html, /T1700/)
  assert.match(html, /not visible to SIEMless/i)
  // targets are rendered as text (escaped), never as markup
  assert.ok(!html.includes('<script'))
  // ack round-trips
  const ack = [...document.querySelectorAll('button')].find((b) => b.textContent.includes('Mark reviewed'))
  await act(async () => ack.click())
  await flush()
  assert.ok(restLog.some((r) => r.path === '/finding/ack' && r.opts.method === 'POST'))
  // severity filter hides lows
  const select = document.querySelector('select')
  await act(async () => { select.value = 'high'; select.dispatchEvent(new window.Event('change', { bubbles: true })) })
  await flush()
  html = document.body.innerHTML
  assert.ok(!/SL-003/.test(html.split('evidence chain')[0]), 'medium findings hidden at ≥ high')
  // tabs
  for (const [label, expect] of [['exporters', /jsonl/], ['rules', /baseline ruleset/i], ['events', /secret\.access/]]) {
    const btn = [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === label)
    await act(async () => btn.click())
    await flush()
    assert.match(document.body.innerHTML, expect, label)
  }
  // exporters tab: test button posts
  const tab = [...document.querySelectorAll('button')].find((b) => b.textContent.trim() === 'exporters')
  await act(async () => tab.click())
  await flush()
  const send = [...document.querySelectorAll('button')].find((b) => b.textContent.includes('Send test event'))
  await act(async () => send.click())
  await flush()
  assert.ok(restLog.some((r) => r.path === '/exporters/test'))
  assert.ok(sdk.calls.notify.some((n) => /test event|siemless\.health/i.test(n.message)))
})

test('status chip and high-severity toast', async () => {
  const chip = ctx.contributions.find((c) => c.area === sdk.STATUSBAR_AREAS.right)
  const el = document.createElement('div')
  document.body.appendChild(el)
  await act(async () => createRoot(el).render(chip.render()))
  await flush()
  assert.match(el.textContent, /high|findings/)
  const before = sdk.calls.notify.length
  for (const fn of sdk.calls.events['plugin.siemless.finding']) fn({ severity: 'high', rule_id: 'SL-001', title: 'x' })
  assert.equal(sdk.calls.notify.length, before + 1)
  for (const fn of sdk.calls.events['plugin.siemless.finding']) fn({ severity: 'low', rule_id: 'SL-003', title: 'y' })
  assert.equal(sdk.calls.notify.length, before + 1, 'low findings do not toast')
})
