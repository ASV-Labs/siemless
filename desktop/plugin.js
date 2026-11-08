// SIEMless — Hermes Desktop half.
// Plain ESM, no build step. Only `@hermes/plugin-sdk`, `react` and `react/jsx-runtime` may be imported.
// Everything on screen comes from this plugin's own backend (dashboard/plugin_api.py) through ctx.rest.
// No app markup is queried, observed or styled; the page draws only its own elements.

import {
  host,
  useValue,
  useQuery,
  queryClient,
  ROUTES_AREA,
  SIDEBAR_NAV_AREA,
  STATUSBAR_AREAS,
  PALETTE_AREA,
  Button,
  Badge,
  Input,
  Codicon,
  EmptyState,
  cn,
  haptic,
  relativeTime
} from '@hermes/plugin-sdk'
import { createElement as h, useEffect, useMemo, useState } from 'react'

const ID = 'siemless'
const ROUTE = '/siemless'
let REST = null // set in register(); ctx.rest is scoped to /api/plugins/siemless

// ------------------------------------------------------------------ helpers
const SEV_ORDER = ['info', 'low', 'medium', 'high', 'critical']
const SEV_CLASS = {
  info: 'text-(--ui-text-tertiary)',
  low: 'text-(--ui-text-secondary)',
  medium: 'text-(--ui-warning)',
  high: 'text-(--ui-danger)',
  critical: 'text-(--ui-danger) font-semibold'
}
const SEV_DOT = { info: '○', low: '◔', medium: '◑', high: '◕', critical: '●' }
const KIND_ICON = {
  'secret.access': 'key',
  'net.egress': 'globe',
  'process.exec': 'terminal',
  'file.read': 'file',
  'file.write': 'edit',
  'config.change': 'settings-gear',
  'cron.change': 'calendar',
  'plugin.change': 'extensions',
  'skill.change': 'book',
  'approval.request': 'question',
  'approval.response': 'shield',
  'subagent.start': 'organization',
  'subagent.stop': 'organization',
  'content.untrusted': 'warning',
  'tool.call': 'symbol-method',
  'llm.response': 'hubot',
  'aux.call': 'hubot',
  command: 'terminal-cmd',
  finding: 'bell',
  'turn.start': 'comment-discussion',
  'turn.end': 'comment-discussion'
}

function short(s, n) {
  if (!s) return ''
  return s.length > n ? s.slice(0, Math.max(0, n - 1)) + '…' : s
}
function fmtTs(ms) {
  if (!ms) return ''
  try {
    return relativeTime(ms)
  } catch {
    return new Date(ms).toLocaleTimeString()
  }
}
function fmtClock(ms) {
  if (!ms) return '-'
  const d = new Date(ms)
  return d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit', second: '2-digit' })
}
async function rest(path, opts) {
  if (!REST) throw new Error('siemless backend is not connected')
  return REST(path, opts)
}
function sevRank(s) {
  const i = SEV_ORDER.indexOf(s)
  return i < 0 ? 0 : i
}

// --------------------------------------------------------------- components
function Tile({ label, value, sub, tone }) {
  return h(
    'div',
    { className: 'flex min-w-28 flex-col rounded-md border border-(--ui-stroke-secondary) px-3 py-2' },
    h('div', { className: 'text-[0.625rem] uppercase tracking-wide text-(--ui-text-quaternary)' }, label),
    h('div', { className: cn('text-lg font-semibold tabular-nums', tone || 'text-(--ui-text-primary)') }, value == null ? '—' : String(value)),
    sub ? h('div', { className: 'text-[0.6875rem] text-(--ui-text-tertiary)' }, sub) : null
  )
}

function SeverityBar({ counts }) {
  const total = SEV_ORDER.reduce((a, k) => a + (counts[k] || 0), 0)
  if (!total) return h('div', { className: 'text-xs text-(--ui-text-tertiary)' }, 'no findings in the last 24 h')
  return h(
    'div',
    { className: 'flex items-center gap-2' },
    h(
      'div',
      { className: 'flex h-2 w-48 overflow-hidden rounded-full bg-(--ui-fill-tertiary)' },
      SEV_ORDER.map((k) =>
        counts[k]
          ? h('div', {
              key: k,
              title: `${k}: ${counts[k]}`,
              className: cn('h-full', k === 'critical' || k === 'high' ? 'bg-(--ui-danger)' : k === 'medium' ? 'bg-(--ui-warning)' : 'bg-(--ui-text-quaternary)'),
              style: { width: `${(100 * counts[k]) / total}%` }
            })
          : null
      )
    ),
    h(
      'div',
      { className: 'flex gap-1 text-[0.6875rem] text-(--ui-text-tertiary)' },
      SEV_ORDER.filter((k) => counts[k]).map((k) => h('span', { key: k, className: SEV_CLASS[k] }, `${SEV_DOT[k]} ${counts[k]} ${k}`))
    )
  )
}

function FindingRow({ f, active, onClick }) {
  return h(
    'button',
    {
      type: 'button',
      onClick,
      className: cn(
        'flex w-full items-start gap-2 rounded px-2 py-1.5 text-left hover:bg-(--ui-fill-secondary)',
        active ? 'bg-(--ui-fill-secondary)' : '',
        f.acked ? 'opacity-60' : ''
      )
    },
    h('span', { className: cn('mt-0.5 w-3 shrink-0 text-center text-xs', SEV_CLASS[f.severity]) }, SEV_DOT[f.severity] || '○'),
    h(
      'div',
      { className: 'min-w-0 flex-1' },
      h(
        'div',
        { className: 'flex items-center gap-1 text-xs' },
        h('span', { className: 'font-mono text-[0.6875rem] text-(--ui-text-tertiary)' }, f.rule_id),
        h('span', { className: 'truncate text-(--ui-text-primary)', title: f.title }, f.title)
      ),
      h(
        'div',
        { className: 'flex items-center gap-2 text-[0.6875rem] text-(--ui-text-tertiary)' },
        h('span', null, fmtTs(f.time)),
        h('span', null, `confidence ${f.confidence}`),
        f.attack && f.attack.length ? h('span', { className: 'font-mono' }, f.attack.map((a) => a.id).join(' ')) : null,
        f.acked ? h('span', null, '✓ reviewed') : null
      )
    )
  )
}

function ChainRow({ e, highlight }) {
  return h(
    'div',
    { className: cn('flex items-start gap-2 rounded px-2 py-1', highlight ? 'bg-(--ui-fill-secondary)' : '') },
    h(Codicon, { name: KIND_ICON[e.kind] || 'circle-outline', size: 12, className: 'mt-0.5 shrink-0 text-(--ui-text-tertiary)' }),
    h(
      'div',
      { className: 'min-w-0 flex-1 text-xs' },
      h(
        'div',
        { className: 'flex items-center gap-1' },
        h('span', { className: 'font-mono text-(--ui-text-secondary)' }, e.kind),
        e.tool ? h('span', { className: 'text-(--ui-text-tertiary)' }, e.tool) : null,
        h(Badge, { variant: 'outline', size: 'xs', title: e.visibility === 'observed' ? 'Hermes reported it' : 'derived from arguments or command text' }, e.visibility),
        e.outcome ? h('span', { className: 'text-(--ui-text-quaternary)' }, e.outcome) : null
      ),
      e.target || e.host ? h('div', { className: 'truncate font-mono text-[0.6875rem] text-(--ui-text-tertiary)', title: e.target || e.host }, e.target || e.host) : null,
      e.tags && e.tags.length ? h('div', { className: 'truncate text-[0.625rem] text-(--ui-text-quaternary)' }, e.tags.join(' ')) : null
    ),
    h('div', { className: 'shrink-0 font-mono text-[0.625rem] text-(--ui-text-quaternary)' }, fmtClock(e.time))
  )
}

function FindingDetail({ id, onChanged }) {
  const q = useQuery({ queryKey: [ID, 'finding', id], queryFn: () => rest(`/finding?id=${encodeURIComponent(id)}`), enabled: !!id })
  const [showContext, setShowContext] = useState(false)
  if (!id) return h('div', { className: 'p-3 text-xs text-(--ui-text-tertiary)' }, 'Pick a finding to see what it rests on.')
  if (q.isLoading) return h('div', { className: 'p-3 text-xs text-(--ui-text-tertiary)' }, 'loading…')
  if (q.isError || !q.data) return h('div', { className: 'p-3 text-xs text-(--ui-text-tertiary)' }, 'not found')
  const f = q.data.finding
  const chainIds = new Set((f.evidence || []).map((e) => e.id))
  const rows = showContext ? [...q.data.context].sort((a, b) => a.time - b.time) : q.data.chain
  return h(
    'div',
    { className: 'flex h-full flex-col' },
    h(
      'div',
      { className: 'border-b border-(--ui-stroke-secondary) p-3' },
      h(
        'div',
        { className: 'flex items-center gap-2' },
        h('span', { className: cn('text-sm', SEV_CLASS[f.severity]) }, `${SEV_DOT[f.severity]} ${f.severity}`),
        h('span', { className: 'font-mono text-xs text-(--ui-text-tertiary)' }, f.rule_id),
        h('span', { className: 'text-xs text-(--ui-text-tertiary)' }, f.rule_name),
        h('div', { className: 'flex-1' }),
        h(Badge, { variant: 'outline', size: 'xs' }, `confidence ${f.confidence}`)
      ),
      h('div', { className: 'mt-1 text-sm text-(--ui-text-primary)' }, f.title),
      h('div', { className: 'mt-2 text-xs text-(--ui-text-secondary)' }, h('span', { className: 'text-(--ui-text-quaternary)' }, 'observed: '), f.observed),
      h('div', { className: 'mt-1 text-xs text-(--ui-text-secondary)' }, h('span', { className: 'text-(--ui-text-quaternary)' }, 'why: '), f.why),
      f.attack && f.attack.length
        ? h(
            'div',
            { className: 'mt-2 flex flex-wrap gap-1' },
            f.attack.map((a) => h(Badge, { key: a.id, variant: 'outline', size: 'xs', title: a.tactic ? `${a.tactic.name} (${a.tactic.id})` : '' }, `${a.id} ${a.name}`))
          )
        : h('div', { className: 'mt-2 text-[0.6875rem] text-(--ui-text-quaternary)' }, f.attack_note || 'no ATT&CK technique matches exactly'),
      f.attack && f.attack.length && f.attack_note ? h('div', { className: 'mt-1 text-[0.6875rem] text-(--ui-text-quaternary)' }, f.attack_note) : null,
      h(
        'div',
        { className: 'mt-2 text-[0.6875rem] text-(--ui-text-tertiary)' },
        `${(f.visibility || {}).observed || 0} observed · ${(f.visibility || {}).inferred || 0} inferred`,
        f.session_id ? ` · session ${short(f.session_id, 14)}` : ''
      ),
      h(
        'div',
        { className: 'mt-2 flex gap-1' },
        h(
          Button,
          {
            variant: f.acked ? 'ghost' : 'outline',
            size: 'xs',
            onClick: async () => {
              haptic('tap')
              await rest('/finding/ack', { method: 'POST', body: { id: f.id, acked: !f.acked } })
              queryClient.invalidateQueries({ queryKey: [ID] })
              if (onChanged) onChanged()
            }
          },
          h(Codicon, { name: f.acked ? 'circle-outline' : 'check', size: 12 }),
          f.acked ? 'Un-review' : 'Mark reviewed'
        ),
        h(Button, { variant: showContext ? 'secondary' : 'ghost', size: 'xs', onClick: () => setShowContext(!showContext) }, showContext ? 'evidence only' : 'session context')
      )
    ),
    h(
      'div',
      { className: 'min-h-0 flex-1 overflow-auto p-1' },
      h('div', { className: 'px-2 pb-1 text-[0.625rem] uppercase tracking-wide text-(--ui-text-quaternary)' }, showContext ? 'session timeline (evidence highlighted)' : 'evidence chain, oldest first'),
      rows.map((e) => h(ChainRow, { key: e.id, e, highlight: showContext && chainIds.has(e.id) }))
    ),
    f.missing_evidence && f.missing_evidence.length
      ? h(
          'div',
          { className: 'border-t border-(--ui-stroke-secondary) p-3 text-[0.6875rem] text-(--ui-text-tertiary)' },
          h('div', { className: 'text-(--ui-text-quaternary)' }, 'not visible to SIEMless:'),
          f.missing_evidence.map((m, i) => h('div', { key: i }, `· ${m}`))
        )
      : null,
    h('div', { className: 'border-t border-(--ui-stroke-secondary) p-3 text-xs text-(--ui-text-secondary)' }, h('span', { className: 'text-(--ui-text-quaternary)' }, 'next: '), f.recommendation)
  )
}

function ExporterRow({ x }) {
  const tone =
    x.state === 'ok' ? 'text-(--ui-success)' : x.state === 'retrying' || x.state === 'refused' ? 'text-(--ui-danger)' : 'text-(--ui-text-tertiary)'
  const where = x.target || x.url || x.events_path || ''
  return h(
    'div',
    { className: 'flex items-center gap-2 px-2 py-1 text-xs', title: x.last_error || '' },
    h('span', { className: cn('w-16 shrink-0 font-mono', tone) }, x.name),
    h('span', { className: cn('w-24 shrink-0', tone) }, x.state === 'needs_consent' ? 'needs consent' : x.state),
    h('span', { className: 'w-20 shrink-0 tabular-nums text-(--ui-text-secondary)' }, `${x.sent} sent`),
    x.failed ? h('span', { className: 'w-16 shrink-0 tabular-nums text-(--ui-danger)' }, `${x.failed} fail`) : h('span', { className: 'w-16 shrink-0' }),
    x.dropped ? h('span', { className: 'w-20 shrink-0 tabular-nums text-(--ui-danger)' }, `${x.dropped} dropped`) : h('span', { className: 'w-20 shrink-0' }),
    x.spooled ? h('span', { className: 'w-20 shrink-0 tabular-nums text-(--ui-warning)' }, `${x.spooled} spooled`) : h('span', { className: 'w-20 shrink-0' }),
    h('span', { className: 'min-w-0 flex-1 truncate font-mono text-[0.6875rem] text-(--ui-text-quaternary)', title: where }, where),
    x.last_ok ? h('span', { className: 'shrink-0 text-[0.6875rem] text-(--ui-text-quaternary)' }, `ok ${fmtTs(x.last_ok)}`) : null
  )
}

function RuleRow({ r }) {
  return h(
    'div',
    { className: 'px-2 py-1 text-xs' },
    h(
      'div',
      { className: 'flex items-center gap-2' },
      h('span', { className: 'font-mono text-(--ui-text-tertiary)' }, r.id),
      h('span', { className: cn(SEV_CLASS[r.severity]) }, SEV_DOT[r.severity]),
      h('span', { className: 'text-(--ui-text-primary)' }, r.name),
      r.enabled === false ? h(Badge, { variant: 'outline', size: 'xs' }, 'disabled') : null,
      h('div', { className: 'flex-1' }),
      r.attack && r.attack.length ? h('span', { className: 'font-mono text-[0.625rem] text-(--ui-text-quaternary)' }, r.attack.join(' ')) : null
    ),
    r.description ? h('div', { className: 'text-[0.6875rem] text-(--ui-text-tertiary)' }, r.description) : null
  )
}

function EventRow({ e }) {
  return h(ChainRow, { e })
}

// -------------------------------------------------------------------- page
function SiemlessPage() {
  const focused = useValue(host.state.focusedSessionId)
  const [tab, setTab] = useState('findings') // findings | events | exporters | rules
  const [scope, setScope] = useState('all') // all | chat
  const [q, setQ] = useState('')
  const [minSev, setMinSev] = useState('info')
  const [selected, setSelected] = useState(null)
  const sessionId = scope === 'chat' ? focused : null

  const status = useQuery({ queryKey: [ID, 'status'], queryFn: () => rest('/status'), refetchInterval: 5000 })
  const findings = useQuery({
    queryKey: [ID, 'findings', sessionId || '*'],
    queryFn: () => rest(`/findings?limit=200${sessionId ? `&session_id=${encodeURIComponent(sessionId)}` : ''}`),
    refetchInterval: 5000
  })
  const events = useQuery({
    queryKey: [ID, 'events', sessionId || '*'],
    queryFn: () => rest(`/events?limit=200${sessionId ? `&session_id=${encodeURIComponent(sessionId)}` : ''}`),
    refetchInterval: 5000,
    enabled: tab === 'events'
  })
  const exporters = useQuery({ queryKey: [ID, 'exporters'], queryFn: () => rest('/exporters'), refetchInterval: 5000, enabled: tab === 'exporters' })
  const rules = useQuery({ queryKey: [ID, 'rules'], queryFn: () => rest('/rules'), enabled: tab === 'rules' })

  const st = status.data
  const list = useMemo(() => {
    const fs = (findings.data && findings.data.findings) || []
    const ql = q.trim().toLowerCase()
    return fs
      .filter((f) => sevRank(f.severity) >= sevRank(minSev))
      .filter((f) => !ql || `${f.rule_id} ${f.title} ${f.observed} ${(f.attack || []).map((a) => a.id).join(' ')}`.toLowerCase().includes(ql))
  }, [findings.data, q, minSev])
  useEffect(() => {
    if (selected && !list.some((f) => f.id === selected)) setSelected(list[0] ? list[0].id : null)
    if (!selected && list[0]) setSelected(list[0].id)
  }, [list])

  const queueTone = st && st.queue && st.queue.dropped > 0 ? 'text-(--ui-danger)' : null
  const badExporters = st && st.exporters ? st.exporters.filter((x) => x.state === 'retrying' || x.state === 'refused').length : 0

  return h(
    'div',
    { className: 'flex h-full flex-col' },
    // header
    h(
      'div',
      { className: 'flex items-center gap-3 border-b border-(--ui-stroke-secondary) px-3 py-2' },
      h(Codicon, { name: 'shield', size: 16, className: 'text-(--ui-accent)' }),
      h('div', { className: 'text-sm font-medium text-(--ui-text-primary)' }, 'SIEMless'),
      h('div', { className: 'text-xs text-(--ui-text-tertiary)' }, 'what the agent did, as security events'),
      h('div', { className: 'flex-1' }),
      st
        ? h(
            'div',
            { className: 'flex items-center gap-1 text-[0.6875rem] text-(--ui-text-tertiary)' },
            h(Badge, { variant: 'outline', size: 'xs' }, `v${st.version}`),
            h(Badge, { variant: 'outline', size: 'xs' }, st.remote_export ? 'remote export on' : 'local only'),
            st.queue && !st.queue.worker_alive && st.live ? h(Badge, { variant: 'destructive', size: 'xs' }, 'worker stopped') : null
          )
        : null
    ),
    // tiles
    h(
      'div',
      { className: 'flex flex-wrap items-stretch gap-2 border-b border-(--ui-stroke-secondary) px-3 py-2' },
      h(Tile, { label: 'events 24h', value: st ? st.events_24h : null, sub: st && st.kinds_24h ? `${Object.keys(st.kinds_24h).length} kinds` : '' }),
      h(Tile, { label: 'findings 24h', value: st ? Object.values(st.findings_24h || {}).reduce((a, b) => a + b, 0) : null, sub: st ? `${st.findings_total} total` : '', tone: st && (st.findings_24h.high || st.findings_24h.critical) ? 'text-(--ui-danger)' : null }),
      h(Tile, { label: 'sessions 24h', value: st ? (st.sessions_24h != null ? st.sessions_24h : st.correlator ? st.correlator.sessions : null) : null, sub: st ? `${st.hosts_known} hosts known` : '' }),
      // The page reads through its own process, whose queue is always empty; show the queue only where it is real.
      st && st.live === false
        ? h(Tile, { label: 'store', value: st.db_bytes != null ? `${(st.db_bytes / 1048576).toFixed(1)} MB` : null, sub: 'on this machine' })
        : h(Tile, { label: 'queue', value: st && st.queue ? `${st.queue.size}/${st.queue.capacity}` : null, sub: st && st.queue ? `${st.queue.dropped} dropped` : '', tone: queueTone }),
      h(Tile, { label: 'exporters', value: st && st.exporters ? st.exporters.length : null, sub: badExporters ? `${badExporters} failing` : 'healthy', tone: badExporters ? 'text-(--ui-danger)' : null }),
      h(Tile, { label: 'detect latency', value: st && st.latency_ms && st.latency_ms.p50 != null ? `${st.latency_ms.p50} ms` : null, sub: st && st.latency_ms && st.latency_ms.p95 != null ? `p95 ${st.latency_ms.p95} ms` : 'hook → finding' }),
      h('div', { className: 'flex flex-1 flex-col justify-center px-2' }, h(SeverityBar, { counts: (st && st.findings_24h) || {} }))
    ),
    // tabs
    h(
      'div',
      { className: 'flex items-center gap-1 border-b border-(--ui-stroke-secondary) px-3 py-1' },
      ['findings', 'events', 'exporters', 'rules'].map((t) =>
        h(Button, { key: t, variant: tab === t ? 'secondary' : 'ghost', size: 'xs', onClick: () => setTab(t) }, t)
      ),
      h('div', { className: 'flex-1' }),
      tab === 'findings' || tab === 'events'
        ? h(Button, { variant: scope === 'chat' ? 'secondary' : 'ghost', size: 'xs', title: 'only the focused chat', onClick: () => setScope(scope === 'chat' ? 'all' : 'chat') }, scope === 'chat' ? 'this chat' : 'all sessions')
        : null
    ),
    // body
    tab === 'findings'
      ? h(
          'div',
          { className: 'flex min-h-0 flex-1' },
          h(
            'div',
            { className: 'flex w-96 shrink-0 flex-col border-r border-(--ui-stroke-secondary)' },
            h(
              'div',
              { className: 'flex items-center gap-1 p-2' },
              h(Input, { value: q, placeholder: 'filter findings…', onChange: (e) => setQ(e.target.value), className: 'h-7 text-xs' }),
              h(
                'select',
                { value: minSev, onChange: (e) => setMinSev(e.target.value), className: 'h-7 rounded border border-(--ui-stroke-secondary) bg-transparent px-1 text-xs text-(--ui-text-secondary)', title: 'minimum severity' },
                SEV_ORDER.map((s) => h('option', { key: s, value: s }, `≥ ${s}`))
              )
            ),
            h(
              'div',
              { className: 'min-h-0 flex-1 overflow-auto px-1 pb-2' },
              findings.isLoading
                ? h('div', { className: 'p-3 text-xs text-(--ui-text-tertiary)' }, 'loading…')
                : findings.isError
                  ? h('div', { className: 'p-3 text-xs text-(--ui-text-tertiary)' }, 'The SIEMless backend is not reachable. Is the plugin enabled (plugins.enabled) and the gateway restarted?')
                  : list.length === 0
                    ? h('div', { className: 'p-3 text-xs text-(--ui-text-tertiary)' }, 'No findings. Events are still being recorded; the rules only speak when a sequence matches.')
                    : list.map((f) => h(FindingRow, { key: f.id, f, active: f.id === selected, onClick: () => setSelected(f.id) }))
            )
          ),
          h('div', { className: 'min-w-0 flex-1' }, h(FindingDetail, { id: selected, onChanged: () => queryClient.invalidateQueries({ queryKey: [ID, 'findings'] }) }))
        )
      : tab === 'events'
        ? h(
            'div',
            { className: 'min-h-0 flex-1 overflow-auto p-1' },
            events.isLoading
              ? h('div', { className: 'p-3 text-xs text-(--ui-text-tertiary)' }, 'loading…')
              : ((events.data && events.data.events) || []).length === 0
                ? h(EmptyState, { title: 'No events yet', description: 'Every tool call, file read, command and request the agent makes shows up here.' })
                : (events.data.events || []).map((e) => h(EventRow, { key: e.id, e }))
          )
        : tab === 'exporters'
          ? h(
              'div',
              { className: 'min-h-0 flex-1 overflow-auto p-2' },
              exporters.data
                ? h(
                    'div',
                    null,
                    h(
                      'div',
                      { className: 'mb-2 flex items-center gap-2 text-xs text-(--ui-text-tertiary)' },
                      h('span', null, exporters.data.remote_export ? 'Remote export is on: configured destinations receive events.' : 'Remote export is off: everything stays on this machine until remote_export is set to true.'),
                      h('div', { className: 'flex-1' }),
                      h(
                        Button,
                        {
                          variant: 'outline',
                          size: 'xs',
                          onClick: async () => {
                            haptic('tap')
                            try {
                              await rest('/exporters/test', { method: 'POST', body: {} })
                              host.notify({ kind: 'success', message: 'Sent one siemless.health event through every exporter' })
                            } catch (err) {
                              host.notify({ kind: 'error', message: String(err && err.message ? err.message : err) })
                            }
                            queryClient.invalidateQueries({ queryKey: [ID, 'exporters'] })
                            queryClient.invalidateQueries({ queryKey: [ID, 'status'] })
                          }
                        },
                        h(Codicon, { name: 'debug-start', size: 12 }),
                        'Send test event'
                      )
                    ),
                    h('div', { className: 'mb-1 text-[0.625rem] uppercase tracking-wide text-(--ui-text-quaternary)' }, `queue ${exporters.data.queue.size}/${exporters.data.queue.capacity} · ${exporters.data.queue.dropped} dropped · worker ${exporters.data.queue.worker_alive ? 'alive' : 'not in this process'}`),
                    (exporters.data.exporters || []).map((x) => h(ExporterRow, { key: x.name, x }))
                  )
                : h('div', { className: 'p-3 text-xs text-(--ui-text-tertiary)' }, 'loading…')
            )
          : h(
              'div',
              { className: 'min-h-0 flex-1 overflow-auto p-2' },
              rules.data
                ? h(
                    'div',
                    null,
                    h('div', { className: 'mb-1 text-[0.625rem] uppercase tracking-wide text-(--ui-text-quaternary)' }, `baseline ruleset · ATT&CK ${rules.data.attack_version}`),
                    (rules.data.rules || []).map((r) => h(RuleRow, { key: r.id, r }))
                  )
                : h('div', { className: 'p-3 text-xs text-(--ui-text-tertiary)' }, 'loading…')
            )
  )
}

// -------------------------------------------------------------- status bar
function StatusChip() {
  const q = useQuery({ queryKey: [ID, 'chip'], queryFn: () => rest('/status'), refetchInterval: 10000 })
  const st = q.data
  const counts = (st && st.findings_24h) || {}
  const hot = (counts.high || 0) + (counts.critical || 0)
  const bad = st && st.exporters ? st.exporters.some((x) => x.state === 'retrying' || x.state === 'refused') : false
  return h(
    'button',
    {
      type: 'button',
      className: cn('inline-flex items-center gap-1 px-1.5 text-[0.6875rem] hover:text-(--ui-text-primary)', hot ? 'text-(--ui-danger)' : 'text-(--ui-text-tertiary)'),
      title: bad ? 'SIEMless: an exporter is failing' : 'SIEMless: agent security telemetry',
      onClick: () => {
        haptic('tap')
        host.navigate(ROUTE)
      }
    },
    h(Codicon, { name: bad ? 'warning' : 'shield', size: 12 }),
    st == null ? 'siemless' : hot ? `${hot} high` : `${Object.values(counts).reduce((a, b) => a + b, 0)} findings`
  )
}

// ----------------------------------------------------------------- plugin
export default {
  id: ID,
  name: 'SIEMless',
  defaultEnabled: true,
  register(ctx) {
    REST = (path, opts) => ctx.rest(path, opts)
    ctx.registerMany([
      { id: 'page', area: ROUTES_AREA, data: { path: ROUTE }, render: () => h(SiemlessPage) },
      { id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: ROUTE, label: 'SIEMless', codicon: 'shield' } },
      { id: 'chip', area: STATUSBAR_AREAS.right, order: 150, render: () => h(StatusChip) },
      {
        id: 'open',
        area: PALETTE_AREA,
        data: {
          id: 'siemless.open',
          label: 'SIEMless: security findings',
          keywords: ['security', 'siem', 'findings', 'telemetry', 'ocsf', 'audit'],
          run: () => host.navigate(ROUTE)
        }
      }
    ])
    // Live refresh when the agent half announces a finding or an exporter changes state.
    ctx.onEvent(`plugin.${ID}.finding`, (payload) => {
      queryClient.invalidateQueries({ queryKey: [ID] })
      const sev = payload && payload.severity
      if (sev === 'high' || sev === 'critical') {
        host.notify({ kind: 'warning', message: `SIEMless ${payload.rule_id}: ${payload.title}` })
      }
    })
    ctx.onEvent(`plugin.${ID}.health`, () => {
      queryClient.invalidateQueries({ queryKey: [ID, 'status'] })
      queryClient.invalidateQueries({ queryKey: [ID, 'exporters'] })
      queryClient.invalidateQueries({ queryKey: [ID, 'chip'] })
    })
    ctx.onDispose(() => {
      REST = null
    })
  }
}
